/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

use nvidia_mnccd::libnvml_sys::safe_nvml;
use nvidia_mnccd::libnvml_sys::{
    nvmlNvlinkLockRemapTable_v1_t, nvmlNvlinkNvlePrivateInfo_v1_t,
    nvmlNvlinkSetupNvleEncryptionKey_v1_t, nvmlReturn_t,
};

/// Error type for NVLE setup operations
#[derive(Debug, thiserror::Error)]
enum NvleSetupError {
    #[error("NVML error: {0}")]
    NvmlError(#[from] nvmlReturn_t),
    #[error("NVML complex error: {0}")]
    NvmlComplexError(#[from] safe_nvml::NvmlComplexError),
    #[error("No GPUs with active links found")]
    NoGpusWithActiveLinks,
    #[error("Fabric probe not complete for GPU {0}")]
    FabricProbeIncomplete(u32),
    #[error("Failed to get NVLE private info for GPU {0}")]
    FailedToGetNvlePrivateInfo(u32),
    #[error("Remap table validation failed: FLA/GPA entries differ across GPUs")]
    RemapTableValidationFailed,
    #[error("Remap table not locked for GPU {0}")]
    RemapTableNotLocked(u32),
}

/// Result type for NVLE setup operations
type NvleSetupResult<T> = Result<T, NvleSetupError>;

/// Structure to hold GPU information needed for NVLE setup
#[derive(Debug, Clone)]
struct GpuNvleInfo {
    index: u32,
    alid: u32,
    nvle_private_info: nvmlNvlinkNvlePrivateInfo_v1_t,
}

/// NVLE setup helper
struct NvleSetupHelper {
    gpu_infos: Vec<GpuNvleInfo>,
}

impl NvleSetupHelper {
    /// Create a new NVLE setup helper
    fn new() -> Self {
        Self {
            gpu_infos: Vec::new(),
        }
    }

    /// Check if fabric probe is complete for a device
    fn check_fabric_probe_completion(
        device: &safe_nvml::Device,
        gpu_index: u32,
    ) -> NvleSetupResult<()> {
        // Poll for fabric probe completion (up to 5 seconds)
        for _ in 0..10 {
            match safe_nvml::device_is_fabric_probe_completed(device) {
                Ok(true) => return Ok(()),
                Ok(false) => {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
                Err(e) => return Err(NvleSetupError::NvmlError(e)),
            }
        }
        Err(NvleSetupError::FabricProbeIncomplete(gpu_index))
    }

    /// Get the opaque NVLE private-info blob for a GPU
    fn get_nvle_private_info(
        device: &safe_nvml::Device,
        gpu_index: u32,
    ) -> NvleSetupResult<nvmlNvlinkNvlePrivateInfo_v1_t> {
        safe_nvml::device_nvlink_get_nvle_private_info(device).map_err(|e| {
            eprintln!(
                "Failed to get NVLE private info for GPU {}: {}",
                gpu_index, e
            );
            NvleSetupError::FailedToGetNvlePrivateInfo(gpu_index)
        })
    }

    /// Collect information about all GPUs in the system
    fn collect_gpu_info(&mut self) -> NvleSetupResult<()> {
        let num_gpus = safe_nvml::device_get_count()?;
        let mut gpus_with_active_links = 0;

        self.gpu_infos.clear();

        for i in 0..num_gpus {
            let device = safe_nvml::Device::new_from_index(i)?;

            // Check if fabric probe is complete
            Self::check_fabric_probe_completion(&device, i)?;

            // Get ALID from the NVLink remap table info
            let alid = safe_nvml::device_nvlink_get_remap_table_info(&device)
                .map(|info| info.alid)
                .map_err(NvleSetupError::NvmlError)?;

            // Get the opaque NVLE private-info blob
            let nvle_private_info = Self::get_nvle_private_info(&device, i)?;

            // Note: In the C++ code, they check for active links using NvlinkUtil::getActiveLinkMask
            // For now, we'll assume all GPUs have active links if they pass fabric probe
            // You may want to add a check here if needed
            gpus_with_active_links += 1;

            self.gpu_infos.push(GpuNvleInfo {
                index: i,
                alid,
                nvle_private_info,
            });
        }

        if gpus_with_active_links == 0 {
            return Err(NvleSetupError::NoGpusWithActiveLinks);
        }

        Ok(())
    }

    /// Setup encryption keys for all GPU pairs
    fn setup_encryption_keys(&self, key_secret: &[u8; 32]) -> NvleSetupResult<()> {
        if key_secret.len() != 32 {
            return Err(NvleSetupError::NvmlError(
                nvmlReturn_t::NVML_ERROR_INVALID_ARGUMENT,
            ));
        }

        for i in 0..self.gpu_infos.len() {
            for j in (i + 1)..self.gpu_infos.len() {
                let local_gpu = &self.gpu_infos[i];
                let remote_gpu = &self.gpu_infos[j];

                // Setup encryption key from local to remote
                let local_device = safe_nvml::Device::new_from_index(local_gpu.index)?;

                let mut encryption_key: nvmlNvlinkSetupNvleEncryptionKey_v1_t =
                    unsafe { std::mem::zeroed() };
                encryption_key.localGpuAlid = local_gpu.alid;
                encryption_key.remoteGpuAlid = remote_gpu.alid;
                encryption_key.localGpuNvlePrivateInfo = local_gpu.nvle_private_info;
                encryption_key.remoteGpuNvlePrivateInfo = remote_gpu.nvle_private_info;
                encryption_key.nvleKey.copy_from_slice(key_secret);

                safe_nvml::device_nvlink_setup_nvle_encryption_key(
                    &local_device,
                    &mut encryption_key,
                )
                .map_err(NvleSetupError::NvmlError)?;

                // Setup encryption key from remote to local
                let remote_device = safe_nvml::Device::new_from_index(remote_gpu.index)?;

                encryption_key.localGpuAlid = remote_gpu.alid;
                encryption_key.remoteGpuAlid = local_gpu.alid;
                encryption_key.localGpuNvlePrivateInfo = remote_gpu.nvle_private_info;
                encryption_key.remoteGpuNvlePrivateInfo = local_gpu.nvle_private_info;

                safe_nvml::device_nvlink_setup_nvle_encryption_key(
                    &remote_device,
                    &mut encryption_key,
                )
                .map_err(NvleSetupError::NvmlError)?;
            }
        }

        Ok(())
    }

    /// Query remap tables, validate consistency across GPUs, then lock for all GPUs
    ///
    /// Note: This function requires the enabled link mask to be set properly.
    /// You may need to add a function to get NVLink status or pass the link mask as a parameter.
    fn query_and_lock_remap_table(&self) -> NvleSetupResult<()> {
        use nvidia_mnccd::validate_remap_tables_on_all_gpus;
        use nvidia_mnccd::MnccdGrpcPerGpuRemapTableInfo;

        let mut per_gpu_tables: Vec<MnccdGrpcPerGpuRemapTableInfo> = Vec::new();
        for gpu_info in &self.gpu_infos {
            let device = safe_nvml::Device::new_from_index(gpu_info.index)?;

            // Query remap table info
            let info = safe_nvml::device_nvlink_get_remap_table_info(&device)
                .map_err(NvleSetupError::NvmlError)?;
            let uuid = device.get_uuid().map_err(NvleSetupError::NvmlError)?;
            let cap = info.flaRemapTabAddr.len().min(info.gpaRemapTabAddr.len());
            let n = info.remapTabSize as usize;
            if n > cap {
                return Err(NvleSetupError::RemapTableValidationFailed);
            }
            per_gpu_tables.push(MnccdGrpcPerGpuRemapTableInfo {
                gpu_uuid: uuid,
                remap_tab_size: info.remapTabSize,
                fla_remap_table_addr: info.flaRemapTabAddr[..n].to_vec(),
                gpa_remap_table_addr: info.gpaRemapTabAddr[..n].to_vec(),
                alid: info.alid,
            });
        }

        if !validate_remap_tables_on_all_gpus(&per_gpu_tables) {
            return Err(NvleSetupError::RemapTableValidationFailed);
        }

        for gpu_info in &self.gpu_infos {
            let device = safe_nvml::Device::new_from_index(gpu_info.index)?;

            // Lock remap table. The lock now applies to the GPU's enabled links
            // implicitly; the caller no longer supplies a link mask.
            let mut lock_info: nvmlNvlinkLockRemapTable_v1_t = unsafe { std::mem::zeroed() };

            safe_nvml::device_nvlink_lock_remap_table(&device, &mut lock_info)
                .map_err(NvleSetupError::NvmlError)?;

            // A successful return only means the request was accepted; confirm the
            // table is actually locked via the output flag.
            if lock_info.bRemapTableLocked == 0 {
                return Err(NvleSetupError::RemapTableNotLocked(gpu_info.index));
            }
        }

        Ok(())
    }

    /// Refresh NVLE keys for all GPU pairs without changing remap table state.
    fn refresh_nvle_keys(&self, key_secret: &[u8; 32]) -> NvleSetupResult<()> {
        self.setup_encryption_keys(key_secret)
    }

    /// Set the NVLE ready state to true for all collected GPUs
    fn set_nvle_ready(&self) -> NvleSetupResult<()> {
        for gpu_info in &self.gpu_infos {
            let device = safe_nvml::Device::new_from_index(gpu_info.index)?;
            safe_nvml::device_nvlink_set_nvle_ready(&device, true)
                .map_err(NvleSetupError::NvmlError)?;
        }
        Ok(())
    }

    /// Complete NVLE setup process
    ///
    /// Mirrors the gRPC `setup_nvle_on_all_gpus` sequence:
    /// 1. Collect GPU information
    /// 2. Query remap table for all GPUs (also provides per-GPU ALID)
    /// 3. Validate remap table consistency across GPUs
    /// 4. Lock remap table for all GPUs
    /// 5. Setup encryption keys for all GPU pairs
    /// 6. Set NVLE ready state to true for all GPUs
    fn setup_nvle(&mut self, key_secret: &[u8; 32]) -> NvleSetupResult<()> {
        println!("Starting NVLE setup...");

        // Step 1: Collect GPU information
        println!("Step 1: Collecting GPU information...");
        self.collect_gpu_info()?;
        println!("Found {} GPUs with active links", self.gpu_infos.len());

        // Steps 2-4: Query, validate, then lock the remap table for all GPUs
        println!("Steps 2-4: Querying, validating, and locking remap table...");
        self.query_and_lock_remap_table()?;
        println!("Remap table locked for all GPUs");

        // Step 5: Setup encryption keys
        println!("Step 5: Setting up encryption keys for all GPU pairs...");
        self.setup_encryption_keys(key_secret)?;
        println!("Encryption keys setup complete");

        // Step 6: Set NVLE ready state to true
        println!("Step 6: Setting NVLE ready state to true for all GPUs...");
        self.set_nvle_ready()?;
        println!("NVLE ready state set for all GPUs");

        Ok(())
    }

    /// Get GPU information
    fn get_gpu_infos(&self) -> &[GpuNvleInfo] {
        &self.gpu_infos
    }
}

/// Create a default NVLE encryption key secret
///
/// This creates a simple key secret similar to the C++ test implementation.
/// In production, you should use a cryptographically secure random key.
fn create_default_key_secret() -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = b'a';
    key[1] = b'b';
    key[2] = b'c';
    key[3] = b'd';
    // Rest remains zeros
    key
}

fn create_refresh_key_secret() -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = b'n';
    key[1] = b'v';
    key[2] = b'l';
    key[3] = b'e';
    key[4] = b'r';
    key[5] = b'e';
    key[6] = b'f';
    key[7] = b'r';
    key
}

#[test]
fn test_nvle_setup_helper_creation() {
    let helper = NvleSetupHelper::new();
    assert_eq!(helper.get_gpu_infos().len(), 0);
}

/// Test NVLE setup - similar to NvleBaseConfigurationTest in the C++ code
///
/// This test performs the complete NVLE setup process:
/// 1. Initialize NVML
/// 2. Collect GPU information
/// 3. Query remap table for all GPUs (also provides per-GPU ALID)
/// 4. Validate remap table consistency, then lock remap table for all GPUs
/// 5. Setup encryption keys for all GPU pairs
/// 6. Set NVLE ready state to true for all GPUs
#[test]
fn test_setup_nvle() {
    // Initialize NVML - skip test if library not found
    let init_result = safe_nvml::init();
    match init_result {
        Ok(_) => {}
        Err(nvmlReturn_t::NVML_ERROR_LIBRARY_NOT_FOUND) => {
            println!("NVML library not found. Skipping NVLE test.");
            return;
        }
        Err(e) => {
            panic!("Failed to initialize NVML: {}", e);
        }
    }

    // Create NVLE setup helper
    let mut helper = NvleSetupHelper::new();

    // Create encryption key (using default for testing)
    let key_secret = create_default_key_secret();

    // Perform complete NVLE setup
    match helper.setup_nvle(&key_secret) {
        Ok(()) => {
            println!("NVLE setup completed successfully!");

            // Verify we collected GPU information
            let gpu_infos = helper.get_gpu_infos();
            assert!(
                !gpu_infos.is_empty(),
                "Should have collected at least one GPU"
            );

            println!("Found {} GPUs:", gpu_infos.len());
            for gpu_info in gpu_infos {
                println!("  GPU {}: ALID = {}", gpu_info.index, gpu_info.alid);
            }
        }
        Err(NvleSetupError::NoGpusWithActiveLinks) => {
            println!("No GPUs with active links found. Skipping test.");
        }
        Err(NvleSetupError::FabricProbeIncomplete(gpu)) => {
            println!("Fabric probe not complete for GPU {}. Skipping test.", gpu);
        }
        Err(NvleSetupError::NvmlError(nvmlReturn_t::NVML_ERROR_NOT_SUPPORTED)) => {
            println!("NVLE not supported on this system. Skipping test.");
        }
        Err(NvleSetupError::NvmlComplexError(safe_nvml::NvmlComplexError::NvmlError(
            nvmlReturn_t::NVML_ERROR_NOT_SUPPORTED,
        ))) => {
            println!("NVLE not supported on this system. Skipping test.");
        }
        Err(NvleSetupError::NvmlError(nvmlReturn_t::NVML_ERROR_NO_PERMISSION)) => {
            println!("Insufficient permissions for NVLE setup. Skipping test.");
        }
        Err(NvleSetupError::NvmlComplexError(safe_nvml::NvmlComplexError::NvmlError(
            nvmlReturn_t::NVML_ERROR_NO_PERMISSION,
        ))) => {
            println!("Insufficient permissions for NVLE setup. Skipping test.");
        }
        Err(e) => {
            panic!("NVLE setup failed: {}", e);
        }
    }

    // Cleanup
    if let Err(e) = safe_nvml::shutdown() {
        eprintln!("Warning: Failed to shutdown NVML: {}", e);
    }
}

/// Test NVLE key refresh on a single node without a user-facing CLI trigger.
///
/// The runtime daemon path is triggered by RM setting DRAIN_P2P. This live test
/// covers the same key-programming operation by doing normal setup first, then
/// reprogramming keys for the existing GPU pairs with a second key secret.
#[test]
fn test_refresh_nvle_keys_single_node() {
    match safe_nvml::init() {
        Ok(_) => {}
        Err(nvmlReturn_t::NVML_ERROR_LIBRARY_NOT_FOUND) => {
            println!("NVML library not found. Skipping NVLE refresh test.");
            return;
        }
        Err(e) => {
            panic!("Failed to initialize NVML: {}", e);
        }
    }

    let mut helper = NvleSetupHelper::new();
    let initial_key = create_default_key_secret();
    let refresh_key = create_refresh_key_secret();

    let setup_result = helper.setup_nvle(&initial_key);
    match setup_result {
        Ok(()) => {}
        Err(NvleSetupError::NoGpusWithActiveLinks) => {
            println!("No GPUs with active links found. Skipping test.");
            let _ = safe_nvml::shutdown();
            return;
        }
        Err(NvleSetupError::FabricProbeIncomplete(gpu)) => {
            println!("Fabric probe not complete for GPU {}. Skipping test.", gpu);
            let _ = safe_nvml::shutdown();
            return;
        }
        Err(NvleSetupError::NvmlError(nvmlReturn_t::NVML_ERROR_NOT_SUPPORTED))
        | Err(NvleSetupError::NvmlComplexError(safe_nvml::NvmlComplexError::NvmlError(
            nvmlReturn_t::NVML_ERROR_NOT_SUPPORTED,
        ))) => {
            println!("NVLE not supported on this system. Skipping test.");
            let _ = safe_nvml::shutdown();
            return;
        }
        Err(NvleSetupError::NvmlError(nvmlReturn_t::NVML_ERROR_NO_PERMISSION))
        | Err(NvleSetupError::NvmlComplexError(safe_nvml::NvmlComplexError::NvmlError(
            nvmlReturn_t::NVML_ERROR_NO_PERMISSION,
        ))) => {
            println!("Insufficient permissions for NVLE setup. Skipping test.");
            let _ = safe_nvml::shutdown();
            return;
        }
        Err(e) => {
            let _ = safe_nvml::shutdown();
            panic!("NVLE setup failed before refresh: {}", e);
        }
    }

    if helper.get_gpu_infos().len() < 2 {
        println!("Fewer than two GPUs found. Skipping key refresh test.");
        let _ = safe_nvml::shutdown();
        return;
    }

    match helper.refresh_nvle_keys(&refresh_key) {
        Ok(()) => println!("NVLE key refresh completed successfully!"),
        Err(e) => {
            let _ = safe_nvml::shutdown();
            panic!("NVLE key refresh failed: {}", e);
        }
    }

    if let Err(e) = safe_nvml::shutdown() {
        eprintln!("Warning: Failed to shutdown NVML: {}", e);
    }
}
