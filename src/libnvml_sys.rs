/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

//! Dynamic NVML bindings and safe wrappers for MNCCD GPU operations.
//!
//! Low-level types are generated at build time from `nvml-sys-headers/`. The
//! [`safe_nvml`] module provides Rust-friendly helpers used by the gRPC handlers.

use once_cell::sync::Lazy;

pub use nvml_lib::*;

mod nvml_lib {
    #![allow(
        non_snake_case,
        dead_code,
        non_upper_case_globals,
        non_camel_case_types,
        missing_docs
    )]
    #![allow(
        clippy::too_many_arguments,
        clippy::missing_safety_doc,
        clippy::type_complexity
    )]
    include!(concat!(env!("OUT_DIR"), "/nvml_bindings.rs"));
}

/// Error type for NVML library loading failures
#[derive(Debug, thiserror::Error)]
pub enum LibraryLoadError {
    #[error("Failed to load NVML library 'libnvidia-ml.so.1': {0}")]
    LoadError(#[from] libloading::Error),
}

static NVML: Lazy<Result<nvml, LibraryLoadError>> =
    Lazy::new(|| unsafe { nvml::new("libnvidia-ml.so.1").map_err(LibraryLoadError::LoadError) });

/// Helper function to get a reference to the NVML library
/// Returns an error if the library failed to load during initialization
fn get_nvml() -> Result<&'static nvml, &'static LibraryLoadError> {
    NVML.as_ref().map_err(|e| e)
}

pub mod safe_nvml {
    //! Reference-counted NVML init/shutdown and device helpers used by MNCCD RPC handlers.
    use std::{
        ffi::{c_char, CStr, CString},
        fmt,
        mem::MaybeUninit,
        sync::Mutex,
    };

    use super::*;

    impl From<nvmlReturn_t> for Result<(), nvmlReturn_t> {
        fn from(r: nvmlReturn_t) -> Self {
            match r {
                nvmlReturn_t::NVML_SUCCESS => Ok(()),
                _ => Err(r),
            }
        }
    }

    impl nvmlReturn_t {
        pub fn result(self) -> Result<(), nvmlReturn_t> {
            self.into()
        }
    }

    static NVML_INIT_STATUS: Lazy<Mutex<Option<nvmlReturn_t>>> = Lazy::new(|| Mutex::new(None));

    impl fmt::Display for nvmlReturn_enum {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            // Safety: nvmlErrorString may return null pointer in case of invalid error code
            //         Such case is handled by returning "Invalid error string".
            //         Otherwise, the result is expected to point to a valid C zero-terminated string.
            unsafe {
                let nvml = match super::get_nvml() {
                    Ok(nvml) => nvml,
                    Err(_) => return write!(f, "NVML library not loaded"),
                };
                let ffi_error_str = nvml.nvmlErrorString(*self);
                if ffi_error_str.is_null() {
                    return write!(f, "Invalid error string");
                }
                match CStr::from_ptr(ffi_error_str).to_str() {
                    Ok(s) => {
                        write!(f, "{}", s)
                    }
                    Err(_) => write!(f, "Invalid error string"),
                }
            }
        }
    }

    impl std::error::Error for nvmlReturn_enum {}

    /// Initializes the NVML library (`nvmlInit_v2`) once for the process lifetime.
    pub fn init() -> Result<(), nvmlReturn_t> {
        let mut init_status = NVML_INIT_STATUS
            .lock()
            .map_err(|_| nvmlReturn_t::NVML_ERROR_UNKNOWN)?;
        if let Some(status) = *init_status {
            return status.result();
        }

        let nvml = super::get_nvml().map_err(|_| nvmlReturn_t::NVML_ERROR_LIBRARY_NOT_FOUND)?;
        let status = unsafe { nvml.nvmlInit_v2() };
        if status == nvmlReturn_t::NVML_SUCCESS {
            *init_status = Some(status);
        }
        status.result()
    }

    /// Keeps NVML initialized for the process lifetime.
    pub fn shutdown() -> Result<(), nvmlReturn_t> {
        Ok(())
    }

    fn c_string_buffer_to_string(
        bytes: &[u8],
    ) -> Result<String, core::ffi::FromBytesUntilNulError> {
        let cstr = CStr::from_bytes_until_nul(bytes)?;
        Ok(cstr.to_string_lossy().into_owned())
    }

    pub fn system_get_driver_version() -> Result<String, nvmlReturn_t> {
        let nvml = super::get_nvml().map_err(|_| nvmlReturn_t::NVML_ERROR_LIBRARY_NOT_FOUND)?;
        let mut version = [0u8; NVML_SYSTEM_DRIVER_VERSION_BUFFER_SIZE as usize];
        unsafe {
            nvml.nvmlSystemGetDriverVersion(
                version.as_mut_ptr() as *mut c_char,
                std::mem::size_of_val(&version) as u32,
            )
            .result()?;
        }
        c_string_buffer_to_string(&version).map_err(|_| nvmlReturn_t::NVML_ERROR_UNKNOWN)
    }

    pub fn system_get_nvml_version() -> Result<String, nvmlReturn_t> {
        let nvml = super::get_nvml().map_err(|_| nvmlReturn_t::NVML_ERROR_LIBRARY_NOT_FOUND)?;
        let mut version = [0u8; NVML_SYSTEM_NVML_VERSION_BUFFER_SIZE as usize];
        unsafe {
            nvml.nvmlSystemGetNVMLVersion(
                version.as_mut_ptr() as *mut c_char,
                std::mem::size_of_val(&version) as u32,
            )
            .result()?;
        }
        c_string_buffer_to_string(&version).map_err(|_| nvmlReturn_t::NVML_ERROR_UNKNOWN)
    }

    pub fn system_get_cuda_driver_version() -> Result<i32, nvmlReturn_t> {
        let nvml = super::get_nvml().map_err(|_| nvmlReturn_t::NVML_ERROR_LIBRARY_NOT_FOUND)?;
        let mut version = 0i32;
        unsafe {
            nvml.nvmlSystemGetCudaDriverVersion_v2(&mut version as *mut i32)
                .result()?;
        }
        Ok(version)
    }

    /// Returns the number of visible GPU devices.
    pub fn device_get_count() -> Result<u32, nvmlReturn_t> {
        let nvml = super::get_nvml().map_err(|_| nvmlReturn_t::NVML_ERROR_LIBRARY_NOT_FOUND)?;
        let mut count = 0u32;
        unsafe {
            nvml.nvmlDeviceGetCount_v2(&mut count as *mut u32)
                .result()?
        }
        Ok(count)
    }

    /// Opaque NVML device handle with convenience methods for MNCCD RPCs.
    pub struct Device {
        /// Raw NVML device handle passed to FFI calls.
        pub handle: nvmlDevice_t,
    }

    #[derive(Debug, thiserror::Error)]
    pub enum NvmlComplexError {
        #[error("Invalid Index {0}")]
        InvalidIndex(u32),
        #[error("Invalid Serial {0}")]
        InvalidSerial(String),
        #[error("Invalid UUID {0}")]
        InvalidUuid(String),
        #[error("Invalid PCI Info {0}")]
        InvalidPciInfo(String),
        #[error("NVML Error: {0}")]
        NvmlError(#[from] nvmlReturn_t),
        #[error("String conversion error: {0}")]
        FromBytesUntilNulError(#[from] core::ffi::FromBytesUntilNulError),
        #[error("String conversion error: {0}")]
        FromBytesWithNulError(#[from] std::ffi::FromBytesWithNulError),
        #[error("Unexpected null pointer")]
        UnexpectedNull,
        #[error("Unrecognized enum value: {0}")]
        UnrecognizedEnumValue(u32),
    }

    impl Device {
        /// Wraps an existing NVML device handle.
        pub fn new(handle: nvmlDevice_t) -> Self {
            Self { handle }
        }

        /// Opens the GPU at zero-based `index` via `nvmlDeviceGetHandleByIndex_v2`.
        pub fn new_from_index(index: u32) -> Result<Self, NvmlComplexError> {
            let handle = device_get_handle_by_index(index).map_err(NvmlComplexError::NvmlError)?;
            Ok(Self::new(handle))
        }

        /// Opens the GPU with the given NVML UUID string.
        pub fn new_from_uuid(uuid: &str) -> Result<Self, NvmlComplexError> {
            let handle = device_get_handle_by_uuid(uuid)?;
            Ok(Self::new(handle))
        }

        /// Returns the zero-based NVML index for this device.
        pub fn get_index(&self) -> Result<u32, nvmlReturn_t> {
            device_get_index(self)
        }

        /// Returns the NVML UUID string for this device.
        pub fn get_uuid(&self) -> Result<String, nvmlReturn_t> {
            device_get_uuid(self)
        }
    }

    pub fn device_get_handle_by_index(index: u32) -> Result<nvmlDevice_t, nvmlReturn_t> {
        let nvml = super::get_nvml().map_err(|_| nvmlReturn_t::NVML_ERROR_LIBRARY_NOT_FOUND)?;
        let mut device = std::ptr::null_mut();
        unsafe {
            nvml.nvmlDeviceGetHandleByIndex_v2(index, &mut device as *mut nvmlDevice_t)
                .result()?;
        }
        Ok(device)
    }

    pub fn device_get_handle_by_uuid(uuid: &str) -> Result<nvmlDevice_t, NvmlComplexError> {
        let nvml = super::get_nvml()
            .map_err(|_| NvmlComplexError::NvmlError(nvmlReturn_t::NVML_ERROR_LIBRARY_NOT_FOUND))?;
        let mut device = std::ptr::null_mut();
        let ffi_uuid =
            CString::new(uuid).map_err(|_| NvmlComplexError::InvalidUuid(uuid.to_string()))?;

        unsafe {
            nvml.nvmlDeviceGetHandleByUUID(ffi_uuid.as_ptr(), &mut device as *mut nvmlDevice_t)
                .result()
                .map_err(NvmlComplexError::NvmlError)?;
        }
        Ok(device)
    }

    pub fn device_get_index(device: &Device) -> Result<u32, nvmlReturn_t> {
        let nvml = super::get_nvml().map_err(|_| nvmlReturn_t::NVML_ERROR_LIBRARY_NOT_FOUND)?;
        let mut index = 0u32;
        unsafe {
            nvml.nvmlDeviceGetIndex(device.handle, &mut index as *mut u32)
                .result()?;
        }
        Ok(index)
    }

    pub fn device_get_uuid(device: &Device) -> Result<String, nvmlReturn_t> {
        let nvml = super::get_nvml().map_err(|_| nvmlReturn_t::NVML_ERROR_LIBRARY_NOT_FOUND)?;
        let mut uuid = [0u8; NVML_DEVICE_UUID_V2_BUFFER_SIZE as usize];
        unsafe {
            nvml.nvmlDeviceGetUUID(
                device.handle,
                uuid.as_mut_ptr() as *mut c_char,
                std::mem::size_of_val(&uuid) as u32,
            )
            .result()?;
        }
        c_string_buffer_to_string(&uuid).map_err(|_| nvmlReturn_t::NVML_ERROR_UNKNOWN)
    }

    /// Returns the current GPU recovery action (`NVML_FI_DEV_GET_GPU_RECOVERY_ACTION`).
    pub fn device_get_gpu_recovery_action(device: &Device) -> Result<u32, nvmlReturn_t> {
        let nvml = super::get_nvml().map_err(|_| nvmlReturn_t::NVML_ERROR_LIBRARY_NOT_FOUND)?;
        let mut field_value: nvmlFieldValue_t = unsafe { std::mem::zeroed() };
        field_value.fieldId = NVML_FI_DEV_GET_GPU_RECOVERY_ACTION;
        field_value.scopeId = 0;

        let status = unsafe {
            nvml.nvmlDeviceGetFieldValues(
                device.handle,
                1,
                &mut field_value as *mut nvmlFieldValue_t,
            )
        };
        status.result()?;
        field_value.nvmlReturn.result()?;

        let action = unsafe {
            match field_value.valueType {
                nvmlValueType_t::NVML_VALUE_TYPE_UNSIGNED_INT => field_value.value.uiVal,
                nvmlValueType_t::NVML_VALUE_TYPE_SIGNED_INT => field_value.value.siVal as u32,
                nvmlValueType_t::NVML_VALUE_TYPE_UNSIGNED_LONG => field_value.value.ulVal as u32,
                nvmlValueType_t::NVML_VALUE_TYPE_UNSIGNED_LONG_LONG => {
                    field_value.value.ullVal as u32
                }
                nvmlValueType_t::NVML_VALUE_TYPE_UNSIGNED_SHORT => field_value.value.usVal as u32,
                _ => return Err(nvmlReturn_t::NVML_ERROR_UNKNOWN),
            }
        };

        Ok(action)
    }

    /// Returns `true` once fabric probe has completed for the device.
    pub fn device_is_fabric_probe_completed(device: &Device) -> Result<bool, nvmlReturn_t> {
        let nvml = super::get_nvml().map_err(|_| nvmlReturn_t::NVML_ERROR_LIBRARY_NOT_FOUND)?;
        let mut fabric_probe_info: MaybeUninit<nvmlGpuFabricInfoV_t> = MaybeUninit::zeroed();
        unsafe {
            // Set the version field before calling the function
            // NVML_STRUCT_VERSION(GpuFabricInfo, 3) expands to sizeof(nvmlGpuFabricInfo_v3_t) | (3 << 24U)
            let fabric_probe_info_ptr = fabric_probe_info.as_mut_ptr() as *mut nvmlGpuFabricInfoV_t;
            (*fabric_probe_info_ptr).version =
                (std::mem::size_of::<nvmlGpuFabricInfoV_t>() as u32) | (3u32 << 24);

            nvml.nvmlDeviceGetGpuFabricInfoV(device.handle, fabric_probe_info_ptr)
                .result()?;
            Ok(fabric_probe_info.assume_init().state == NVML_GPU_FABRIC_STATE_COMPLETED as u8)
        }
    }

    /// Reads the opaque NVLE private-info blob (`nvmlDeviceGetNvlinkNvlePrivateInfo_v1`).
    ///
    /// The returned blob is opaque and is fed back verbatim into
    /// [`device_nvlink_setup_nvle_encryption_key`].
    pub fn device_nvlink_get_nvle_private_info(
        device: &Device,
    ) -> Result<nvmlNvlinkNvlePrivateInfo_v1_t, nvmlReturn_t> {
        let nvml = super::get_nvml().map_err(|_| nvmlReturn_t::NVML_ERROR_LIBRARY_NOT_FOUND)?;
        let mut private_info: MaybeUninit<nvmlNvlinkNvlePrivateInfo_v1_t> = MaybeUninit::zeroed();

        unsafe {
            nvml.nvmlDeviceGetNvlinkNvlePrivateInfo_v1(device.handle, private_info.as_mut_ptr())
                .result()?;
            Ok(private_info.assume_init())
        }
    }

    /// Locks the NVLink remap table (`nvmlDeviceLockNvlinkRemapTable_v1`).
    pub fn device_nvlink_lock_remap_table(
        device: &Device,
        remap_table_lock_info: &mut nvmlNvlinkLockRemapTable_v1_t,
    ) -> Result<(), nvmlReturn_t> {
        let nvml = super::get_nvml().map_err(|_| nvmlReturn_t::NVML_ERROR_LIBRARY_NOT_FOUND)?;
        unsafe {
            nvml.nvmlDeviceLockNvlinkRemapTable_v1(
                device.handle,
                remap_table_lock_info as *mut nvmlNvlinkLockRemapTable_v1_t,
            )
            .result()
        }
    }

    /// Reads FLA/GPA remap table contents (`nvmlDeviceGetNvlinkRemapTableInfo_v1`).
    pub fn device_nvlink_get_remap_table_info(
        device: &Device,
    ) -> Result<nvmlNvlinkGetRemapTableInfo_v1_t, nvmlReturn_t> {
        let nvml = super::get_nvml().map_err(|_| nvmlReturn_t::NVML_ERROR_LIBRARY_NOT_FOUND)?;
        let mut remap_table_info: MaybeUninit<nvmlNvlinkGetRemapTableInfo_v1_t> =
            MaybeUninit::zeroed();

        unsafe {
            nvml.nvmlDeviceGetNvlinkRemapTableInfo_v1(
                device.handle,
                remap_table_info.as_mut_ptr() as *mut nvmlNvlinkGetRemapTableInfo_v1_t,
            )
            .result()?;
            Ok(remap_table_info.assume_init())
        }
    }

    /// Programs NVLE encryption keys for a GPU pair (`nvmlDeviceSetupNvlinkNvleEncryptionKey_v1`).
    pub fn device_nvlink_setup_nvle_encryption_key(
        device: &Device,
        encryption_key: &mut nvmlNvlinkSetupNvleEncryptionKey_v1_t,
    ) -> Result<(), nvmlReturn_t> {
        let nvml = super::get_nvml().map_err(|_| nvmlReturn_t::NVML_ERROR_LIBRARY_NOT_FOUND)?;
        unsafe {
            nvml.nvmlDeviceSetupNvlinkNvleEncryptionKey_v1(
                device.handle,
                encryption_key as *mut nvmlNvlinkSetupNvleEncryptionKey_v1_t,
            )
            .result()
        }
    }

    /// Signals whether NVLE is ready on the device (`nvmlDeviceSetNvlinkNvleReady_v1`).
    pub fn device_nvlink_set_nvle_ready(device: &Device, ready: bool) -> Result<(), nvmlReturn_t> {
        let nvml = super::get_nvml().map_err(|_| nvmlReturn_t::NVML_ERROR_LIBRARY_NOT_FOUND)?;
        let mut nvle_ready = nvmlNvlinkSetNvleReady_v1_t {
            bNvleReady: ready as u8,
        };

        unsafe {
            nvml.nvmlDeviceSetNvlinkNvleReady_v1(
                device.handle,
                &mut nvle_ready as *mut nvmlNvlinkSetNvleReady_v1_t,
            )
            .result()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::c_string_buffer_to_string;

        #[test]
        fn converts_null_terminated_buffer() {
            let buffer = [b'5', b'5', b'0', b'.', b'5', b'4', 0, 0];

            assert_eq!(c_string_buffer_to_string(&buffer).unwrap(), "550.54");
        }

        #[test]
        fn trims_zero_padded_uuid_buffer() {
            let mut buffer = [0u8; 16];
            buffer[..8].copy_from_slice(b"GPU-1234");
            buffer[8] = 0;

            let uuid = c_string_buffer_to_string(&buffer).unwrap();
            assert_eq!(uuid, "GPU-1234");
            assert!(!uuid.contains('\0'));
        }

        #[test]
        fn preserves_lossy_utf8_conversion() {
            let buffer = [b'f', 0x80, b'o', 0];

            assert_eq!(c_string_buffer_to_string(&buffer).unwrap(), "f\u{FFFD}o");
        }

        #[test]
        fn rejects_non_terminated_buffer() {
            let buffer = *b"driver";

            assert!(c_string_buffer_to_string(&buffer).is_err());
        }
    }
}
