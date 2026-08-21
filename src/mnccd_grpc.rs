/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

//! gRPC service implementation and generated protobuf types for MNCCD.
//!
//! The [`proto`] module contains prost/tonic bindings generated from
//! `proto/mnccd_grpc.proto`. [`MnccdGrpcService`] implements the server trait;
//! [`MnccdGrpcClient`] is the generated client stub.

use crate::crypto::*;
use crate::libnvml_sys::safe_nvml;
use crate::libnvml_sys::{
    nvmlNvlinkLockRemapTable_v1_t, nvmlNvlinkNvlePrivateInfo_v1_t,
    nvmlNvlinkSetupNvleEncryptionKey_v1_t, nvmlReturn_t, NVML_NVLINK_NVLE_PRIVATE_INFO_SIZE,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::RetryIf;
use tracing::{debug, info, warn};

/// Protobuf message and client/server types generated from `mnccd_grpc.proto`.
pub mod proto {
    tonic::include_proto!("mnccd_grpc");
}

use proto::mnccd_grpc_client::MnccdGrpcClient;
use proto::mnccd_grpc_server::MnccdGrpc;

/// Process-wide state shared by gRPC handlers on the leader node.
///
/// Tracks monotonically increasing flow ids and the shared secrets allocated
/// for each flow. Non-leader nodes forward allocation and secret lookup RPCs
/// to the leader rather than mutating this state directly.
#[derive(Debug, Clone)]
pub struct MnccdGlobalData {
    flow_id_counter: Arc<Mutex<u64>>,
    flow_to_secret_map: Arc<Mutex<HashMap<u64, Vec<u8>>>>,
}

impl MnccdGlobalData {
    pub(crate) fn new() -> Self {
        MnccdGlobalData {
            flow_id_counter: Arc::new(Mutex::new(0)),
            flow_to_secret_map: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn get_flow_id_counter_locked(&self) -> Result<std::sync::MutexGuard<'_, u64>, tonic::Status> {
        self.flow_id_counter
            .lock()
            .map_err(|e| tonic::Status::internal(format!("flow_id_counter lock poisoned: {e}")))
    }

    fn get_flow_to_secret_map_locked(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, HashMap<u64, Vec<u8>>>, tonic::Status> {
        self.flow_to_secret_map
            .lock()
            .map_err(|e| tonic::Status::internal(format!("flow_to_secret_map lock poisoned: {e}")))
    }

    /// Allocates the next flow id from the leader counter (read current value, then increment).
    fn allocate_flow_id(&self) -> Result<u64, tonic::Status> {
        let mut counter = self.get_flow_id_counter_locked()?;
        let flow_id = *counter;
        *counter += 1;
        Ok(flow_id)
    }

    /// Allocates a flow id and stores `shared_secret` under that id (leader-only).
    pub(crate) fn allocate_flow_and_store_secret(
        &self,
        shared_secret: Vec<u8>,
    ) -> Result<(u64, Vec<u8>), tonic::Status> {
        let flow_id = self.allocate_flow_id()?;
        let mut map = self.get_flow_to_secret_map_locked()?;
        map.insert(flow_id, shared_secret.clone());
        Ok((flow_id, shared_secret))
    }

    /// Returns a copy of the shared secret for `flow_id`, if present (leader-only).
    pub(crate) fn get_shared_secret(&self, flow_id: u64) -> Result<Vec<u8>, tonic::Status> {
        let map = self.get_flow_to_secret_map_locked()?;
        map.get(&flow_id)
            .cloned()
            .ok_or_else(|| tonic::Status::invalid_argument("Flow id does not exist"))
    }
}

/// gRPC service handler for all [`MnccdGrpc`] RPCs.
#[derive(Debug)]
pub struct MnccdGrpcService {
    global_data: MnccdGlobalData,
}

impl MnccdGrpcService {
    /// Creates a service instance backed by the given shared global state.
    pub fn new(global_data: MnccdGlobalData) -> Self {
        Self { global_data }
    }
}

/// Runs synchronous NVML work off the async runtime, on Tokio's blocking pool.
///
/// NVML FFI calls are blocking and can take a meaningful amount of time (driver
/// round-trips, fabric-probe waits, key programming). Executing them directly in
/// an `async fn` would tie up a runtime worker thread and stall other tasks, so
/// handlers hand the work to this helper instead. A panic or cancellation of the
/// blocking task surfaces as an internal `Status`.
async fn run_nvml_blocking<T, F>(work: F) -> Result<T, tonic::Status>
where
    F: FnOnce() -> Result<T, tonic::Status> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|e| tonic::Status::internal(format!("NVML worker task failed: {e}")))?
}

#[tonic::async_trait]
impl MnccdGrpc for MnccdGrpcService {
    /// This API simply returns a Hello message to the client
    /// Serves as a smoke test for the gRPC infrastructure
    async fn mnccd_grpc_echo_message(
        &self,
        request: tonic::Request<proto::MnccdGrpcEchoRequest>,
    ) -> Result<tonic::Response<proto::MnccdGrpcEchoResponse>, tonic::Status> {
        debug!(
            "Received mnccd_grpc_echo_message RPC from {:?}",
            request.remote_addr()
        );

        let response = proto::MnccdGrpcEchoResponse {
            message: format!("Hello {}!", request.into_inner().name),
        };

        Ok(tonic::Response::new(response))
    }

    /// This API returns a flow id along with any associated cryptographic info
    /// like keys and IV masks.
    async fn mnccd_grpc_alloc_flow(
        &self,
        request: tonic::Request<proto::MnccdGrpcAllocFlowRequest>,
    ) -> Result<tonic::Response<proto::MnccdGrpcAllocFlowResponse>, tonic::Status> {
        let flow_id: u64;
        let mut primary_key: Vec<u8> = Vec::new();
        let mut secondary_key: Vec<u8> = Vec::new();
        let mut primary_ivmask: Vec<u8> = Vec::new();
        let mut secondary_ivmask: Vec<u8> = Vec::new();
        let shared_secret: Vec<u8>;

        debug!(
            "Received mnccd_grpc_alloc_flow RPC from {:?}",
            request.remote_addr()
        );

        let flow_type = request.get_ref().flow_type;
        let mnccd_to_mnccd = request.get_ref().mnccd_to_mnccd;

        // Allocate an id from the global counter on the leader instance
        // Secondary instances should send a gRPC to the leader for this
        if crate::utils::is_leader()
            .map_err(|e| tonic::Status::internal(format!("unable to determine leader role: {e}")))?
        {
            let secret = crate::generate_random_bytes(32).map_err(|e| {
                tonic::Status::internal(format!("Failed to generate shared secret: {e}"))
            })?;
            (flow_id, shared_secret) = self.global_data.allocate_flow_and_store_secret(secret)?;
        } else {
            debug!("Forwarding the flow id alloc request to the leader");
            let channel = crate::create_channel_handle_for_client(&crate::CONFIG.leader_ip)
                .await
                .map_err(|e| tonic::Status::internal(format!("Failed to create channel: {}", e)))?;

            let req_data = proto::MnccdGrpcAllocFlowRequest {
                flow_type: flow_type,
                mnccd_to_mnccd: Some(true),
            };

            let channel_clone = channel.clone();
            let response = call_with_retry(
                move || {
                    let channel = channel_clone.clone();
                    let req = tonic::Request::new(req_data.clone());
                    Box::pin(async move {
                        let mut client = MnccdGrpcClient::new(channel);
                        client.mnccd_grpc_alloc_flow(req).await
                    })
                },
                "mnccd_grpc_alloc_flow",
            )
            .await?;

            let inner = response.into_inner();
            flow_id = inner.flow_id;
            shared_secret = inner.shared_secret;
        }

        // Generate keys and IVs only in case of None and false
        if mnccd_to_mnccd != Some(true) {
            primary_key =
                derive_hkdf_material(&shared_secret, HKDF_LABEL_PRIMARY_KEY, flow_id, 0, 32)?;
            secondary_key =
                derive_hkdf_material(&shared_secret, HKDF_LABEL_SECONDARY_KEY, flow_id, 0, 32)?;
            primary_ivmask =
                derive_hkdf_material(&shared_secret, HKDF_LABEL_PRIMARY_IVMASK, flow_id, 0, 12)?;
            secondary_ivmask =
                derive_hkdf_material(&shared_secret, HKDF_LABEL_SECONDARY_IVMASK, flow_id, 0, 12)?;
        }

        let response = proto::MnccdGrpcAllocFlowResponse {
            flow_id: flow_id,
            key_rotation_threshold: 0,
            primary_key: primary_key,
            secondary_key: secondary_key,
            primary_ivmask: primary_ivmask,
            secondary_ivmask: secondary_ivmask,
            shared_secret: shared_secret,
        };

        Ok(tonic::Response::new(response))
    }

    /// This API looks up the KMB info for the given flow id and returns the same
    async fn mnccd_grpc_import_flow(
        &self,
        request: tonic::Request<proto::MnccdGrpcImportFlowRequest>,
    ) -> Result<tonic::Response<proto::MnccdGrpcImportFlowResponse>, tonic::Status> {
        debug!(
            "Received mnccd_grpc_import_flow RPC from {:?}",
            request.remote_addr()
        );

        let flow_id = request.get_ref().flow_id;

        debug!("Fetching the shared secret for flow id {flow_id} from the leader");
        let channel = crate::create_channel_handle_for_client(&crate::CONFIG.leader_ip)
            .await
            .map_err(|e| tonic::Status::internal(format!("Failed to create channel: {}", e)))?;

        let req_data = proto::MnccdGrpcGetSharedSecretRequest { flow_id: flow_id };

        let channel_clone = channel.clone();
        let response = call_with_retry(
            move || {
                let channel = channel_clone.clone();
                let req = tonic::Request::new(req_data.clone());
                Box::pin(async move {
                    let mut client = MnccdGrpcClient::new(channel);
                    client.mnccd_grpc_get_shared_secret(req).await
                })
            },
            "mnccd_grpc_get_shared_secret",
        )
        .await?;

        let shared_secret = response.into_inner().shared_secret;

        let primary_key =
            derive_hkdf_material(&shared_secret, HKDF_LABEL_PRIMARY_KEY, flow_id, 0, 32)?;
        let secondary_key =
            derive_hkdf_material(&shared_secret, HKDF_LABEL_SECONDARY_KEY, flow_id, 0, 32)?;
        let primary_ivmask =
            derive_hkdf_material(&shared_secret, HKDF_LABEL_PRIMARY_IVMASK, flow_id, 0, 12)?;
        let secondary_ivmask =
            derive_hkdf_material(&shared_secret, HKDF_LABEL_SECONDARY_IVMASK, flow_id, 0, 12)?;

        let response = proto::MnccdGrpcImportFlowResponse {
            flow_type: 0,
            key_rotation_threshold: 0,
            primary_key: primary_key,
            secondary_key: secondary_key,
            primary_ivmask: primary_ivmask,
            secondary_ivmask: secondary_ivmask,
        };

        Ok(tonic::Response::new(response))
    }

    /// This API looks up the shared secret for the given flow id and returns the same
    /// This must be called only on the leader
    async fn mnccd_grpc_get_shared_secret(
        &self,
        request: tonic::Request<proto::MnccdGrpcGetSharedSecretRequest>,
    ) -> Result<tonic::Response<proto::MnccdGrpcGetSharedSecretResponse>, tonic::Status> {
        debug!(
            "Received mnccd_grpc_get_shared_secret RPC from {:?}",
            request.remote_addr()
        );

        let flow_id = request.get_ref().flow_id;
        let shared_secret = self.global_data.get_shared_secret(flow_id)?;

        let response = proto::MnccdGrpcGetSharedSecretResponse { shared_secret };

        Ok(tonic::Response::new(response))
    }

    /// Confirms fabric probe completion and collects NVLE private info for all local GPUs.
    async fn mnccd_grpc_collect_gpus_info(
        &self,
        request: tonic::Request<proto::MnccdGrpcCollectGpusInfoRequest>,
    ) -> Result<tonic::Response<proto::MnccdGrpcCollectGpusInfoResponse>, tonic::Status> {
        debug!(
            "Received mnccd_grpc_collect_gpus_info RPC from {:?}",
            request.remote_addr()
        );

        run_nvml_blocking(move || {
            // init() is reference counted and safe to call repeatedly; ignore
            // errors in case NVML is already initialized.
            let _ = safe_nvml::init();

            // Get GPU count
            let num_gpus = safe_nvml::device_get_count()
                .map_err(|e| tonic::Status::internal(format!("Failed to get GPU count: {}", e)))?;

            let mut gpu_infos = Vec::new();

            // Collect information for each GPU
            for i in 0..num_gpus {
                let device = safe_nvml::Device::new_from_index(i).map_err(|e| {
                    tonic::Status::internal(format!(
                        "Failed to get device handle for GPU {}: {}",
                        i, e
                    ))
                })?;

                // Get UUID for the device
                let uuid = device.get_uuid().map_err(|e| {
                    tonic::Status::internal(format!("Failed to get UUID for GPU {}: {}", i, e))
                })?;

                // Check if fabric probe is complete (with timeout similar to collect_gpu_info)
                let mut fabric_probe_complete = false;
                for _ in 0..10 {
                    match safe_nvml::device_is_fabric_probe_completed(&device) {
                        Ok(true) => {
                            fabric_probe_complete = true;
                            break;
                        }
                        Ok(false) => {
                            std::thread::sleep(std::time::Duration::from_millis(500));
                        }
                        Err(e) => {
                            return Err(tonic::Status::internal(format!(
                                "Failed to check fabric probe for GPU {} (UUID: {}): {}",
                                i, uuid, e
                            )));
                        }
                    }
                }

                if !fabric_probe_complete {
                    return Err(tonic::Status::failed_precondition(format!(
                        "Fabric probe not complete for GPU {} (UUID: {})",
                        i, uuid,
                    )));
                }

                // Get the opaque NVLE private-info blob (fed verbatim into key setup later).
                let private_info = safe_nvml::device_nvlink_get_nvle_private_info(&device)
                    .map_err(|e| {
                        tonic::Status::internal(format!(
                            "Failed to get NVLE private info for GPU {} (UUID: {}): {}",
                            i, uuid, e
                        ))
                    })?;

                // This node's IP as known to the cluster (matched against node_ips).
                let node_ip = crate::utils::local_node_ip()
                    .map_err(|e| {
                        tonic::Status::internal(format!("Failed to determine local node IP: {}", e))
                    })?
                    .to_string();

                // Guard against a reported length larger than the fixed buffer so the
                // slice below can't panic on out-of-bounds indexing.
                let private_info_len = private_info.size as usize;
                if private_info_len > private_info.data.len() {
                    return Err(tonic::Status::internal(format!(
                        "NVLE private info for GPU {} (UUID: {}) reports size {} exceeding buffer capacity {}",
                        i,
                        uuid,
                        private_info_len,
                        private_info.data.len()
                    )));
                }

                let nvle_private_info = private_info.data[..private_info_len].to_vec();

                let gpu_info = proto::MnccdGrpcGpuInfo {
                    uuid,
                    nvle_private_info,
                    node_ip,
                };

                gpu_infos.push(gpu_info);
            }

            if gpu_infos.is_empty() {
                return Err(tonic::Status::not_found("No GPUs with active links found"));
            }

            let _ = safe_nvml::shutdown();

            let response = proto::MnccdGrpcCollectGpusInfoResponse { gpu_infos };

            Ok(tonic::Response::new(response))
        })
        .await
    }

    /// This API queries remap table info for all GPUs on this node (by NVML device index)
    async fn mnccd_grpc_query_remap_table(
        &self,
        request: tonic::Request<proto::MnccdGrpcQueryRemapTableRequest>,
    ) -> Result<tonic::Response<proto::MnccdGrpcQueryRemapTableResponse>, tonic::Status> {
        debug!(
            "Received mnccd_grpc_query_remap_table RPC from {:?}",
            request.remote_addr()
        );

        run_nvml_blocking(move || {
            let _ = safe_nvml::init();

            let num_gpus = safe_nvml::device_get_count()
                .map_err(|e| tonic::Status::internal(format!("Failed to get GPU count: {}", e)))?;

            let mut queried_gpu_uuids = Vec::new();
            let mut per_gpu_remap_table = Vec::new();
            let mut errors = Vec::new();

            for i in 0..num_gpus {
                let device = match safe_nvml::Device::new_from_index(i) {
                    Ok(d) => d,
                    Err(e) => {
                        errors.push(format!("Failed to get device handle for GPU {}: {}", i, e));
                        continue;
                    }
                };

                let uuid = match device.get_uuid() {
                    Ok(u) => u,
                    Err(e) => {
                        errors.push(format!("Failed to get UUID for GPU {}: {}", i, e));
                        continue;
                    }
                };

                match safe_nvml::device_nvlink_get_remap_table_info(&device) {
                    Ok(info) => {
                        let cap = info.flaRemapTabAddr.len().min(info.gpaRemapTabAddr.len());
                        let n = info.remapTabSize as usize;
                        if n > cap {
                            errors.push(format!(
                                "Remap table for GPU UUID: {uuid} has size {} but NVML \
                                 returned capacity {}",
                                info.remapTabSize, cap
                            ));
                            continue;
                        }

                        let fla_remap_table_addr = info.flaRemapTabAddr[..n].to_vec();
                        let gpa_remap_table_addr = info.gpaRemapTabAddr[..n].to_vec();
                        per_gpu_remap_table.push(proto::MnccdGrpcPerGpuRemapTableInfo {
                            gpu_uuid: uuid.clone(),
                            remap_tab_size: info.remapTabSize,
                            fla_remap_table_addr,
                            gpa_remap_table_addr,
                            alid: info.alid,
                        });
                        queried_gpu_uuids.push(uuid);
                    }
                    Err(e) => {
                        errors.push(format!(
                            "Failed to query remap table info for GPU UUID: {uuid}: {e}"
                        ));
                    }
                }
            }

            let success = errors.is_empty() && !queried_gpu_uuids.is_empty();
            let error_message = if errors.is_empty() {
                String::new()
            } else {
                errors.join("; ")
            };

            let _ = safe_nvml::shutdown();

            let response = proto::MnccdGrpcQueryRemapTableResponse {
                success,
                error_message,
                queried_gpu_uuids,
                per_gpu_remap_table,
            };

            Ok(tonic::Response::new(response))
        })
        .await
    }

    /// This API locks the remap table for all GPUs
    async fn mnccd_grpc_lock_remap_table(
        &self,
        request: tonic::Request<proto::MnccdGrpcLockRemapTableRequest>,
    ) -> Result<tonic::Response<proto::MnccdGrpcLockRemapTableResponse>, tonic::Status> {
        debug!(
            "Received mnccd_grpc_lock_remap_table RPC from {:?}",
            request.remote_addr()
        );

        run_nvml_blocking(move || {
            let _ = safe_nvml::init();

            let num_gpus = safe_nvml::device_get_count()
                .map_err(|e| tonic::Status::internal(format!("Failed to get GPU count: {}", e)))?;

            let mut locked_gpu_uuids = Vec::new();
            let mut errors = Vec::new();

            for i in 0..num_gpus {
                let device = match safe_nvml::Device::new_from_index(i) {
                    Ok(d) => d,
                    Err(e) => {
                        errors.push(format!("Failed to get device handle for GPU {}: {}", i, e));
                        continue;
                    }
                };

                let uuid = match device.get_uuid() {
                    Ok(u) => u,
                    Err(e) => {
                        errors.push(format!("Failed to get UUID for GPU {}: {}", i, e));
                        continue;
                    }
                };

                let mut lock_info: nvmlNvlinkLockRemapTable_v1_t = unsafe { std::mem::zeroed() };

                match safe_nvml::device_nvlink_lock_remap_table(&device, &mut lock_info) {
                    Ok(_) if lock_info.bRemapTableLocked != 0 => {
                        locked_gpu_uuids.push(uuid);
                    }
                    Ok(_) => {
                        // NVML accepted the request but the table is not actually locked.
                        errors.push(format!(
                            "Remap table not locked for GPU UUID: {uuid} \
                         (bRemapTableLockDisabled={})",
                            lock_info.bRemapTableLockDisabled
                        ));
                    }
                    Err(e) => {
                        errors.push(format!(
                            "Failed to lock remap table for GPU UUID: {uuid}: {e}",
                        ));
                    }
                }
            }

            let success = errors.is_empty() && !locked_gpu_uuids.is_empty();
            let error_message = if errors.is_empty() {
                String::new()
            } else {
                errors.join("; ")
            };

            let _ = safe_nvml::shutdown();

            let response = proto::MnccdGrpcLockRemapTableResponse {
                success,
                error_message,
                locked_gpu_uuids,
            };

            Ok(tonic::Response::new(response))
        })
        .await
    }

    /// This API collects local GPUs currently in RM DRAIN_P2P recovery state.
    async fn mnccd_grpc_collect_drain_p2p_gpus(
        &self,
        request: tonic::Request<proto::MnccdGrpcCollectDrainP2pGpusRequest>,
    ) -> Result<tonic::Response<proto::MnccdGrpcCollectDrainP2pGpusResponse>, tonic::Status> {
        debug!(
            "Received mnccd_grpc_collect_drain_p2p_gpus RPC from {:?}",
            request.remote_addr()
        );

        let collect_result =
            tokio::task::spawn_blocking(crate::collect_local_drain_p2p_recovery_gpus)
                .await
                .map_err(|e| {
                    tonic::Status::internal(format!(
                        "DRAIN_P2P GPU collection task failed to join: {e}"
                    ))
                })?;

        match collect_result {
            Ok(gpus) => Ok(tonic::Response::new(
                proto::MnccdGrpcCollectDrainP2pGpusResponse {
                    success: true,
                    error_message: String::new(),
                    gpus: gpus
                        .into_iter()
                        .map(|gpu| proto::MnccdGrpcRetrainGpu {
                            node_ip: gpu.node_ip,
                            gpu_uuid: gpu.gpu_uuid,
                            gpu_index: gpu.gpu_index,
                            recovery_action: gpu.recovery_action,
                        })
                        .collect(),
                },
            )),
            Err(e) => Ok(tonic::Response::new(
                proto::MnccdGrpcCollectDrainP2pGpusResponse {
                    success: false,
                    error_message: e,
                    gpus: Vec::new(),
                },
            )),
        }
    }

    /// This API reports an RM DRAIN_P2P recovery action to the leader.
    async fn mnccd_grpc_report_retrain_event(
        &self,
        request: tonic::Request<proto::MnccdGrpcReportRetrainEventRequest>,
    ) -> Result<tonic::Response<proto::MnccdGrpcReportRetrainEventResponse>, tonic::Status> {
        debug!(
            "Received mnccd_grpc_report_retrain_event RPC from {:?}",
            request.remote_addr()
        );

        if !crate::utils::is_leader()
            .map_err(|e| tonic::Status::internal(format!("unable to determine leader role: {e}")))?
        {
            return Ok(tonic::Response::new(
                proto::MnccdGrpcReportRetrainEventResponse {
                    success: false,
                    error_message: "retrain events must be reported to the leader".to_string(),
                },
            ));
        }

        let req = request.into_inner();
        if req.gpus.is_empty() {
            return Ok(tonic::Response::new(
                proto::MnccdGrpcReportRetrainEventResponse {
                    success: false,
                    error_message: "no GPUs provided in retrain event".to_string(),
                },
            ));
        }

        info!(
            "Leader received NVLE retrain event for {} GPU(s)",
            req.gpus.len()
        );

        let trigger_gpu_uuids = req.gpus.iter().map(|gpu| gpu.gpu_uuid.clone()).collect();

        match crate::refresh_nvle_keys_for_drain_p2p_event(trigger_gpu_uuids).await {
            Ok(()) => Ok(tonic::Response::new(
                proto::MnccdGrpcReportRetrainEventResponse {
                    success: true,
                    error_message: String::new(),
                },
            )),
            Err(e) => Ok(tonic::Response::new(
                proto::MnccdGrpcReportRetrainEventResponse {
                    success: false,
                    error_message: e,
                },
            )),
        }
    }

    /// This API sets up NVLink NVLE encryption key for a device
    /// Similar to device_nvlink_setup_nvle_encryption_key function
    async fn mnccd_grpc_setup_nvle_encryption_key(
        &self,
        request: tonic::Request<proto::MnccdGrpcSetupNvleEncryptionKeyRequest>,
    ) -> Result<tonic::Response<proto::MnccdGrpcSetupNvleEncryptionKeyResponse>, tonic::Status>
    {
        let remote_addr = request.remote_addr();
        debug!(
            "Received mnccd_grpc_setup_nvle_encryption_key RPC from {:?}",
            remote_addr
        );

        let req = request.into_inner();
        debug!(
            "Setting up NVLE key for GPU {} local ALID {} remote ALID {}",
            req.device_uuid, req.local_gpu_alid, req.remote_gpu_alid
        );

        // Validate required fields
        if req.device_uuid.is_empty() {
            return Ok(tonic::Response::new(
                proto::MnccdGrpcSetupNvleEncryptionKeyResponse {
                    success: false,
                    error_message: "device_uuid is required".to_string(),
                    retryable: false,
                },
            ));
        }

        if req.nvle_key.len() != 32 {
            return Ok(tonic::Response::new(
                proto::MnccdGrpcSetupNvleEncryptionKeyResponse {
                    success: false,
                    error_message: format!(
                        "nvle_key must be 32 bytes, got {} bytes",
                        req.nvle_key.len()
                    ),
                    retryable: false,
                },
            ));
        }

        // Pure conversions with no NVML involvement: validate the request fully
        // before handing work to a blocking thread so malformed input fails cheaply.
        let local_private_info = bytes_to_nvle_private_info(&req.local_gpu_nvle_private_info)?;
        let remote_private_info = bytes_to_nvle_private_info(&req.remote_gpu_nvle_private_info)?;

        run_nvml_blocking(move || {
            // Initialize NVML if not already initialized
            let _ = safe_nvml::init();

            // Get device handle from UUID
            let device = safe_nvml::Device::new_from_uuid(&req.device_uuid).map_err(|e| {
                tonic::Status::invalid_argument(format!(
                    "Failed to get device handle for UUID {}: {}",
                    req.device_uuid, e
                ))
            })?;

            // Setup encryption key struct
            let mut encryption_key: nvmlNvlinkSetupNvleEncryptionKey_v1_t =
                unsafe { std::mem::zeroed() };
            encryption_key.localGpuAlid = req.local_gpu_alid;
            encryption_key.remoteGpuAlid = req.remote_gpu_alid;
            encryption_key.localGpuNvlePrivateInfo = local_private_info;
            encryption_key.remoteGpuNvlePrivateInfo = remote_private_info;
            encryption_key.nvleKey.copy_from_slice(&req.nvle_key);

            // Call the NVML function
            match safe_nvml::device_nvlink_setup_nvle_encryption_key(&device, &mut encryption_key) {
                Ok(_) => {
                    let _ = safe_nvml::shutdown();
                    Ok(tonic::Response::new(
                        proto::MnccdGrpcSetupNvleEncryptionKeyResponse {
                            success: true,
                            error_message: String::new(),
                            retryable: false,
                        },
                    ))
                }
                Err(e) => {
                    let _ = safe_nvml::shutdown();
                    Ok(tonic::Response::new(
                        proto::MnccdGrpcSetupNvleEncryptionKeyResponse {
                            success: false,
                            error_message: format!("Failed to setup NVLE encryption key: {}", e),
                            retryable: e == nvmlReturn_t::NVML_ERROR_IN_USE,
                        },
                    ))
                }
            }
        })
        .await
    }

    /// This API signals whether NVLE is ready for all GPUs
    async fn mnccd_grpc_set_nvle_ready(
        &self,
        request: tonic::Request<proto::MnccdGrpcSetNvleReadyRequest>,
    ) -> Result<tonic::Response<proto::MnccdGrpcSetNvleReadyResponse>, tonic::Status> {
        debug!(
            "Received mnccd_grpc_set_nvle_ready RPC from {:?}",
            request.remote_addr()
        );

        let req = request.into_inner();

        run_nvml_blocking(move || {
            let _ = safe_nvml::init();

            let num_gpus = match safe_nvml::device_get_count() {
                Ok(n) => n,
                Err(e) => {
                    let _ = safe_nvml::shutdown();
                    return Err(tonic::Status::internal(format!(
                        "Failed to get GPU count: {}",
                        e
                    )));
                }
            };

            let mut ready_gpu_uuids = Vec::new();

            for i in 0..num_gpus {
                let device = match safe_nvml::Device::new_from_index(i) {
                    Ok(d) => d,
                    Err(e) => {
                        let _ = safe_nvml::shutdown();
                        return Err(tonic::Status::internal(format!(
                            "Failed to get device handle for GPU {}: {}",
                            i, e
                        )));
                    }
                };

                let uuid = match device.get_uuid() {
                    Ok(u) => u,
                    Err(e) => {
                        let _ = safe_nvml::shutdown();
                        return Err(tonic::Status::internal(format!(
                            "Failed to get UUID for GPU {}: {}",
                            i, e
                        )));
                    }
                };

                if let Err(e) = safe_nvml::device_nvlink_set_nvle_ready(&device, req.ready) {
                    let _ = safe_nvml::shutdown();
                    return Err(tonic::Status::internal(format!(
                        "Failed to set NVLE ready for GPU UUID: {uuid}: {e}",
                    )));
                }

                ready_gpu_uuids.push(uuid);
            }

            let _ = safe_nvml::shutdown();

            let response = proto::MnccdGrpcSetNvleReadyResponse { ready_gpu_uuids };

            Ok(tonic::Response::new(response))
        })
        .await
    }
}

fn derive_hkdf_material(
    shared_secret: &[u8],
    secret_name: &str,
    flow_id: u64,
    key_rotation_count: u32,
    output_length: usize,
) -> Result<Vec<u8>, tonic::Status> {
    if output_length == 0 {
        return Err(tonic::Status::invalid_argument(format!(
            "HKDF output length must be greater than zero (secret_name={secret_name}, flow_id={flow_id})"
        )));
    }

    generate_hkdf_keys_or_iv_masks(
        shared_secret,
        secret_name,
        flow_id,
        key_rotation_count,
        output_length,
    )
    .map_err(|e| {
        tonic::Status::internal(format!(
            "HKDF derivation failed for {secret_name} (flow_id={flow_id}, key_rotation_count={key_rotation_count}): {e}"
        ))
    })
}

/// Reconstructs the opaque NVLE private-info blob from its on-the-wire bytes.
fn bytes_to_nvle_private_info(
    bytes: &[u8],
) -> Result<nvmlNvlinkNvlePrivateInfo_v1_t, tonic::Status> {
    let max = NVML_NVLINK_NVLE_PRIVATE_INFO_SIZE as usize;
    if bytes.len() > max {
        return Err(tonic::Status::invalid_argument(format!(
            "nvle_private_info must be <= {} bytes, got {} bytes",
            max,
            bytes.len()
        )));
    }

    let mut private_info: nvmlNvlinkNvlePrivateInfo_v1_t = unsafe { std::mem::zeroed() };
    private_info.data[..bytes.len()].copy_from_slice(bytes);
    private_info.size = bytes.len() as u32;
    Ok(private_info)
}

/// Returns true for transient gRPC status codes that are safe to retry.
fn is_retryable(status: &tonic::Status) -> bool {
    matches!(
        status.code(),
        tonic::Code::Unavailable
            | tonic::Code::DeadlineExceeded
            | tonic::Code::ResourceExhausted
            | tonic::Code::Aborted
    )
}

/// Backoff iterator from `[retry_policy]` in config (`ExponentialBackoff` + jitter).
fn retry_strategy_from_config() -> impl Iterator<Item = Duration> {
    let max_retries = crate::CONFIG.max_retries;
    let max_backoff_ms = crate::CONFIG.max_backoff_ms.max(1);
    let backoff_ms = crate::CONFIG.initial_backoff_ms.clamp(1, max_backoff_ms);
    ExponentialBackoff::from_millis(backoff_ms)
        .max_delay(Duration::from_millis(max_backoff_ms))
        .map(jitter)
        .take(max_retries)
}

/// Calls a gRPC method with retries on transient failures (`tokio-retry`).
/// Retries when the status code is unavailable, deadline exceeded, resource
/// exhausted, or aborted, using the backoff policy from [`crate::CONFIG`].
/// The closure must clone request data and build a fresh `tonic::Request` on each attempt.
pub async fn call_with_retry<F, Res>(
    mut call_fn: F,
    operation_name: &str,
) -> Result<tonic::Response<Res>, tonic::Status>
where
    F: FnMut() -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<tonic::Response<Res>, tonic::Status>> + Send>,
    >,
{
    let max_retries = crate::CONFIG.max_retries;
    let operation_name = operation_name.to_string();
    let mut attempt = 0;

    RetryIf::spawn(
        retry_strategy_from_config(),
        || call_fn(),
        move |status: &tonic::Status| {
            if !is_retryable(status) {
                return false;
            }
            if attempt >= max_retries {
                return false;
            }
            attempt += 1;
            warn!("{operation_name} failed (retry {attempt}/{max_retries}): {status}");
            true
        },
    )
    .await
}
