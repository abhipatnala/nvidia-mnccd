/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

use nvidia_mnccd::libnvml_sys::nvmlReturn_t;
use nvidia_mnccd::libnvml_sys::safe_nvml;

/// Test NVML functionality - prints GPU info to verify NVML is working
#[test]
fn test_nvml() {
    use safe_nvml::*;

    // Initialize NVML - skip test if library not found
    match init() {
        Ok(_) => {}
        Err(nvmlReturn_t::NVML_ERROR_LIBRARY_NOT_FOUND) => {
            println!("NVML is not loaded. Skipping NVML testing");
            return;
        }
        Err(e) => panic!("Failed to initialize NVML: {}", e),
    }

    println!("Driver version: {}", system_get_driver_version().unwrap());
    println!("NVML version: {}", system_get_nvml_version().unwrap());
    println!(
        "Cuda driver version: {}",
        system_get_cuda_driver_version().unwrap()
    );

    let dev_count = device_get_count().unwrap();
    println!("Devices count: {}", dev_count);
    for i in 0..dev_count {
        let dev = Device::new_from_index(i).expect("Cannot get device handle from index");

        println!("Device {} has UUID {}", i, dev.get_uuid().unwrap());
    }

    shutdown().unwrap();
}
