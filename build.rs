/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

use bindgen::EnumVariation;
use std::env;
use std::path::{Path, PathBuf};

/// Minimum CUDA toolkit version whose `nvml.h` exposes the NVLE/remap-table
/// APIs MNCCD binds. Older toolkits install a header that fails
/// [`assert_header_has_required_symbols`].
const MIN_CUDA_FOR_NVML_H: &str = "13.5";

/// Standard locations searched for an installed `nvml.h` when `NVML_HEADER_DIR`
/// is unset.
const SYSTEM_NVML_HEADERS: &[&str] = &[
    "/usr/include/nvml.h",
    "/usr/local/include/nvml.h",
    "/usr/local/cuda/include/nvml.h",
];

/// Resolves the `nvml.h` used to generate the NVML bindings.
///
/// Only the header is needed at build time. Resolution order:
///
/// 1. `NVML_HEADER_DIR` — directory containing an `nvml.h`.
/// 2. The installed system header, from [`SYSTEM_NVML_HEADERS`].
///
/// The chosen header must expose every NVML symbol MNCCD uses (including the
/// NVLE/remap-table APIs). That requires CUDA **13.5** or newer (see
/// [`MIN_CUDA_FOR_NVML_H`]).
///
/// Panics if no readable `nvml.h` is found; the returned path is guaranteed to
/// exist, so callers need not re-check.
fn resolve_nvml_header() -> PathBuf {
    println!("cargo:rerun-if-env-changed=NVML_HEADER_DIR");

    if let Some(dir) = env::var_os("NVML_HEADER_DIR") {
        let header = Path::new(&dir).join("nvml.h");
        if !header.is_file() {
            panic!(
                "NVML_HEADER_DIR={:?} does not contain nvml.h (looked for {}). \
                 Point NVML_HEADER_DIR at the directory holding an nvml.h.",
                dir,
                header.display(),
            );
        }
        return header;
    }

    SYSTEM_NVML_HEADERS
        .iter()
        .map(Path::new)
        .find(|p| p.is_file())
        .unwrap_or_else(|| {
            panic!(
                "nvml.h was not found in any of {SYSTEM_NVML_HEADERS:?}.\n\
                 Install CUDA {MIN_CUDA_FOR_NVML_H} or newer (or the matching NVML \
                 development header / NVIDIA GDK), and set NVML_HEADER_DIR to the \
                 directory that contains that nvml.h.",
            )
        })
        .to_path_buf()
}

/// NVML symbols that only exist in sufficiently recent `nvml.h` versions and
/// that `src/libnvml_sys.rs` depends on. Used as a sentinel to reject stale
/// headers before generating bindings, rather than silently emitting bindings
/// missing these APIs.
const REQUIRED_NVML_SYMBOLS: &[&str] = &[
    "nvmlDeviceLockNvlinkRemapTable_v1",
    "nvmlDeviceGetNvlinkRemapTableInfo_v1",
    "nvmlDeviceSetupNvlinkNvleEncryptionKey_v1",
    "nvmlDeviceSetNvlinkNvleReady_v1",
    "nvmlDeviceGetNvlinkNvlePrivateInfo_v1",
];

/// Fails the build if `header` is missing any [`REQUIRED_NVML_SYMBOLS`].
fn assert_header_has_required_symbols(header: &Path) {
    let contents = std::fs::read_to_string(header)
        .unwrap_or_else(|e| panic!("Unable to read nvml.h at {}: {e}", header.display()));

    let missing: Vec<&str> = REQUIRED_NVML_SYMBOLS
        .iter()
        .copied()
        .filter(|sym| !contents.contains(sym))
        .collect();

    if !missing.is_empty() {
        panic!(
            "nvml.h at {} is missing required NVML symbol(s): {}.\n\
             This header is too old for MNCCD: it lacks the NVLE/remap-table APIs \
             used in src/libnvml_sys.rs. CUDA {MIN_CUDA_FOR_NVML_H} or newer is \
             required. Point NVML_HEADER_DIR at a CUDA {MIN_CUDA_FOR_NVML_H}+ nvml.h, \
             or update the installed CUDA toolkit / NVML development header.",
            header.display(),
            missing.join(", "),
        );
    }
}

fn generate_bindings() {
    let header = resolve_nvml_header();
    let include_dir = header
        .parent()
        .expect("resolved nvml.h path must have a parent directory");

    println!("cargo:rerun-if-changed={}", header.display());

    // Reject a stale header (one that predates the NVLE/remap-table APIs)
    // before running bindgen, so the build fails fast instead of emitting
    // incomplete bindings.
    assert_header_has_required_symbols(&header);

    let bindings = bindgen::Builder::default()
        .header(header.to_str().expect("nvml.h path must be valid UTF-8"))
        // Search the header's own directory for any headers it includes.
        .clang_arg(format!("-I{}", include_dir.display()))
        // Suppress the unversioned function aliases so only the versioned APIs
        // are bound.
        .clang_arg("-DNVML_NO_UNVERSIONED_FUNC_DEFS")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .allowlist_function("nvml.*")
        .allowlist_type("nvml.*")
        .allowlist_var("NVML.*")
        .default_enum_style(EnumVariation::Rust {
            non_exhaustive: true,
        })
        .enable_function_attribute_detection()
        .disable_nested_struct_naming()
        .layout_tests(false)
        .size_t_is_usize(true)
        .dynamic_library_name("nvml")
        .formatter(bindgen::Formatter::Rustfmt)
        .generate_comments(false)
        .generate()
        .unwrap_or_else(|_| panic!("Unable to generate bindings for NVML"));

    let out_path = env::var("OUT_DIR").unwrap();
    let out_path = Path::new(&out_path);

    bindings
        .write_to_file(out_path.join("nvml_bindings.rs"))
        .unwrap_or_else(|_| panic!("Couldn't write bindings for NVML"));
}

fn compile_grpc_protos() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/mnccd_grpc.proto");
    let fds = protox::compile(["proto/mnccd_grpc.proto"], ["."])?;
    tonic_prost_build::configure().compile_fds(fds)?;
    Ok(())
}

fn warn_if_default_data_dir_unset() {
    println!("cargo:rerun-if-env-changed=MNCCD_DEFAULT_DATA_DIR");
    println!("cargo:rerun-if-env-changed=PROFILE");
    let is_release = env::var("PROFILE").as_deref() == Ok("release");
    if is_release && env::var_os("MNCCD_DEFAULT_DATA_DIR").is_none() {
        println!(
            "cargo:warning=MNCCD_DEFAULT_DATA_DIR not set; using built-in default \
             \"/etc/nvidia-mnccd\". Packagers should set this at build time to match \
             the target distro's FHS layout."
        );
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate rust bindings for NVML APIs
    generate_bindings();

    // Process protobuf via protox (pure Rust; no protoc binary)
    compile_grpc_protos()?;

    // Nudge packagers to set the compile-time config directory for release builds.
    warn_if_default_data_dir_unset();

    Ok(())
}
