#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Pack a run tarball for mnccd_run_package_installer.sh:
# nvidia-mnccd, nvidia-mnccd.md5sum, nvidia-mnccd.sha256sum,
# mnccd_run_package_installer.sh, nvidia-mnccd.service, mnccd_config.toml, LICENSE, third-party-notices.txt
# Writes tarball digest sidecars under _out: *.tar.gz.md5sum, *.tar.gz.sha256sum
#
# TLS keys/certificates are not packaged; operators provision them separately
# under /etc/nvidia-mnccd/tls/ when using [tls].mode = "mtls".
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALLER="${ROOT}/scripts/mnccd_run_package_installer.sh"
UNIT="${ROOT}/scripts/nvidia-mnccd.service"

usage() {
    echo "Usage: $0 [--arch ARCH] [--profile PROFILE] [--output PATH]" >&2
    echo "  --arch     Target arch, e.g. x86_64 or aarch64; maps to the" >&2
    echo "             <arch>-unknown-linux-gnu target (default: the cargo default target)" >&2
    echo "  --profile  Cargo profile to package: release or debug (default: release)" >&2
    echo "  --output   Write tarball to PATH (default: _out/nvidia-mnccd-run-<ver>-<arch>-<profile>.tar.gz)" >&2
}

OUT=""
PROFILE="release"
while [ $# -gt 0 ]; do
    case "$1" in
        --arch)
            ARCH="${2:-}"
            if [ -z "$ARCH" ]; then
                echo "error: --arch requires a value" >&2
                exit 1
            fi
            shift
            ;;
        --profile)
            PROFILE="${2:-}"
            case "$PROFILE" in
                release|debug) ;;
                *) echo "error: --profile must be 'release' or 'debug'" >&2; exit 1 ;;
            esac
            shift
            ;;
        --output) OUT="${2:-}"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
    shift
done

if [ -n "${ARCH+x}" ]; then
    # Map the arch to the linux-gnu target triple to locate cargo's artifact directory.
    TARGET="${ARCH}-unknown-linux-gnu"
    ARTIFACT_DIR=${ROOT}/target/${TARGET}/${PROFILE}
else
    ARTIFACT_DIR=${ROOT}/target/${PROFILE}
    # No arch given: package the cargo default (host) target and derive ARCH from it.
    TARGET=$(rustc -vV | grep host: | cut -d' ' -f2)
    ARCH="${TARGET%%-*}"
fi
BIN="${ARTIFACT_DIR}/nvidia-mnccd"

need_file() {
    local f="$1"
    if [ ! -f "$f" ]; then
        echo "Missing required file: $f" >&2
        exit 1
    fi
}

need_file "$BIN"
need_file "$INSTALLER"
need_file "$UNIT"
need_file "${ROOT}/mnccd_config.toml"
need_file "${ROOT}/LICENSE"
need_file "${ROOT}/third-party-notices.txt"

if [ ! -x "$BIN" ]; then
    echo "Binary is not executable: $BIN" >&2
    exit 1
fi

VERSION="$(grep -m1 '^version[[:space:]]*=' "${ROOT}/Cargo.toml" | sed -E 's/^version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/')"
OUT_DIR="${ROOT}/_out"
mkdir -p "$OUT_DIR"
if [ -z "$OUT" ]; then
    OUT="${OUT_DIR}/nvidia-mnccd-run-${VERSION}-${ARCH}-${PROFILE}.tar.gz"
fi

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/mnccd-run-pack.XXXXXX")"
cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT

cp -a "$BIN" "$STAGE/nvidia-mnccd"
(
    cd "$STAGE"
    md5sum nvidia-mnccd > nvidia-mnccd.md5sum
    sha256sum nvidia-mnccd > nvidia-mnccd.sha256sum
)
cp -a "${ROOT}/mnccd_config.toml" "$STAGE/"
cp -a "${ROOT}/LICENSE" "$STAGE/"
cp -a "${ROOT}/third-party-notices.txt" "$STAGE/"
cp -a "$INSTALLER" "$STAGE/mnccd_run_package_installer.sh"
cp -a "$UNIT" "$STAGE/nvidia-mnccd.service"

TAR_MEMBERS=(
    nvidia-mnccd
    nvidia-mnccd.md5sum
    nvidia-mnccd.sha256sum
    mnccd_config.toml
    LICENSE
    third-party-notices.txt
    mnccd_run_package_installer.sh
    nvidia-mnccd.service
)

(
    cd "$STAGE"
    tar -czf "$OUT" "${TAR_MEMBERS[@]}"
)

CANON_TAR_NAME="nvidia-mnccd-run-${VERSION}-${ARCH}-${PROFILE}.tar.gz"
MD5_SIDE="${OUT_DIR}/${CANON_TAR_NAME}.md5sum"
SHA256_SIDE="${OUT_DIR}/${CANON_TAR_NAME}.sha256sum"

H_MD5="$(md5sum "$OUT" | awk '{print $1}')"
H_SHA256="$(sha256sum "$OUT" | awk '{print $1}')"
echo "$H_MD5  $CANON_TAR_NAME" >"$MD5_SIDE"
echo "$H_SHA256  $CANON_TAR_NAME" >"$SHA256_SIDE"

echo "Wrote $OUT"
echo "Wrote $MD5_SIDE"
echo "Wrote $SHA256_SIDE"
