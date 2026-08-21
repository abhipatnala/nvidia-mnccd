#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Generate API documentation for nvidia-mnccd:
#   - Rust:  cargo doc  -> docs/nvidia_mnccd/index.html
#   - gRPC:  protoc    -> docs/grpc_messages.html (requires protoc-gen-doc)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROTO="${ROOT}/proto/mnccd_grpc.proto"
RUST_DOC="${ROOT}/docs"
GRPC_OUT="${RUST_DOC}/grpc_messages.html"

OPEN=0
SKIP_GRPC=0
REQUIRE_GRPC=0
FEATURES=""
NO_DEFAULT_FEATURES=0

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Generate Rust (rustdoc) and gRPC (protoc-gen-doc) API documentation.

Options:
  --open            Open Rust docs in a browser after generation
  --features LIST   Cargo features for rustdoc (optional)
  --no-default-features
                    Pass --no-default-features to cargo doc
  --skip-grpc       Skip gRPC HTML generation
  --require-grpc    Exit with error if gRPC docs cannot be generated
  -h, --help        Show this help

Outputs (under docs/):
  Rust:  docs/nvidia_mnccd/index.html
  gRPC:  docs/grpc_messages.html

gRPC docs require protoc and protoc-gen-doc on PATH, e.g.:
  go install github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc@latest
EOF
}

CARGO_DOC_FLAGS=(doc --no-deps)
while [ $# -gt 0 ]; do
    case "$1" in
        --open) OPEN=1 ;;
        --features)
            FEATURES="${2:-}"
            if [ -z "$FEATURES" ]; then
                echo "error: --features requires a value" >&2
                exit 1
            fi
            shift
            ;;
        --no-default-features) NO_DEFAULT_FEATURES=1 ;;
        --skip-grpc) SKIP_GRPC=1 ;;
        --require-grpc) REQUIRE_GRPC=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
    shift
done

if [ "$NO_DEFAULT_FEATURES" -eq 1 ]; then
    CARGO_DOC_FLAGS+=(--no-default-features)
fi
if [ -n "$FEATURES" ]; then
    CARGO_DOC_FLAGS+=(--features "$FEATURES")
fi

echo "==> Generating Rust API docs (cargo ${CARGO_DOC_FLAGS[*]})"
(cd "$ROOT" && cargo "${CARGO_DOC_FLAGS[@]}")

mkdir -p "$RUST_DOC"
# Omit rustdoc's HTML source listings (sources remain in the repo).
rsync -a --delete --exclude=src/ "${ROOT}/target/doc/" "$RUST_DOC/"
rm -rf "${RUST_DOC}/src"
echo "    Rust docs: file://${RUST_DOC}/nvidia_mnccd/index.html"

if [ "$OPEN" -eq 1 ]; then
    if command -v xdg-open >/dev/null 2>&1; then
        xdg-open "${RUST_DOC}/nvidia_mnccd/index.html"
    elif command -v open >/dev/null 2>&1; then
        open "${RUST_DOC}/nvidia_mnccd/index.html"
    else
        echo "    (no xdg-open/open found; open ${RUST_DOC}/nvidia_mnccd/index.html manually)"
    fi
fi

generate_grpc_docs() {
    if [ ! -f "$PROTO" ]; then
        echo "error: proto file not found: $PROTO" >&2
        return 1
    fi
    if ! command -v protoc >/dev/null 2>&1; then
        echo "error: protoc not found on PATH" >&2
        return 1
    fi
    if ! command -v protoc-gen-doc >/dev/null 2>&1; then
        echo "error: protoc-gen-doc not found on PATH" >&2
        echo "       install: go install github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc@latest" >&2
        return 1
    fi

    mkdir -p "$RUST_DOC"
    protoc \
        --doc_out="$RUST_DOC" \
        --doc_opt=html,grpc_messages.html \
        -I "${ROOT}/proto" \
        "$PROTO"
    echo "    gRPC docs: file://${GRPC_OUT}"
}

if [ "$SKIP_GRPC" -eq 0 ]; then
    echo "==> Generating gRPC API docs from ${PROTO}"
    if generate_grpc_docs; then
        :
    elif [ "$REQUIRE_GRPC" -eq 1 ]; then
        exit 1
    else
        echo "    skipped gRPC docs (install protoc-gen-doc to enable)"
    fi
fi

echo "Done."
