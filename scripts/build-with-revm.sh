#!/bin/bash
# Build WayChain daemon with revm FFI.
set -euo pipefail
cd "$(dirname "$0")"

echo "=== Building revm FFI (Rust) ==="
cd revm-ffi
cargo build --release
cd ..

echo "=== Building waychain daemon (Go + CGo) ==="
CGO_ENABLED=1 go build -o waychain .
echo "=== OK ==="
echo "Binary: $(pwd)/waychain"
echo "Library: $(pwd)/revm-ffi/target/release/librevm_ffi.so"