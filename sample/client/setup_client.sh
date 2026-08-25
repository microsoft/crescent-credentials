#!/usr/bin/bash
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
#
set -e

# Change to the script's directory (which should be client/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Define the source and target directories as arrays
CRESCENT_DIR="../../creds"

echo "Building crescent wasm package"
pushd "$CRESCENT_DIR" > /dev/null
cargo install wasm-pack

# Build crescent wasm package 
# cargo check -p crescent --lib --release --target wasm32-unknown-unknown --no-default-features --features wasm

RUSTFLAGS="-A unused-imports -A unused-assignments -A unused-variables --cfg getrandom_backend=\"wasm_js\"" \
wasm-pack build --target web --no-default-features --features wasm || \
echo -e "\n\033[33m[WARNING] wasm-pack build failed. Proceeding without it.\033[0m\n"

popd > /dev/null

echo "Install NPM dependencies"
npm install
