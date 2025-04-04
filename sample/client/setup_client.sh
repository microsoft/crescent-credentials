#!/bin/bash

# Define the source and target directories as arrays
CRESCENT_DIR=("../../creds")

# Make sure we're in the right directory
CURRENT_DIR=${PWD##*/}
if [ "$CURRENT_DIR" != "client" ]; then
    echo "Run this script from the client/ folder"
    exit 1
fi

echo "Building crescent wasm package"
pushd $CRESCENT_DIR > /dev/null
cargo install wasm-pack
RUSTFLAGS="-A unused-imports -A unused-assignments -A unused-variables" \
wasm-pack build --target web --no-default-features --features wasm

if [ $? -ne 0 ]; then
    echo "[WARNING] wasm-pack build failed. Proceeding without it."
fi

## Alternative way to build wasm package with temp install of wasm-pack but slower as it builds each time
# TMP_DIR="$(mktemp -d)"
# cargo install --root "$TMP_DIR" wasm-pack
# "$TMP_DIR/bin/wasm-pack" build --target web --no-default-features --features wasm
# rm -rf "$TMP_DIR"

echo "Install NPM dependencies"
popd > /dev/null
npm install
