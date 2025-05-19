#!/bin/bash
set -e

# Define the source and target directories as arrays
CRESCENT_DIR="../../creds"

# Make sure we're in the right directory
CURRENT_DIR=${PWD##*/}
if [ "$CURRENT_DIR" != "client" ]; then
    echo "Run this script from the client/ folder"
    exit 1
fi

echo "Building crescent wasm package"
pushd $CRESCENT_DIR > /dev/null
cargo install wasm-pack

# Build crescent wasm package 
RUSTFLAGS="-A unused-imports -A unused-assignments -A unused-variables --cfg getrandom_backend=\"wasm_js\"" \
wasm-pack build --target web --no-default-features --features wasm || \
echo -e "\n\033[33m[WARNING] wasm-pack build failed. Proceeding without it.\033[0m\n"

popd > /dev/null

echo "Install NPM dependencies"
npm install

if [ -f "$CRESCENT_DIR/pkg/package.json" ]; then
    echo "Installing NPM dependencies for crescent"
    npm install -D ../../creds/pkg/    
else
    echo -e "\n\033[33m[WARNING]No package.json found in ../../creds/pkg. Skipping NPM install.\033[0m\n"
fi
