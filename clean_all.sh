#!/usr/bin/bash
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
#

# Enable glob pattern matching
shopt -s extglob

# cd to this script's directory so we can run it from any location
cd "$(dirname "${BASH_SOURCE[0]}")"

# clean Rust targets
cargo clean
rm -f ./Cargo.lock

# remove generated files
rm -rf circuit_setup/inputs/*/!(*.json)
rm -rf circuit_setup/generated_files/!(README.md)
rm -rf creds/test-vectors/!(README.md)

# clean wasm
rm -rf creds/pkg

# clean sample
./sample/clean-sample.sh

