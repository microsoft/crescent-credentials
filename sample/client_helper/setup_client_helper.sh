#!/bin/bash

# Define the source and target directories
SOURCE_DIR="../../creds/test-vectors/rs256"
TARGET_DIR="./data/creds/shared"

# Make sure we're in the right directory
CURRENT_DIR=${PWD##*/}
if [ $CURRENT_DIR != 'client_helper' ]; then
    echo "Run this script from client_helper"
    exit -1
fi

# Remove and re-create the target directory 
echo "Removing and re-creating data/creds directory"
rm -fr "data/creds/"
mkdir -p "$TARGET_DIR"
mkdir -p "${TARGET_DIR}/cache"

echo "Copying files $SOURCE_DIR to $TARGET_DIR"
set -x 
cp "${SOURCE_DIR}/config.json" "${TARGET_DIR}/"
cp "${SOURCE_DIR}/main.wasm" "${TARGET_DIR}/"
cp "${SOURCE_DIR}/main_c.r1cs" "${TARGET_DIR}/"
cp "${SOURCE_DIR}/io_locations.sym" "${TARGET_DIR}/"
cp "${SOURCE_DIR}/cache/groth16_params.bin" "${TARGET_DIR}/cache/"
cp "${SOURCE_DIR}/cache/groth16_pvk.bin" "${TARGET_DIR}/cache/"
cp "${SOURCE_DIR}/cache/range_pk.bin" "${TARGET_DIR}/cache/"
set +x

echo "Done"
