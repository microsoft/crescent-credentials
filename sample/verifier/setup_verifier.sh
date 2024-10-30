#!/bin/bash

# Define the source and target directories
SOURCE_DIR="../../creds/test-vectors/rs256"
TARGET_DIR="./data/issuers/shared"

# Make sure we're in the right directory
CURRENT_DIR=${PWD##*/}
if [ $CURRENT_DIR != 'verifier' ]; then
    echo "Run this script from the verifier/ folder"
    exit -1
fi

# Remove and re-create the target directory 
echo "Removing and re-creating data/issuers directory"
rm -fr "data/issuers/"
mkdir -p "$TARGET_DIR"
mkdir -p "${TARGET_DIR}/cache"

echo "Copying files $SOURCE_DIR to $TARGET_DIR"
set -x 
cp "${SOURCE_DIR}/io_locations.sym" "${TARGET_DIR}/"
cp "${SOURCE_DIR}/cache/groth16_pvk.bin" "${TARGET_DIR}/cache/"
cp "${SOURCE_DIR}/cache/groth16_vk.bin" "${TARGET_DIR}/cache/"
cp "${SOURCE_DIR}/cache/range_vk.bin" "${TARGET_DIR}/cache/"
set +x

echo "Done"
