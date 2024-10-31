#!/bin/bash

# Define the source and target directories as arrays
SOURCE_DIRS=("../../creds/test-vectors/rs256" "../../creds/test-vectors/mdl1")
TARGET_DIRS=("./data/creds/jwt_corporate_1/shared" "./data/creds/mdl_1/shared")

# Make sure we're in the right directory
CURRENT_DIR=${PWD##*/}
if [ "$CURRENT_DIR" != "client_helper" ]; then
    echo "Run this script from the client_helper/ folder"
    exit 1
fi

# Loop through each source and target directory pair
for i in "${!SOURCE_DIRS[@]}"; do
    SOURCE_DIR="${SOURCE_DIRS[i]}"
    TARGET_DIR="${TARGET_DIRS[i]}"

    # Remove and re-create the target directory
    echo "Removing and re-creating $TARGET_DIR directory"
    rm -fr "$TARGET_DIR"
    mkdir -p "$TARGET_DIR"
    mkdir -p "${TARGET_DIR}/cache"

    echo "Copying files from $SOURCE_DIR to $TARGET_DIR"
    set -x
    cp "${SOURCE_DIR}/config.json" "${TARGET_DIR}/"
    cp "${SOURCE_DIR}/main.wasm" "${TARGET_DIR}/"
    cp "${SOURCE_DIR}/main_c.r1cs" "${TARGET_DIR}/"
    cp "${SOURCE_DIR}/io_locations.sym" "${TARGET_DIR}/"
    cp "${SOURCE_DIR}/cache/groth16_params.bin" "${TARGET_DIR}/cache/"
    cp "${SOURCE_DIR}/cache/groth16_pvk.bin" "${TARGET_DIR}/cache/"
    cp "${SOURCE_DIR}/cache/range_pk.bin" "${TARGET_DIR}/cache/"
    set +x

    echo "Finished copying for $TARGET_DIR"
done

echo "All copy operations complete."
