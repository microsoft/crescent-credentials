#!/usr/bin/bash
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
#
set -e -o errexit
# Change to the script's directory (which should be client_helper/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Define the source and target directories as arrays
SOURCE_DIRS=(../../creds/test-vectors/{rs256,rs256-db,mdl1})
TARGET_DIRS=(./data/creds/{jwt_corporate_1/shared,jwt_sd/shared,mdl_1/shared})
CLEANUP_DIR="./data/creds"

# Remove and re-create the cleanup directory (could contain old creds)
echo "Removing and re-creating $CLEANUP_DIR directory"
rm -fr "$CLEANUP_DIR"
mkdir -p "$CLEANUP_DIR"

# Loop through each source and target directory pair
for i in "${!SOURCE_DIRS[@]}"; do
    SOURCE_DIR="${SOURCE_DIRS[i]}"
    TARGET_DIR="${TARGET_DIRS[i]}"

    # Ensure the source directory exists
    if [ ! -d "$SOURCE_DIR" ]; then
        echo -e "\033[0;31mSource directory $SOURCE_DIR does not exist. Run run_setup.sh first.\033[0m"
        exit 1
    fi

    echo "Removing and re-creating $TARGET_DIR directory"
    mkdir -p "$TARGET_DIR"
    mkdir -p "${TARGET_DIR}/cache"

    echo "Copying files from $SOURCE_DIR to $TARGET_DIR"
    set -x
    ln "${SOURCE_DIR}/config.json" "${TARGET_DIR}/"
    ln "${SOURCE_DIR}/main.wasm" "${TARGET_DIR}/"
    ln "${SOURCE_DIR}/main_c.r1cs" "${TARGET_DIR}/"
    ln "${SOURCE_DIR}/io_locations.sym" "${TARGET_DIR}/"
    [ -f "${SOURCE_DIR}/device.prv" ] && ln "${SOURCE_DIR}/device.prv" "${TARGET_DIR}/"
    [ -f "${SOURCE_DIR}/device.pub" ] && ln "${SOURCE_DIR}/device.pub" "${TARGET_DIR}/"
    ln "${SOURCE_DIR}/cache/prover_params.bin" "${TARGET_DIR}/cache/"
    ln "${SOURCE_DIR}/cache/groth16_pvk.bin" "${TARGET_DIR}/cache/"
    ln "${SOURCE_DIR}/cache/range_pk.bin" "${TARGET_DIR}/cache/"
    set +x

    echo "Finished copying for $TARGET_DIR"
done

# Copy the client_state for mDL credentials  
# TODO: this is temporary, eventually we will generate the client state upon request, as we do for JWTs
if [ ! -f "../../creds/test-vectors/mdl1/cache/client_state.bin" ]; then
    echo "WARNING: client_state.json does not exist in ../../creds/test-vectors/mdl1/"
    echo "WARNING: mDL demos will not work"
else
    echo "Copying client_state for mDL demo"
    mkdir -p "./data/creds/mdl_1/shared/cache"
    cp "../../creds/test-vectors/mdl1/cache/client_state.bin" "./data/creds/mdl_1/shared/cache/"
fi


echo "All copy operations complete."
