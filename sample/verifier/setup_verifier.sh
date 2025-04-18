#!/bin/bash
set -e

# Define the source and target directories as arrays
# Note: the rs256-db (device binding) set also supports selective disclosure, so we use that set for both features
SOURCE_DIRS=("../../creds/test-vectors/rs256" "../../creds/test-vectors/rs256-db" "../../creds/test-vectors/mdl1")
TARGET_DIRS=("./data/issuers/jwt_corporate_1/shared" "./data/issuers/jwt_sd/shared" "./data/issuers/mdl_1/shared")
# Directory to clean up before copying new files
CLEANUP_DIR="./data/issuers"

# Make sure we're in the right directory
CURRENT_DIR=${PWD##*/}
if [ "$CURRENT_DIR" != "verifier" ]; then
    echo "Run this script from the verifier/ folder"
    exit 1
fi

# Remove and re-create the cleanup directory (could contain old creds)
echo "Removing and re-creating $CLEANUP_DIR directory"
rm -fr "$CLEANUP_DIR"
mkdir -p "$CLEANUP_DIR"

# Loop through each source and target directory pair
for i in "${!SOURCE_DIRS[@]}"; do
    SOURCE_DIR="${SOURCE_DIRS[i]}"
    TARGET_DIR="${TARGET_DIRS[i]}"

    # Remove and re-create the target directory
    echo "Removing and re-creating $TARGET_DIR directory"
    mkdir -p "$TARGET_DIR"
    mkdir -p "${TARGET_DIR}/cache"

    echo "Copying files from $SOURCE_DIR to $TARGET_DIR"
    set -x
    cp "${SOURCE_DIR}/io_locations.sym" "${TARGET_DIR}/"
    cp "${SOURCE_DIR}/config.json" "${TARGET_DIR}/"
    cp "${SOURCE_DIR}/cache/groth16_pvk.bin" "${TARGET_DIR}/cache/"
    cp "${SOURCE_DIR}/cache/groth16_vk.bin" "${TARGET_DIR}/cache/"
    cp "${SOURCE_DIR}/cache/range_vk.bin" "${TARGET_DIR}/cache/"
    set +x

    echo "Finished copying for $TARGET_DIR"
done

# Copy the issuer public key for the mDL demo only
cp "${SOURCE_DIRS[2]}/issuer.pub" "${TARGET_DIRS[2]}/"

echo "All copy operations complete."
