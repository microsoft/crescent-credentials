#!/usr/bin/bash
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
#

set -e

# Change to the script's directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Call the issuer key generation script
../common/generate-keys.sh

# Call the JWKS generation script
node scripts/generate-jwks.js

# Copy the user device public key for device-bound JWTs
mkdir -p keys/
cp -f ../../circuit_setup/inputs/rs256-db/device.pub keys/device.pub
