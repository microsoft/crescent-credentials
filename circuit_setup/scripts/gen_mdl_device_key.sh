#!/usr/bin/bash
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
#

# Change to the directory where the script is located
cd "$(dirname "${BASH_SOURCE[0]}")" || exit

PRIVATE_KEY=../inputs/mdl1/device.prv
PUBLIC_KEY=../inputs/mdl1/device.pub

echo "Generating mDL device key pair"

# Generate the private key (PEM format)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -pkeyopt ec_param_enc:named_curve -out "${PRIVATE_KEY}"
echo "Generated private key: ${PRIVATE_KEY}"

# Extract the public key (PEM format)
openssl ec -in "${PRIVATE_KEY}" -pubout -out "${PUBLIC_KEY}"
echo "Generated public key: ${PUBLIC_KEY}"
