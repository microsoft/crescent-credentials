# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

#!/usr/bin/bash

PRIVATE_KEY=../inputs/mdl1/device_private_key.pem
PUBLIC_KEY=../inputs/mdl1/device_public_key.pem

echo "Generating mDL device key pair"

# Generate the private key (PEM format)
openssl ecparam -name prime256v1 -genkey -noout -out ${PRIVATE_KEY}
echo "Generated private key: ${PRIVATE_KEY}"

# Extract the public key (PEM format)
openssl ec -in ${PRIVATE_KEY} -pubout -out ${PUBLIC_KEY}
echo "Generated public key: ${PUBLIC_KEY}"