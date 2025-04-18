#!/bin/bash
set -e

# call the issuer key generation script
../common/generate-keys.sh

# call the JWKS generation script
node scripts/generate-jwks.js

# copy the user device public key for device-bound JWTs
# note: the sample currently only uses one device key, shared by all users, simulating
#       a device key registered with the issuer out-of-band. Fresh device keys could
#       be generated for each user at issuance time; the sample flows would need to be updated
mkdir -p keys/
cp  -f ../../circuit_setup/inputs/rs256-db/device.pub keys/device.pub