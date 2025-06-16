#!/bin/bash
set -e

# usage: setup-sample.sh

# setup client_helper project
cd client_helper
./setup_client_helper.sh
cargo build --release
cd ..

# setup issuer project
cd issuer
./setup_issuer.sh
cargo build --release
cd ..

# setup verifier project
cd verifier
./setup_verifier.sh
cargo build --release
cd ..

# setup client project
cd client
./setup_client.sh
npm run build:debug

# Create json file with base64 encoded mdoc and device private key
# (until we have an issuer to issue mDLs, we use the ones generated in the Crescent lib)
cat <<EOF > mdl.json
{
  "mdoc": "$(base64 -w 0 "../../circuit_setup/inputs/mdl1/mdl.cbor")",
  "devicePrivateKey": "$(base64 -w 0 "../../circuit_setup/inputs/mdl1/device.prv")"
}
EOF

cd ..
