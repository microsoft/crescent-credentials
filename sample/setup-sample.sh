#!/bin/bash
set -e
set -x

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

# Create json file with base64 encoded MDOC and device private key
cat <<EOF > mdl.json
{
  "mdoc": "$(base64 -w 0 "../../circuit_setup/inputs/mdl1/mdl.cbor")",
  "devicePrivateKey": "$(base64 -w 0 "../../circuit_setup/inputs/mdl1/device.prv")"
}
EOF

cd ..
