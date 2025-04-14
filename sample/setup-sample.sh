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
# until we have an issuer to issue mDLs, we use the ones generated in the Crescent lib
# the sample expects a hex file, so we convert the binary file to hex
hexdump -v -e '1/1 "%02x"' "../../circuit_setup/inputs/mdl1/mdl.cbor" > "mdl.cbor.hex"
cd ..
