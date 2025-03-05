#!/bin/bash

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
cd ..
