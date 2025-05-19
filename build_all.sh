#!/bin/bash

RELEASE_FLAG="--release"

git submodule update --init --recursive

#
# Circuit setup
#
cd circuit_setup/scripts
./run_setup.sh rs256
./run_setup.sh rs256-sd
./run_setup.sh rs256-db
./run_setup.sh mdl1

cd ../../creds

cargo run --bin crescent $RELEASE_FLAG --features print-trace zksetup --name rs256
cargo run --bin crescent $RELEASE_FLAG --features print-trace prove --name rs256
cargo run --bin crescent $RELEASE_FLAG --features print-trace show --name rs256
cargo run --bin crescent $RELEASE_FLAG --features print-trace verify --name rs256

cargo run --bin crescent $RELEASE_FLAG --features print-trace zksetup --name rs256-sd
cargo run --bin crescent $RELEASE_FLAG --features print-trace prove --name rs256-sd
cargo run --bin crescent $RELEASE_FLAG --features print-trace show --name rs256-sd
cargo run --bin crescent $RELEASE_FLAG --features print-trace verify --name rs256-sd

cargo run --bin crescent $RELEASE_FLAG --features print-trace zksetup --name rs256-db
cargo run --bin crescent $RELEASE_FLAG --features print-trace prove --name rs256-db
cargo run --bin crescent $RELEASE_FLAG --features print-trace show --name rs256-db
cargo run --bin crescent $RELEASE_FLAG --features print-trace verify --name rs256-db

cargo run --bin crescent $RELEASE_FLAG --features print-trace zksetup --name mdl1
cargo run --bin crescent $RELEASE_FLAG --features print-trace prove --name mdl1
cargo run --bin crescent $RELEASE_FLAG --features print-trace show --name mdl1
cargo run --bin crescent $RELEASE_FLAG --features print-trace verify --name mdl1
cd ..

#
# Sample setup
#
cd sample
# Node must be available for the .js scripts to be executed
./setup-sample.sh

#
# Client setup
#
cd client
npm install
npm run build:debug
cd ..
