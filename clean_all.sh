#!/bin/bash

# clean Rust targets
for d in circuit_setup/mdl-tools creds ecdsa-pop sample/verifier sample/issuer sample/client_helper sample/setup_service; do
  (cd $d && cargo clean && rm -f Cargo.lock)
done

# remove generated files
find creds/test-vectors -mindepth 1 ! -name README.md -exec rm -rf {} +
find circuit_setup/inputs -type f ! -iname 'README.md' ! -name '*.json' -delete
find circuit_setup/generated_files -type f ! -iname 'README.md' -delete

# clean wasm
rm -rf creds/pkg

# clean sample
cd sample && rm -rf client_helper/data verifier/data issuer/.well-known issuer/keys
cd client && npm run clean
cd ../..
