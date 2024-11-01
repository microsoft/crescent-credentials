# Sample Verifier

This folder contains a sample verifier who can validate Crescent proofs.

## Setup

The Crescent library must have been built and the ZK setup must have been run before setting up the server, specifically:
* From `../../setup/scripts`, run `./run_setup.sh rs256`, and 
* From `../../creds`, run `cargo run --bin crescent --release --features print-trace zksetup --name rs256`

Then, call the setup script `./setup_verifier.sh`.

To build the server, run `cargo build`.

## Running the server

To start the server, run `cargo run`. By default, the server will listen on `http://localhost:8004`; this can be modified by changing the `port` variable in the [Rocket.toml](./Rocket.toml) file.

## Testing the server

To test the server, start the [issuer](../issuer/README.md) and [client helper](../client_helper/README.md) servers, obtain a JWT from the issuer page and create a show proof using the client helper test page, and post it to the verifier using:

```
wget --method=POST --body-data='{"schema_UID":"jwt_corporate_1", "issuer_URL":"http://127.0.0.1:8001", "proof":"<PROOF_FROM_TEST_PAGE>"}' \
     --header='Content-Type: application/json' \
     --server-response \
     --max-redirect=3 \
     -d \
     http://127.0.0.1:8004/verify
```