# Sample Verifier

This folder contains a sample verifier who can validate Crescent proofs. The project contains two sample web sites illustrating different use scenarios:
* Site 1: a mental health site requiring proof of employment (through email domain disclosure) for access
* Site 2: a social media site requiring proof of age for access

## Setup

The Crescent library must have been built and the ZK setup must have been run before setting up the server, specifically:
* From `../../circuit_setup/scripts`, run `./run_setup.sh rs256`, and 
* From `../../creds`, run `cargo run --bin crescent --release --features print-trace zksetup --name rs256`

Then, call the setup script `./setup_verifier.sh`.

To build the server, run `cargo build --release`.

## Running the server

To start the server, run `cargo run --release`. By default, the server will listen on `http://localhost:8004`; this can be modified by changing the `port` variable in the [Rocket.toml](./Rocket.toml) file. Adding `127.0.0.1 fabrikam.com` to the platform's hosts file (located at `C:\Windows\System32\drivers\etc\hosts` on Windows `/etc/hosts` on *nix systems) allows assessing the server at `http://fabrikam.com:8001`.

## Testing the server

To test the server, start the [issuer](../issuer/README.md) and [client helper](../client_helper/README.md) servers, obtain a JWT from the issuer page and create a show proof using the client helper test page, and post it to the verifier using:

```
wget --method=POST --body-data='{"schema_uid":"<SCHEMA_FROM_TEST_PAGE>", "issuer_url":"http://127.0.0.1:8001", "proof":"<PROOF_FROM_TEST_PAGE>", "dislcosure_uid":"<DISCLOSURE_UID_FROM_TEST_PAGE>"}' \
     --header='Content-Type: application/json' \
     --server-response \
     --max-redirect=3 \
     -d \
     http://127.0.0.1:8004/verify \
     -O- --no-verbose
```
