# Sample Verifier

This folder contains a sample verifier who can validate Crescent proofs.

## Setup

The Crescent library must have been built and the ZK setup must have been run before setting up the server, specifically:
* From `../../setup/scripts`, run `./run_setup.sh rs256`, and 
* From `../../creds`, run `cargo run --bin crescent --release --features print-trace zksetup --name rs256`

Then, call the setup script `./setup_verifier.sh`.

To build the server, run `cargo build --release`.

## Running the server

To start the server, run `cargo run --release`. By default, the server will listen on `http://localhost:8004`; this can be modified by changing the `port` variable in the [Rocket.toml](./Rocket.toml) file. Adding `127.0.0.1 fabrikam.com` to the platform's hosts file (located at `C:\Windows\System32\drivers\etc\hosts` on Windows `/etc/hosts` on *nix systems) allows assessing the server at `http://fabrikam.com:8001`.

## Testing the server

To test the server, run (TODO: fix this; doesn't work anymore)

```
wget --method=POST --body-data='{"schema_UID":"some_uid", "issuer_URL":"http://issuer.url", "proof":"valid_proof"}' \
     --header='Content-Type: application/json' \
     --server-response \
     --max-redirect=3 \
     -d \
     http://127.0.0.1:8004/verify
```