# Sample Client Helper
 
This folder contains a sample Client Helper. This is a server that can be deployed locally or as a web service that the browser extension uses to offload expensive computations and storage. 

## Setup

The Crescent library must have been built and the ZK setup must have been run before setting up the server, specifically:
* From `../../setup/scripts`, run `./run_setup.sh rs256`, and 
* From `../../creds`, run `cargo run --bin crescent --release --features print-trace zksetup --name rs256`

To build the server, run `cargo build`.

## Running the server

To start the server, run `cargo run`. By default, the server will listen on `http://localhost:8003`; this can be modified by changing the `port` variable in the [Rocket.toml](./Rocket.toml) file.

## Testing the server

To test the server, run `cargo test` or visit the test page at the server's URL.  