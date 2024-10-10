# Sample Issuer

This folder contains a sample JWT issuer. This simulates an existing issuer of credentials in JWT format. We can then use Crescent to prove knowledge of these credentials.

## Setup

`OpenSSL` and `node` must be available. 

The issuer first generates its RSA key pair and creates its JSON Web Key (JWK) set by running `./scripts/setup-issuer.sh`; OpenSSL is used to generate an RSA key pair and output the private and public keys in PEM format. The JWK set will be exposed by the web server and will be downloaded by clients and verifiers.

## Running the server

To start the server, run `cargo run`. By default, the server will listen on `http://localhost:8001`; this can be modified by changing the `port` variable in the [Rocket.toml](./Rocket.toml) file.

You can test the server is working correctly by visiting `http://localhost:8001/welcome` and entering the username `alice` and password `password` (another `bob` user is available with the same password; other users can be added by modifying the `rocket` function in `src/main.rs`).
