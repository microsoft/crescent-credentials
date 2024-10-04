# Sample JWT Issuer

This folder contains a sample JWT issuer.  This simulates an existing public issuer of credentials in JWT format.  We can then use Crescent to prove knowledge of these credentials.

## Setup

The issuer first generates its key pair by running `./generate-keys.sh`; this script uses OpenSSL to generate an RSA key pair and output the private and public keys in PEM format. The issuer then creates its JSON Web Key (JWK) set by running `cargo run --bin gen_jwks`; the JWK set will be exposed by the web server and will be downloaded by users and verifiers.

TODO: document how to add demo users

## Running the server

To start the server, run `cargo run`. By default, the server will listen on `http://localhost:8001`; this can be modified by changing the `port` variable in the [Rocket.toml](./Rocket.toml) file.

You can test the server is working correctly by visiting `http://localhost:8001/welcome` and entering the username `alice` and password `password`.
