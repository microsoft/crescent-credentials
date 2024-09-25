# Crescent Sample Issuer

This folder contains a sample JWT issuer for the Crescent framework.

## Setup

The issuer first generate its key pair by running `./generate-keys.sh`; this script uses OpenSSL to generate an RSA key pair and output the private and public keys in PEM format. The issuer then creates its JSON Web Key (JWK) set by running `cargo run --bin gen_jwks`; the JWK set will be exposed by the web server and will be downloaded by users and verifiers.

TODO: document how to add demo users

## Running the server

To start the server, run `cargo run`.

You can test the server is working correctly by requesting a JWT using curl:
```
curl -X POST http://localhost:8000/issue -H "Content-Type: application/json" -d '{"username": "admin", "password": "password"}'
```