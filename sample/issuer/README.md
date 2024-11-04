# Sample Issuer

This folder contains a sample JWT issuer. This simulates an existing issuer of credentials in JWT format. We can then use Crescent to prove knowledge of these credentials.

## Setup

`OpenSSL` and `node` must be available to generate the issuer's key material.

The issuer first generates its RSA key pair and creates its JSON Web Key (JWK) set by running `./setup-issuer.sh`; OpenSSL is used to generate an RSA key pair and output the private and public keys in PEM format. The JWK set will be exposed by the web server and will be downloaded by clients and verifiers.

By default, the issuer is named "Contoso" and the server listens on `http://localhost:8001`; this can be modified by changing the `issuer_name` and `port` variables in the [Rocket.toml](./Rocket.toml) file. Adding `127.0.0.1 contoso.com` to the platform's hosts file (located at `C:\Windows\System32\drivers\etc\hosts` on Windows `/etc/hosts` on *nix systems) allows assessing the server at `http://contoso.com:8001`.


## Running the server

To start the server, run `cargo run --release`.

You can test the server is working correctly by visiting `http://localhost:8001/welcome` and entering the username `alice` and password `password` (another `bob` user is available with the same password; other users can be added by modifying the `rocket` function in `src/main.rs`).
