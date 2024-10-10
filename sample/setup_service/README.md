# Sample Setup Service
 
This folder contains a sample Crescent Setup Server. This entity sets up the ZK parameters used by all users and verifiers working with JWTs sharing the same schema.

## Setup

The Crescent library must have been built before setting up the server.

The server uses a JWT to generate the ZK parameters. An input JWT can be provided (coming from a collaborating issuer or a bootstrapping user); otherwise, a dummy JWT (with dummy attribute and signature values) can be used, as long as it matches the schema used by issuers. To set up the server, run `./scripts/setup-service.sh [JWT_path] [params_UID]` passing an optional JWT path (if absent, a dummy one will be generated and used) and an optional parameters UID (if absent, a random one will be used). The ZK parameters will be make available 

## Running the server

To start the server, run `cargo run`. By default, the server will listen on `http://localhost:8002`; this can be modified by changing the `port` variable in the [Rocket.toml](./Rocket.toml) file.
