# Sample Setup Service
 
This folder contains a sample Crescent Setup Server. This entity sets up the ZK parameters used by all users and verifiers working with JWTs sharing the same schema.

## Setup

TODO: implement and document how to generate the ZK params

## Running the server

To start the server, run `cargo run`. By default, the server will listen on `http://localhost:8002`; this can be modified by changing the `port` variable in the [Rocket.toml](./Rocket.toml) file.
