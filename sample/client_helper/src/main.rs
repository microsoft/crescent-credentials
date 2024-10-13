// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#[macro_use] extern crate rocket;

use crescent::groth16rand::ClientState;
use crescent::prep_inputs::{parse_config, prepare_prover_inputs};
use crescent::structs::GenericInputsJSON;
use rocket::serde::{Serialize, Deserialize};
use rocket::serde::json::Json;
use rocket::fs::NamedFile;
use crescent::{create_client_state, CachePaths, CrescentPairing, ShowParams};
use crescent::VerifierParams;
use crescent::utils::{write_to_b64url,read_from_b64url, read_from_bytes};
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::path::Path;
use rocket::local::blocking::Client;
use rocket::http::Status;
use crescent::ProverParams;


// For now we assume that the Client Helper and Crescent Service live on the same machine and share disk acces.
// TODO: we could make web requests to get the data from the setup service, but this will take more effort.
const CRESCENT_DATA_BASE_PATH : &str = "../../creds/test-vectors/rs256";

// struct for the JWT info
#[derive(Serialize, Deserialize, Clone)]
struct TokenInfo {
    jwt: String,        // A JWT token
    issuer_pem: String  // The issuer's public key, in PEM format
}

// Create a ClientState that is ready for show proofs
#[post("/prepare", format = "json", data = "<token_info>")]
fn prepare(token_info: Json<TokenInfo>) -> String {

    let jwt = &token_info.jwt;
    let issuer_pem = &token_info.issuer_pem;
    println!("got issuer_pem = {}", issuer_pem);

    let paths = CachePaths::new_from_str(CRESCENT_DATA_BASE_PATH);
    println!("Loading prover params");
    let prover_params = ProverParams::<CrescentPairing>::new(&paths);
    println!("Parsing config");
    let config = parse_config(prover_params.config_str).expect("Failed to parse config");
    println!("Creating prover inputs");
    let (prover_inputs_json, _prover_aux_json, _public_ios_json) = 
         prepare_prover_inputs(&config, &jwt, &issuer_pem).expect("Failed to prepare prover inputs");    
    let prover_inputs = GenericInputsJSON{prover_inputs: prover_inputs_json};
    
    println!("Creating client state... this is slow... ");
    let client_state = create_client_state(&paths, &prover_inputs);
    
    let client_state_b64 = write_to_b64url(&client_state);
    println!("Done, returning client state as base64_url encoded string, {} chars long", client_state_b64.len());

    client_state_b64

// TODO: This code doesn't work; something about async and blocking
    // // Fetch prover params from Crescent service
    // let client = Client::untracked(rocket()).expect("valid rocket instance");
    // let response = client.get("localhost:8002/cache/prover_params.bin").dispatch();
    // assert_eq!(response.status(), Status::Ok);
    // print!("Downloading large prover parameters... ");
    // let s = response.into_bytes().unwrap();
    // let pp = read_from_bytes::<ProverParams<CrescentPairing>>(s);
    // assert!(pp.is_ok());    
    // println!(" done.");

    // // Fetch R1CS instance and witness generator. 
    // // TODO: These don't support serialization to allow them to be included in ProverParams
    // let response = client.get("localhost:8002/main.wasm").dispatch();
    // assert_eq!(response.status(), Status::Ok);
    // print!("Downloading wasm for witness generation... ");
    // let s = response.into_bytes().unwrap();
    // let f = OpenOptions::new()
    // .write(true)
    // .create(true)
    // .truncate(true)
    // .open("main.wasm")
    // .unwrap();
    // assert!(BufWriter::new(f).write_all(&s).is_ok());

    // let response = client.get("localhost:8002/main_c.r1cs").dispatch();
    // assert_eq!(response.status(), Status::Ok);
    // print!("Downloading R1CS instance... ");
    // let s = response.into_bytes().unwrap();
    // let f = OpenOptions::new()
    // .write(true)
    // .create(true)
    // .truncate(true)
    // .open("main_c.r1cs")
    // .unwrap();
    // assert!(BufWriter::new(f).write_all(&s).is_ok());    

}

// route to verify if a token UID is ready for presentation
#[get("/state/<token_uid>")]
fn state(token_uid: String) -> Json<String> {
    let state = "ready".to_string();
    Json(state)
}

// route to present a token UID and get a ZK proof
// TODO: should that be a post? with what params?
#[get("/present/<token_uid>")]
fn present(token_uid: String) -> Json<String> {
    let zk_proof = "zk_proof".to_string();
    Json(zk_proof)
}




#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![prepare, state, present]) 
}


#[cfg(test)]
mod test {
    use std::fs;

    use super::*;
    use crate::{test::rocket::local::blocking::Client};
    use crescent::{utils::read_from_b64url, CrescentPairing, ProverParams, VerifierParams};
    use rocket::{http::Status, response};

    #[test]
    fn test_prepare() {
        let paths = CachePaths::new_from_str(CRESCENT_DATA_BASE_PATH);
        let jwt = fs::read_to_string(&paths.jwt).expect(&format!("Unable to read JWT file from {}", paths.jwt));
        let issuer_pem = fs::read_to_string(&paths.issuer_pem).expect(&format!("Unable to read issuer public key PEM from {} ", paths.issuer_pem));        
        let token_info = TokenInfo{jwt, issuer_pem};

        let client = Client::untracked(rocket()).expect("valid rocket instance");
        let response = client.post("/prepare").json(&token_info).dispatch();        
        assert_eq!(response.status(), Status::Ok);

        let response_str = response.into_string().unwrap();
        println!("Got client state response, {} characters long", response_str.len());
        let client_state = read_from_b64url::<ClientState<CrescentPairing>>(response_str);
        assert!(client_state.is_ok());
                
    }
    
}
