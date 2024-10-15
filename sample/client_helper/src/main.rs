// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#[macro_use] extern crate rocket;

use crescent::groth16rand::ClientState;
use crescent::prep_inputs::{parse_config, prepare_prover_inputs};
use crescent::rangeproof::RangeProofPK;
use crescent::structs::{GenericInputsJSON, IOLocations};
use rocket::serde::{Serialize, Deserialize};
use rocket::serde::json::Json;
use rocket::fs::NamedFile;
use crescent::{create_client_state, create_show_proof, verify_show, CachePaths, CrescentPairing, ShowParams, ShowProof};
use crescent::VerifierParams;
use crescent::utils::{read_from_b64url, read_from_bytes, read_from_file, write_to_b64url};
use std::fs::{self, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::path::Path;
use rocket::local::blocking::Client;
use rocket::http::Status;
use crescent::ProverParams;


// For now we assume that the Client Helper and Crescent Service live on the same machine and share disk access.
// TODO: we could make web requests to get the data from the setup service, but this will take more effort.
const CRESCENT_DATA_BASE_PATH : &str = "../../creds/test-vectors/rs256";

// struct for the JWT info
#[derive(Serialize, Deserialize, Clone)]
struct TokenInfo {
    jwt: String,        // A JWT token
    issuer_pem: String  // The issuer's public key, in PEM format
}

#[derive(Serialize, Deserialize, Clone)]
struct ShowData {
    client_state_b64: String,
    range_pk_b64: String,
    io_locations_str: String
}

#[cfg(test)]
impl ShowData {
    // In testing we mock up an instance from files: needs to have a show proof present
    fn new(paths : &CachePaths) -> Self {
        let client_state : ClientState<CrescentPairing> = read_from_file(&paths.client_state).unwrap();
        let range_pk : RangeProofPK<CrescentPairing> = read_from_file(&paths.range_pk).unwrap();
        let io_locations_str = fs::read_to_string(&paths.io_locations).unwrap();

        let client_state_b64 = write_to_b64url(&client_state);
        let range_pk_b64 = write_to_b64url(&range_pk);

        Self{client_state_b64, range_pk_b64, io_locations_str}
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct VerifyData {
    verifier_params_b64: String,
    show_proof_b64: String
}

#[derive(Serialize, Deserialize, Clone)]
struct VerifyResult {
    is_valid: bool,
    email_domain: String
}

// Create a ClientState that is ready for show proofs
#[post("/prepare", format = "json", data = "<token_info>")]
fn prepare(token_info: Json<TokenInfo>) -> Json<ShowData> {

    let jwt = &token_info.jwt;
    let issuer_pem = &token_info.issuer_pem;
    println!("got issuer_pem = {}", issuer_pem);

    let paths = CachePaths::new_from_str(CRESCENT_DATA_BASE_PATH);
    println!("Loading prover params");
    let prover_params = ProverParams::<CrescentPairing>::new(&paths).expect("Failed to create prover params");
    println!("Parsing config");
    let config = parse_config(prover_params.config_str).expect("Failed to parse config");
    println!("Creating prover inputs");
    let (prover_inputs_json, _prover_aux_json, _public_ios_json) = 
         prepare_prover_inputs(&config, &jwt, &issuer_pem).expect("Failed to prepare prover inputs");    
    let prover_inputs = GenericInputsJSON{prover_inputs: prover_inputs_json};
    
    println!("Creating client state... this is slow... ");
    let client_state = create_client_state(&paths, &prover_inputs).expect("Failed to create client state");
    
    let client_state_b64 = write_to_b64url(&client_state);
    println!("Done, client state is a base64_url encoded string that is {} chars long", client_state_b64.len());

    let range_pk : RangeProofPK<CrescentPairing> = read_from_file(&paths.range_pk).expect("Failed to read range proof pk");
    println!("Serializing range proof pk");
    let range_pk_b64 = write_to_b64url(&range_pk);
    println!("Reading IO locations file");
    let io_locations_str: String = fs::read_to_string(&paths.io_locations).unwrap();

    let sd = ShowData {client_state_b64, range_pk_b64, io_locations_str};
    println!("Returning ShowData");

    Json(sd)

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

// Takes a ClientState (as b64) and returns a Show proof
#[post("/show", format = "json", data = "<show_data>")]
fn show<'a>(show_data: Json<ShowData>) -> String {

    let mut client_state = read_from_b64url::<ClientState<CrescentPairing>>(&show_data.client_state_b64).unwrap();
    let io_locations = IOLocations::new_from_str(&show_data.io_locations_str);
    let range_pk = read_from_b64url::<RangeProofPK<'a, CrescentPairing>>(&show_data.range_pk_b64).unwrap();
    let show_proof = create_show_proof(&mut client_state, &range_pk, &io_locations);
    let show_proof_b64 = write_to_b64url(&show_proof);

    show_proof_b64
}

// Takes a show proof and verifier params and verifies the show proof
#[post("/verify", format = "json", data = "<verify_data>")]
fn verify(verify_data: Json<VerifyData>) -> Json<VerifyResult> {

    let vp = read_from_b64url::<VerifierParams<CrescentPairing>>(&verify_data.verifier_params_b64).unwrap();
    let show_proof = read_from_b64url::<ShowProof<CrescentPairing>>(&verify_data.show_proof_b64).unwrap();
    let (is_valid, email_domain) = verify_show(&vp, &show_proof);

    Json(VerifyResult{is_valid, email_domain})
}


#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![prepare, state, present, show, verify]) 
}


#[cfg(test)]
mod test {
    use std::fs;

    use super::*;
    use crate::{test::rocket::local::blocking::Client};
    use crescent::{utils::read_from_b64url, CrescentPairing, ProverParams, VerifierParams};
    use rocket::{http::Status, response};

    #[test]
    fn test_prepare_show() {
        let paths = CachePaths::new_from_str(CRESCENT_DATA_BASE_PATH);
        let jwt = fs::read_to_string(&paths.jwt).expect(&format!("Unable to read JWT file from {}", paths.jwt));
        let issuer_pem = fs::read_to_string(&paths.issuer_pem).expect(&format!("Unable to read issuer public key PEM from {} ", paths.issuer_pem));        
        let token_info = TokenInfo{jwt, issuer_pem};

        let client = Client::untracked(rocket()).expect("valid rocket instance");
        let response = client.post("/prepare").json(&token_info).dispatch();        
        assert_eq!(response.status(), Status::Ok);

        let show_data = response.into_json::<ShowData>().unwrap();
        let client_state = read_from_b64url::<ClientState<CrescentPairing>>(&show_data.client_state_b64);
        assert!(client_state.is_ok());

        let client = Client::untracked(rocket()).expect("valid rocket instance");
        let response = client.post("/show").json(&show_data).dispatch();
        assert_eq!(response.status(), Status::Ok);

    }

    #[test]
    fn test_show_verify() {
        let paths = CachePaths::new_from_str(CRESCENT_DATA_BASE_PATH);        
        
        let show_data = ShowData::new(&paths);
        let client = Client::untracked(rocket()).expect("valid rocket instance");
        let response = client.post("/show").json(&show_data).dispatch();
        assert_eq!(response.status(), Status::Ok);
        let show_proof_b64 = response.into_string().unwrap();

        let vp = VerifierParams::<CrescentPairing>::new(&paths).unwrap();
        let verifier_params_b64 = write_to_b64url(&vp);
        let verify_data = VerifyData{show_proof_b64, verifier_params_b64};
        let client = Client::untracked(rocket()).expect("valid rocket instance");
        let response = client.post("/verify").json(&verify_data).dispatch();
        assert_eq!(response.status(), Status::Ok);

        let verify_result = response.into_json::<VerifyResult>().unwrap();
        assert!(verify_result.is_valid);
        println!("Proof is valid, got email domain: {}", verify_result.email_domain);
    }

    
}
