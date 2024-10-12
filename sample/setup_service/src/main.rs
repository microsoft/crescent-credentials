// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#[macro_use] extern crate rocket;

use rocket::serde::{Serialize, Deserialize};
use rocket::serde::json::Json;
use crescent::{CachePaths, CrescentPairing};
use crescent::VerifierParams;
use crescent::utils::{write_to_b64url,read_from_b64url};

const CRESCENT_DATA_BASE_PATH : &str = "../../creds/test-vectors/rs256";

// struct for the JWT info
#[derive(Serialize, Deserialize, Clone)]
struct TokenInfo {
    JWT: String,
    issuer: String
}

// route to prepare JWT for ZK proof given a TokenInfo, return a token UID  
// TODO: belongs in client helper
#[post("/prepare", format = "json", data = "<token_info>")]
fn prepare(token_info: Json<TokenInfo>) -> Json<String> {
    let token_uid = "token_uid".to_string();
    Json(token_uid)
}

// route to verify if a token UID is ready for presentation
// TODO: belongs in client helper
#[get("/state/<token_uid>")]
fn state(token_uid: String) -> Json<String> {
    let state = "ready".to_string();
    Json(state)
}

// route to present a token UID and get a ZK proof
// TODO: should that be a post? with what params?
// TODO: belongs in client helper
#[get("/present/<token_uid>")]
fn present(token_uid: String) -> Json<String> {
    let zk_proof = "zk_proof".to_string();
    Json(zk_proof)
}


///// Routes for hosting parameters

// Get the parameters required to generate the one-time proofs (the Groth16 proofs)
#[get("/prover_params")]
fn prover_params() -> Json<String> {
    let params = "placeholder prover parameters".to_string();
    Json(params)
}

// Get the parameters required to generate presentation/show proofs
#[get("/show_params")]
fn show_params() -> Json<String> {
    let params = "placeholder show parameters".to_string();
    Json(params)
}

// Get the parameters required to verify presentation proofs
#[get("/verifier_params")]
fn verifier_params() -> String {
    let paths = CachePaths::new_from_str(CRESCENT_DATA_BASE_PATH);
    let verifier_params = VerifierParams::<CrescentPairing>::new(&paths);
    let verifier_params_b64 = write_to_b64url(&verifier_params);
    
    verifier_params_b64
}



#[launch]
fn rocket() -> _ {
    //rocket::build().mount("/", routes![prepare, state, present])  // TODO: these routes go in client_helper
    rocket::build().mount("/", routes![prover_params, show_params, verifier_params])
}


#[cfg(test)]
mod test {
    use super::*;
    use crate::{test::rocket::local::blocking::Client, verifier_params};
    use crescent::{utils::read_from_b64url, CrescentPairing, VerifierParams};
    use rocket::http::Status;

    #[test]
    fn test_verifier_params() {
        let client = Client::untracked(rocket()).expect("valid rocket instance");
        let response = client.get("/verifier_params").dispatch();
        assert_eq!(response.status(), Status::Ok);
        let s = response.into_string().unwrap();
        let vp = read_from_b64url::<VerifierParams<CrescentPairing>>(s);

        assert!(vp.is_ok());
        
    }
}
