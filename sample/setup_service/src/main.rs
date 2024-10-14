// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#[macro_use] extern crate rocket;

use rocket::serde::{Serialize, Deserialize};
use rocket::serde::json::Json;
use rocket::fs::NamedFile;
use crescent::{CachePaths, CrescentPairing, ShowParams};
use crescent::VerifierParams;
use crescent::utils::{write_to_b64url,read_from_b64url, read_from_bytes};
use std::path::PathBuf;
use std::path::Path;

const CRESCENT_DATA_BASE_PATH : &str = "../../creds/test-vectors/rs256";

// struct for the JWT info
#[derive(Serialize, Deserialize, Clone)]
struct TokenInfo {
    JWT: String,
    issuer: String
}

///// Routes for hosting parameters
 // Small parameters are sent as b64_url encoded strings. 
 // The large params required for one-time proof generation are hosted in a file

/// Ensure that both 
/// 1) /setup/scripts/run_setup.sh and 
/// 2) /creds/crescent zksetup
/// have been run and CRESCENT_DATA_PATH points to the place where the generated
/// parameters are stored
/// TODO: create a function to check on start-up that all parameters we serve 
/// in this server are actually generated

// Get the parameters required to generate the one-time proofs (the Groth16 proofs)
// Since the params are so big, we just expose the binary file for download
#[get("/<file..>")]
async fn files(file: PathBuf) -> Option<NamedFile> {
    let paths = CachePaths::new_from_str(CRESCENT_DATA_BASE_PATH);
    let path = Path::new(&paths._base).join(file);
    println!("Got request for file : {:?}", path);
    NamedFile::open(path).await.ok()
}


// Get the parameters required to generate presentation/show proofs
#[get("/show_params")]
fn show_params() -> String {
    let paths = CachePaths::new_from_str(CRESCENT_DATA_BASE_PATH);
    let show_params = ShowParams::<CrescentPairing>::new(&paths);
    let show_params_b64 = write_to_b64url(&show_params);
    
    show_params_b64
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
    rocket::build().mount("/", routes![show_params, verifier_params, files])
}


#[cfg(test)]
mod test {
    use super::*;
    use crate::{test::rocket::local::blocking::Client, verifier_params};
    use crescent::{utils::read_from_b64url, CrescentPairing, ProverParams, VerifierParams};
    use rocket::http::Status;

    #[test]
    fn test_verifier_params() {
        let client = Client::untracked(rocket()).expect("valid rocket instance");
        let response = client.get("/verifier_params").dispatch();
        assert_eq!(response.status(), Status::Ok);
        let s = response.into_string().unwrap();
        let vp = read_from_b64url::<VerifierParams<CrescentPairing>>(&s);

        assert!(vp.is_ok());
    }

    #[test]
    fn test_show_params() {
        let client = Client::untracked(rocket()).expect("valid rocket instance");
        let response = client.get("/show_params").dispatch();
        assert_eq!(response.status(), Status::Ok);
        let s = response.into_string().unwrap();
        let sp = read_from_b64url::<ShowParams<CrescentPairing>>(&s);

        assert!(sp.is_ok());
    }

    #[test]
    fn test_prover_params() {
        let client = Client::untracked(rocket()).expect("valid rocket instance");
        let response = client.get("/cache/prover_params.bin").dispatch();
        assert_eq!(response.status(), Status::Ok);
        println!("Downloading large file...");
        let s = response.into_bytes().unwrap();
        let pp = read_from_bytes::<ProverParams<CrescentPairing>>(s);
        assert!(pp.is_ok());
        let pp = pp.unwrap();
        println!("Got config file {}", pp.config_str);
        // Can also test with `wget localhost:8002/prover_params.bin`
    }       
}
