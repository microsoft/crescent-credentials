// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#[macro_use] extern crate rocket;

use crescent::groth16rand::ClientState;
use crescent::prep_inputs::{parse_config, prepare_prover_inputs};
use crescent::rangeproof::RangeProofPK;
use crescent::structs::{GenericInputsJSON, IOLocations};
use crescent::{create_client_state, create_show_proof, verify_show, CachePaths, CrescentPairing, ShowProof};
use crescent::VerifierParams;
use crescent::utils::{read_from_b64url, read_from_file, write_to_b64url};
use crescent::ProverParams;

use rocket::serde::{Serialize, Deserialize};
use rocket::serde::json::Json;
use rocket::tokio::net::TcpListener;
use rocket::{get, post};
use rocket::tokio::spawn;
use rocket::State;
use rocket::fs::FileServer;

use uuid::Uuid;

use tokio::sync::Mutex;

use std::collections::HashMap;
use std::fs::{self};
use std::sync::Arc;
use std::path::Path;

// define the cred schema UID. This is an opaque string that identifies the setup parameters (TODO: share this value in a common config crate)
const SCHEMA_UID : &str = "https://schemas.crescent.dev/jwt/012345";

// For now we assume that the Client Helper and Crescent Service live on the same machine and share disk access.
// TODO: we could make web requests to get the data from the setup service, but this will take more effort.
//       The code we use in unit tests to make web requests doesn't work from a route handler, we need to investigate.  It may 
//       only be suitable for testing, there is probably a better way.
//       Also we'll need some caching of the parameters to avoid fetching large files multiple times.
//       For caching the client helper could re-use the CachePaths struct and approach.
const CRESCENT_DATA_BASE_PATH : &str = "./data/creds";

// struct for the JWT info
#[derive(Serialize, Deserialize, Clone)]
struct CredInfo {
    cred: String,        // The credential (a JWT)
    schema_UID: String, // The schema UID for the credential
    issuer_URL: String  // The URL of the issuer
}

// holds the ShowData for ready credentials
struct SharedState(Arc<Mutex<HashMap<String, Option<ShowData>>>>);

#[derive(Serialize, Deserialize, Clone, Debug)]
struct ShowData {
    client_state_b64: String,
    range_pk_b64: String,
    io_locations_str: String
}

#[cfg(test)]
impl ShowData {
    // In testing we mock up an instance from files: needs to have a show proof that we can use
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

#[post("/prepare", format = "json", data = "<cred_info>")]
async fn prepare(cred_info: Json<CredInfo>, state: &State<SharedState>) -> String {
    println!("*** /prepare called");
    println!("Schema UID: {}", cred_info.schema_UID);
    println!("Issuer URL: {}", cred_info.issuer_URL);
    println!("Credential: {}", cred_info.cred);

    // create a unique identifier for the credential. For now, this is a UUID; we could use the hash
    // of the credential to make sure we have a cred-dependent unique identifier (TODO).
    let cred_uid = Uuid::new_v4().to_string();
    println!("Generated credential UID: {}", cred_uid);

    // Define base folder path and credential-specific folder path
    let base_folder = CRESCENT_DATA_BASE_PATH;
    let cred_folder = format!("{}/{}", base_folder, cred_uid);

    // Copy the base folder into the new credential-specific folder
    // TODO: don't copy shared parameters, just the credential-specific data (need to modify CachePaths)
    //       the params should be per-schema_uid too.
    fs::create_dir_all(&cred_folder).expect("Failed to create credential folder");
    fs_extra::dir::copy(
        base_folder,
        &cred_folder,
        &fs_extra::dir::CopyOptions::new().content_only(true),
    ).expect("Failed to copy base folder content");
    println!("Copied base folder to credential-specific folder: {}", cred_folder);

    // Insert task with empty data (indicating "preparing")
    {
        let mut tasks = state.inner().0.lock().await;
        tasks.insert(cred_uid.clone(), None);
    }

    let state = state.inner().0.clone();
    let cred_uid_clone = cred_uid.clone();

    rocket::tokio::spawn(async move {
        // prepare the show data in a separate task using the per-credential folder
        // TODO: catch errors, and set the task to an error state (to inform clients to stop waiting)
        let jwt = &cred_info.cred;
        let schema_UID = &cred_info.schema_UID;
        println!("got schema_UID = {}", schema_UID);
        let issuer_URL = &cred_info.issuer_URL;
        println!("got issuer_URL = {}", issuer_URL);

        let paths = CachePaths::new_from_str(&cred_folder);
        println!("Loading issuer public key");
        let issuer_pem = fs::read_to_string(&paths.issuer_pem).expect(&format!("Unable to read issuer public key PEM from {}", paths.issuer_pem));

        println!("Loading prover params");
        let prover_params = ProverParams::<CrescentPairing>::new(&paths).expect("Failed to create prover params");
        println!("Parsing config");
        let config = parse_config(prover_params.config_str).expect("Failed to parse config");

        println!("Creating prover inputs");
        let (prover_inputs_json, _prover_aux_json, _public_ios_json) = prepare_prover_inputs(&config, &jwt, &issuer_pem).expect("Failed to prepare prover inputs");
        let prover_inputs = GenericInputsJSON { prover_inputs: prover_inputs_json };

        println!("Creating client state... this is slow... ");
        let client_state = create_client_state(&paths, &prover_inputs).expect("Failed to create client state");

        let client_state_b64 = write_to_b64url(&client_state);
        println!("Done, client state is a base64_url encoded string that is {} chars long", client_state_b64.len());

        let range_pk: RangeProofPK<CrescentPairing> = read_from_file(&paths.range_pk).expect("Failed to read range proof pk");
        println!("Serializing range proof pk");
        let range_pk_b64 = write_to_b64url(&range_pk);
        println!("Reading IO locations file");
        let io_locations_str: String = fs::read_to_string(&paths.io_locations).unwrap();

        let show_data = ShowData { client_state_b64, range_pk_b64, io_locations_str };
        println!("Task complete, storing ShowData: {:?}", show_data);

        // Store the ShowData into the shared state (indicating "ready")
        let mut tasks = state.lock().await;
        tasks.insert(cred_uid_clone, Some(show_data));
    });

    cred_uid
}

#[get("/status?<cred_uid>")]
async fn status(cred_uid: String, state: &State<SharedState>) -> String {
    println!("*** /status called with credential UID: {}", cred_uid);
    let tasks = state.inner().0.lock().await;
    match tasks.get(&cred_uid) {
        Some(Some(_)) => "ready".to_string(), // If ShowData exists, return "ready"
        Some(None) => "preparing".to_string(), // If still preparing, return "preparing"
        None => "unknown".to_string(), // If no entry exists, return "unknown"
    }
}

#[get("/getshowdata?<cred_uid>")]
async fn get_show_data(cred_uid: String, state: &State<SharedState>) -> Result<Json<ShowData>, String> {
    println!("*** /getshowdata called with credential UID: {}", cred_uid);
    let tasks = state.inner().0.lock().await;

    match tasks.get(&cred_uid) {
        Some(Some(show_data)) => Ok(Json(show_data.clone())), // Return the ShowData if found
        Some(None) => Err("ShowData is still being prepared.".to_string()), // Still preparing
        None => Err("No ShowData found for the given cred_uid.".to_string()), // Invalid cred_uid
    }
}

#[get("/show?<cred_uid>&<disc_uid>")]
async fn show<'a>(cred_uid: String, disc_uid: String, state: &State<SharedState>) -> Result<String, String> {
    println!("*** /show called with credential UID {} and disc_uid {}", cred_uid, disc_uid);
    let tasks = state.inner().0.lock().await;
    
    match tasks.get(&cred_uid) {
        Some(Some(show_data)) => {
            // Deserialize the ClientState and range proof public key from ShowData
            let mut client_state = read_from_b64url::<ClientState<CrescentPairing>>(&show_data.client_state_b64)
                .map_err(|_| "Failed to parse client state".to_string())?;
            let io_locations = IOLocations::new_from_str(&show_data.io_locations_str);
            let range_pk = read_from_b64url::<RangeProofPK<'a, CrescentPairing>>(&show_data.range_pk_b64)
                .map_err(|_| "Failed to parse range proof public key".to_string())?;

            // Create the show proof
            let show_proof = create_show_proof(&mut client_state, &range_pk, &io_locations);
            let show_proof_b64 = write_to_b64url(&show_proof);

            // Return the show proof as a base64-url encoded string
            Ok(show_proof_b64)
        }
        Some(None) => Err("ShowData is still being prepared.".to_string()), // Data is still being prepared
        None => Err("No ShowData found for the given cred_uid.".to_string()), // No data for this cred_uid
    }
}


#[get("/delete?<cred_uid>")]
async fn delete(cred_uid: String, state: &State<SharedState>) -> String {
    println!("*** /delete called with credential UID: {}", cred_uid);

    // Define the path to the credential-specific folder
    let cred_folder = format!("{}/{}", CRESCENT_DATA_BASE_PATH, cred_uid);

    // Attempt to remove the credential folder and handle errors if the folder does not exist
    match fs::remove_dir_all(&cred_folder) {
        Ok(_) => println!("Successfully deleted folder for cred_uid: {}", cred_uid),
        Err(e) => println!("Failed to delete folder for cred_uid: {}. Error: {}", cred_uid, e),
    }

    // Remove the entry from shared state
    let mut tasks = state.inner().0.lock().await;
    tasks.remove(&cred_uid);

    "Deleted".to_string()
}


#[launch]
fn rocket() -> _ {
    let shared_state = SharedState(Arc::new(Mutex::new(HashMap::new())));

    rocket::build()
    .manage(shared_state)
    .mount("/", routes![prepare, status, get_show_data, show, delete])
    .mount("/", FileServer::from("static")) // Serve static files
}

#[cfg(test)]
mod test {
    use std::fs;

    use super::*;
    use crate::test::rocket::local::blocking::Client;
    use crescent::{utils::read_from_b64url, CrescentPairing, VerifierParams};
    use rocket::http::Status;
    use std::time::Duration;

    #[test]
    // tests all server calls (/prepare, /status, /getshowdata, /show) and verify the resulting proof
    fn test_end_to_end() {
        let paths = CachePaths::new_from_str(CRESCENT_DATA_BASE_PATH);
        let cred = fs::read_to_string(&paths.jwt).expect(&format!("Unable to read JWT file from {}", paths.jwt));
        let issuer_URL = "https://issuer.example.com".to_string();
        let schema_UID = SCHEMA_UID.to_string();
        let cred_info = CredInfo{cred, schema_UID, issuer_URL};

         // Step 1: Call /prepare and get the cred_uid
        let client = Client::untracked(rocket()).expect("valid rocket instance");
        let response = client.post("/prepare").json(&cred_info).dispatch();        
        assert_eq!(response.status(), Status::Ok);
        let cred_uid = response.into_string().expect("Failed to get cred_uid");

        // Step 2: Poll the /status endpoint every 5 seconds until the credential is "ready"
        let mut status = "preparing".to_string();
        for _ in 0..100 { // Try 100 times, with 5 second intervals
            let response = client.get(format!("/status?cred_uid={}", cred_uid)).dispatch();
            assert_eq!(response.status(), Status::Ok);
            status = response.into_string().expect("Failed to get status");
            if status == "ready" {
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs(5)); // Wait for 5 seconds
        }
        assert_eq!(status, "ready", "Credential preparation did not complete in time");

        // Step 3: Retrieve the show data using /getshowdata
        let response = client.get(format!("/getshowdata?cred_uid={}", cred_uid)).dispatch();
        assert_eq!(response.status(), Status::Ok);
        let show_data = response.into_json::<ShowData>().expect("Failed to parse ShowData");

        // Step 4: Call /show with the retrieved show data and a disc_uid
        let disc_uid = "some_disc_uid";  // Replace with actual disc_uid if needed
        let response = client.get(format!("/show?cred_uid={}&disc_uid={}", cred_uid, disc_uid)).dispatch();
        assert_eq!(response.status(), Status::Ok);

        // Step 5: Verify the resulting proof
        let vp = VerifierParams::<CrescentPairing>::new(&paths).unwrap();
        let show_proof_b64 = response.into_string().expect("Failed to get show proof");
        let show_proof = read_from_b64url::<ShowProof<CrescentPairing>>(&show_proof_b64).expect("Invalid ShowProof format");
        let (is_valid, email_domain) = verify_show(&vp, &show_proof);
        assert!(is_valid, "Show proof is not valid");
        println!("Proof is valid, got email domain: {}", email_domain);
    }    
}
