// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#[macro_use] extern crate rocket;

use crescent::groth16rand::ClientState;
use crescent::prep_inputs::{parse_config, prepare_prover_inputs};
use crescent::rangeproof::RangeProofPK;
use crescent::structs::{GenericInputsJSON, IOLocations};
use crescent::{create_client_state, create_show_proof, create_show_proof_mdl, CachePaths, CrescentPairing, ProofSpec};
use crescent::utils::{read_from_b64url, read_from_file, write_to_b64url};
use crescent::ProverParams;
use crescent::device::TestDevice;

use crescent_sample_setup_service::common::*;

use rocket::serde::{Serialize, Deserialize};
use rocket::serde::json::Json;
use rocket::{get, post};
use rocket::State;
use rocket::fs::FileServer;

use uuid::Uuid;
use tokio::sync::Mutex;
use serde_json::{json, Value};
use jsonwebkey::JsonWebKey;
use sha2::{Digest, Sha256};

use std::collections::HashMap;
use std::fs::{self};
use std::sync::Arc;
use std::path::Path;
use std::cmp::min;
// For now we assume that the Client Helper and Crescent Service live on the same machine and share disk access.
// TODO: we could make web requests to get the data from the setup service, but this will take more effort (as documented in the sample README).
//       The code we use in unit tests to make web requests doesn't work from a route handler, we need to investigate.  It may 
//       only be suitable for testing, there is probably a better way.
//       Also we'll need some caching of the parameters to avoid fetching large files multiple times.
//       For caching the client helper could re-use the CachePaths struct and approach.
const CRESCENT_DATA_BASE_PATH : &str = "./data/creds";
const CRESCENT_SHARED_DATA_SUFFIX : &str = "shared";

// struct for the JWT info
#[derive(Serialize, Deserialize, Clone)]
struct CredInfo {
    cred: String,       // The credential
    schema_uid: String, // The schema UID for the credential
    issuer_url: String  // The URL of the issuer
}

// holds the ShowData for ready credentials
struct SharedState(Arc<Mutex<HashMap<String, Option<ShowData>>>>);

#[derive(Serialize, Deserialize, Clone, Debug)]
struct ShowData {
    client_state_b64: String,
    range_pk_b64: String,
    io_locations_str: String,
    device_priv_key_path: String
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

async fn fetch_and_save_jwk(issuer_url: &str, cred_folder: &str) -> Result<(), String> {
    // Prepare the JWK URL
    let jwk_url = format!("{}/.well-known/jwks.json", issuer_url);
    println!("Fetching JWK set from: {}", jwk_url);

    // Fetch the JWK
    let response = ureq::get(&jwk_url)
        .call()
        .map_err(|e| format!("Request failed: {}", e))?;
    let body = response.into_string()
        .map_err(|e| format!("Failed to parse response body: {}", e))?;
    let jwk_set: Value = serde_json::from_str(&body)
        .map_err(|e| format!("Failed to parse JSON: {}", e))?;

     // Extract the first key from the JWK set and parse it into `JsonWebKey`
     let jwk_value = jwk_set.get("keys")
        .and_then(|keys| keys.as_array())
        .and_then(|keys| keys.first())
        .ok_or_else(|| "No keys found in JWK set".to_string())?;

    // Deserialize the JSON `Value` into a `JsonWebKey`
    let jwk: JsonWebKey = serde_json::from_value(jwk_value.clone())
        .map_err(|e| format!("Failed to parse JWK: {}", e))?;

    // Convert the JWK to PEM format
    let pem_key = jwk.key.to_pem();

    // Save the PEM-encoded key to issuer.pub in the cred_folder
    let pub_key_path = Path::new(cred_folder).join("issuer.pub");
    fs::write(&pub_key_path, pem_key).map_err(|err| format!("Failed to save public key: {:?}", err))?;

    println!("Saved issuer's public key to {:?}", pub_key_path);
    Ok(())
}

fn compute_cred_uid(_cred : &str) -> String {
    // for now, we just generate a random UUID as the cred_uid
    Uuid::new_v4().to_string()
}

#[post("/prepare", format = "json", data = "<cred_info>")]
async fn prepare(cred_info: Json<CredInfo>, state: &State<SharedState>) -> Json<(String, Option<Vec<String>>)> {
    println!("*** /prepare called");
    println!("Schema UID: {}", cred_info.schema_uid);
    println!("Issuer URL: {}", cred_info.issuer_url);
    let l = min(50, cred_info.cred.len());
    println!("Credential: {}... ({} bytes)", &cred_info.cred[..l], cred_info.cred.len());

    // verify if the schema_uid is one of our supported SCHEMA_UIDS
    if !SCHEMA_UIDS.contains(&cred_info.schema_uid.as_str()) {
        println!("Unsupported schema UID: {}", cred_info.schema_uid);
        return Json(("error".to_string(), None)); // FIXME: not the right way to handle errors
    }
    let cred_type = cred_type_from_schema(&cred_info.schema_uid).unwrap();

    let cred_uid = compute_cred_uid(&cred_info.cred);
    println!("Generated credential UID: {}", cred_uid);

    // Define schemaUID-specific base folder path and a child credential-specific folder path
    let base_folder = format!("{}/{}", CRESCENT_DATA_BASE_PATH, cred_info.schema_uid);
    let shared_folder = format!("{}/{}", base_folder, CRESCENT_SHARED_DATA_SUFFIX);
    let cred_folder = format!("{}/{}", base_folder, cred_uid);

    // Create credential-specific folder
    // TODO: This fails if the directory already exists
    fs::create_dir_all(&cred_folder).expect("Failed to create credential folder");

    // Copy the base folder content to the new credential-specific folder
    copy_with_symlinks(shared_folder.as_ref(), cred_folder.as_ref()).map_err(|_| "Failed to copy base folder").unwrap();
    println!("Copied base folder to credential-specific folder: {}", cred_folder);

    // Insert task with empty data (indicating "preparing")
    {
        let mut tasks = state.inner().0.lock().await;
        tasks.insert(cred_uid.clone(), None);
    }

    // Clone the state for async task
    let state = state.inner().0.clone();
    let cred_uid_clone = cred_uid.clone();
    let issuer_url = cred_info.issuer_url.clone();

    let mut sd_claims: Option<Vec<String>> = None;
    // if the credential is a JWT with selective disclosure, we need to parse the claims that are available
    // to selectively disclose in the credential
    if cred_type == "jwt" && cred_info.schema_uid == "jwt_sd" {
        println!("Parsing claims from jwt_sd credential");
    
        // Get the payload part of the JWT
        let b64url_payload = cred_info.cred.split('.').nth(1).unwrap();
        let payload = base64_url::decode(b64url_payload).unwrap();
        let payload_str = String::from_utf8(payload).unwrap();
    
        // Parse the payload into a JSON object and collect keys
        let payload_json: serde_json::Value = serde_json::from_str(&payload_str).unwrap();
        let claims = payload_json.as_object().unwrap();
    
        // Collect the JSON keys into a vector
        sd_claims = Some(claims.keys().cloned().collect::<Vec<String>>());
        println!("Parsed claims: {:?}", sd_claims);    
    }

    // prepare the show data in a separate task using the per-credential folder
    rocket::tokio::spawn(async move {
        let task_result: Result<(), String> = async {
            let start_time = std::time::SystemTime::now();
            if cred_type == "jwt" {
                // fetch the issuer's JWK
                fetch_and_save_jwk(&issuer_url, &cred_folder).await?;

                println!("got schema_uid = {}", &cred_info.schema_uid);
                println!("got issuer_url = {}", &cred_info.issuer_url);
            }

            let paths = CachePaths::new_from_str(&cred_folder);

            println!("Loading prover params");
            let prover_params = ProverParams::<CrescentPairing>::new(&paths).map_err(|_| "Failed to create prover params")?;
            println!("Parsing config");
            let config = parse_config(&prover_params.config_str).map_err(|_| "Failed to parse config")?;

            let range_pk: RangeProofPK<CrescentPairing> = read_from_file(&paths.range_pk).map_err(|_| "Failed to read range proof pk")?;
            println!("Serializing range proof pk");
            let range_pk_b64 = write_to_b64url(&range_pk);
            println!("Reading IO locations file");
            let io_locations_str: String = fs::read_to_string(&paths.io_locations).map_err(|_| "Failed to read IO locations file")?;

            let client_state = 
            if cred_type == "mdl" {
                let client_state : ClientState<CrescentPairing> = read_from_file(&paths.client_state).map_err(|_| "Failed to read client state")?;
                client_state
            }
            else {
                println!("Loading issuer public key");
                let issuer_pem = fs::read_to_string(&paths.issuer_pem).map_err(|_| "Unable to read issuer public key PEM")?;                
                println!("Creating prover inputs");
                let (prover_inputs_json, prover_aux_json, _public_ios_json) = prepare_prover_inputs(&config, &cred_info.cred, &issuer_pem, None).map_err(|_| "Failed to prepare prover inputs")?;
                let prover_inputs = GenericInputsJSON { prover_inputs: prover_inputs_json };
                let prover_aux_string = json!(prover_aux_json).to_string();

                println!("Creating client state... this is slow...");

                create_client_state(&paths, &prover_inputs, Some(&prover_aux_string), "jwt").map_err(|_| "Failed to create client state")?
            };

            let client_state_b64 = write_to_b64url(&client_state);
            println!("Done, client state is a base64_url encoded string that is {} chars long", client_state_b64.len());
            
            // save the path to the device private key if the credential is device-bound
            let device_priv_key_path = paths.device_prv_pem.clone();
            let show_data = ShowData { client_state_b64, range_pk_b64, io_locations_str, device_priv_key_path };
            println!("Task complete, storing ShowData (size: {:?} bytes, took {:?})",
                show_data.client_state_b64.len() + show_data.io_locations_str.len() + show_data.range_pk_b64.len(), start_time.elapsed().unwrap());

            // Store the ShowData into the shared state (indicating "ready")
            let mut tasks = state.lock().await;
            tasks.insert(cred_uid_clone.clone(), Some(show_data));
            
            Ok(())
        }.await;

        // Handle any error by removing the `cred_uid` entry from the state
        if task_result.is_err() {
            let mut tasks = state.lock().await;
            tasks.remove(&cred_uid_clone);
            eprintln!("Error occurred, removing cred_uid from state: {:?}", task_result.err());
        }
    });

    Json((cred_uid, sd_claims))
}

#[get("/status?<cred_uid>")]
async fn status(cred_uid: String, state: &State<SharedState>) -> String {
    println!("*** /status called with credential UID: {}", cred_uid);
    let tasks = state.inner().0.lock().await;
    let status = match tasks.get(&cred_uid) {
        Some(Some(_)) => "ready".to_string(),    // If ShowData exists, return "ready"
        Some(None) => "preparing".to_string(),   // If still preparing, return "preparing"
        None => "unknown".to_string(),           // If no entry exists, return "unknown"
    };
    println!("Status for cred_uid {}: {}", cred_uid, status);
    status
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

#[get("/show?<cred_uid>&<disc_uid>&<challenge>&<proof_spec>")]
async fn show<'a>(cred_uid: String, disc_uid: String, challenge: String, proof_spec: String, state: &State<SharedState>) -> Result<String, String> {
    println!("*** /show called with credential UID {}, disc_uid {}, challenge {}, and proof_spec {}", cred_uid, disc_uid, challenge, proof_spec);
    let tasks = state.inner().0.lock().await;

    match tasks.get(&cred_uid) {
        Some(Some(show_data)) => {

            // Deserialize the ClientState and range proof public key from ShowData
            let mut client_state = read_from_b64url::<ClientState<CrescentPairing>>(&show_data.client_state_b64)
                .map_err(|_| "Failed to parse client state".to_string())?;
            let io_locations = IOLocations::new_from_str(&show_data.io_locations_str);
            let range_pk = read_from_b64url::<RangeProofPK<CrescentPairing>>(&show_data.range_pk_b64)
                .map_err(|_| "Failed to parse range proof public key".to_string())?;

            // Check that the cred stored at cred_uid supports the disclosure type disc_uid
            if !is_disc_uid_supported(&disc_uid, &client_state.credtype) {
                let msg = format!("Disclosure UID {} is not supported with credential of type {}", disc_uid, client_state.credtype);
                println!("{}",msg);
                return Err(msg);
            }

            // parse the proof spec from base64url
            let proof_spec_string = String::from_utf8(base64_url::decode(&proof_spec).unwrap()).unwrap();
            println!("Parsed proof spec from b64: {:?}", proof_spec_string);
            let mut proof_spec: ProofSpec = serde_json::from_str(&proof_spec_string)
                .map_err(|_| "Failed to parse proof spec".to_string())?;

            // hash the challenge to use as the presentation message (we need to hash it because device (for device-bound creds) only support signing digests)   
            proof_spec.presentation_message = Some(Sha256::digest(challenge).to_vec());

            // create the device signature (if cred is device-bound)
            let device_signature = 
            if proof_spec.device_bound.is_some() && proof_spec.device_bound.unwrap() {
                // instantiate the device from the private key path
                let device_prv_path = &show_data.device_priv_key_path;
                let device = TestDevice::new_from_file(&device_prv_path);
                Some(device.sign(proof_spec.presentation_message.as_ref().unwrap()))
            } else {
                None
            };

            // create the show proof
            let show_proof =
            if &client_state.credtype == "mdl" {
                let age = disc_uid_to_age(&disc_uid).map_err(|_| "Disclosure UID does not have associated age parameter".to_string())? as u64;
                proof_spec.range_over_year = Some(std::collections::BTreeMap::from([("birth_date".to_string(), age)]));
                create_show_proof_mdl(&mut client_state, &range_pk, &proof_spec, &io_locations, device_signature).map_err(|e| format!("Failed to create show proof. {:?}", e))?
            }
            else {
                create_show_proof(&mut client_state, &range_pk, &io_locations, &proof_spec, device_signature).map_err(|e| format!("Failed to create show proof. {:?}", e))?
            };
            
            // Return the show proof as a base64-url encoded string
            let show_proof_b64 = write_to_b64url(&show_proof);     

            Ok(show_proof_b64)
        }
        Some(None) => Err("ShowData is still being prepared.".to_string()), // Data is still being prepared
        None => Err("No ShowData found for the given cred_uid.".to_string()), // No data for this cred_uid
    }
}

#[get("/delete?<cred_uid>")]
async fn delete(cred_uid: String, state: &State<SharedState>) -> String {
    println!("*** /delete called with credential UID: {}", cred_uid);

    let mut delete_successful = false;
    let mut last_error = None;

    // We don't know the schema_uid for the cred_uid, so we need to try all supported ones
    // (we could lookup the schema_uid from the show_data associated from the cred_uid,
    // but that would only be available for prepared credentials)

    // Iterate over each schema_uid in SCHEMA_UIDS
    for schema_uid in SCHEMA_UIDS.iter() {
        // Define the path to the credential-specific folder
        let cred_folder = format!("{}/{}/{}", CRESCENT_DATA_BASE_PATH, schema_uid, cred_uid);
        println!("Attempting to delete folder: {}", cred_folder);

        // Attempt to remove the credential folder
        match fs::remove_dir_all(&cred_folder) {
            Ok(_) => {
                println!("Successfully deleted folder for cred_uid: {} under schema_uid: {}", cred_uid, schema_uid);
                delete_successful = true;
                break;  // Stop after successful deletion
            }
            Err(e) => {
                println!("Failed to delete folder for cred_uid: {} under schema_uid: {}. Error: {}", cred_uid, schema_uid, e);
                last_error = Some(e);
            }
        }
    }

    // Remove the entry from shared state
    let mut tasks = state.inner().0.lock().await;
    tasks.remove(&cred_uid);
    
    // Check if deletion was successful
    if delete_successful {
        "Deleted".to_string()
    } else {
        format!("Failed to delete folder for cred_uid: {}. Last error: {:?}", cred_uid, last_error)
    }
}

#[launch]
fn rocket() -> _ {
    let shared_state = SharedState(Arc::new(Mutex::new(HashMap::new())));

    rocket::build()
    .manage(shared_state)
    .mount("/", routes![prepare, status, get_show_data, show, delete])
    .mount("/", FileServer::from("static")) // Serve static files
}
