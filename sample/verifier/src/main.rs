// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#[macro_use] extern crate rocket;

use crescent::verify_show_mdl;
use rocket::serde::{Serialize, Deserialize};
use rocket::serde::json::Json;
use rocket_dyn_templates::{context, Template};
use rocket::response::{Redirect};
use rocket::response::status::Custom;
use rocket::State;
use rocket::fs::FileServer;
use rocket::http::Status;
use std::collections::HashMap;
use serde_json::Value;
use jsonwebkey::JsonWebKey;
use std::path::Path;
use std::fs;
use std::io;
use std::sync::Mutex;
use uuid::Uuid;
use crescent::{utils::read_from_b64url, CachePaths, CrescentPairing, ShowProof, VerifierParams, verify_show};
use crescent_sample_setup_service::common::*;

// For now we assume that the verifier and Crescent Service live on the same machine and share disk access.
const CRESCENT_DATA_BASE_PATH : &str = "./data/issuers";
const CRESCENT_SHARED_DATA_SUFFIX : &str = "shared";

#[derive(Clone)]
struct ValidationResult {
    schema_UID: String,
    issuer_URL: String,
    disclosure_uid: String,
    disclosed_info: Option<String>,
}

// verifer config from Rocket.toml
struct VerifierConfig {
    // site 1 (JWT verifier)
    site1_verify_url: String,
    site1_verifier_name: String,
    site1_verifier_domain: String,
    
    // site 2 (mDL verifier)
    site2_verify_url: String,
    site2_verifier_name: String,
    site2_verifier_domain: String,

    // holds validation state
    validation_results: Mutex<HashMap<String, ValidationResult>>,
}

// struct for the JWT info
#[derive(Serialize, Deserialize, Clone, Debug)]
struct ProofInfo {
    proof: String,
    schema_UID: String,
    issuer_URL: String,
    disclosure_uid: String,    
}

// helper function to provide the base context for the login page
fn base_context(verifier_config: &State<VerifierConfig>) -> HashMap<String, String> {
    let site1_verifier_name_str = verifier_config.site1_verifier_name.clone();
    let site1_verify_url_str = uri!(verify).to_string();
    let site2_verifier_name_str = verifier_config.site2_verifier_name.clone();
    let site2_verify_url_str = uri!(verify).to_string();

    let mut context = HashMap::new();
    context.insert("site1_verifier_name".to_string(), site1_verifier_name_str);
    context.insert("site1_verify_url".to_string(), site1_verify_url_str);
    context.insert("site2_verifier_name".to_string(), site2_verifier_name_str);
    context.insert("site2_verify_url".to_string(), site2_verify_url_str);
    
    context
}

// redirect from `/` to `/login`
#[get("/")]
fn index_redirect() -> Redirect {
    Redirect::to("/login")
}

// route to serve the login page (site 1 - JWT verifier)
#[get("/login")]
fn login_page(verifier_config: &State<VerifierConfig>) -> Template {
    println!("*** Serving site 1 login page");

    // set the template meta values
    let context = base_context(verifier_config);
    
    // render the login page
    Template::render("login", context)
}

// route to serve the protected resource page after successful verification  (site 1 - JWT verifier)
#[get("/resource?<session_id>")]
fn resource_page(session_id: String, verifier_config: &State<VerifierConfig>) -> Template {
    println!("*** Serving site 1 resource page");

    let validation_result = verifier_config
        .validation_results
        .lock()
        .unwrap()
        .get(&session_id)
        .cloned();

    if let Some(result) = validation_result {
        Template::render("resource", context! {
            site1_verifier_name: verifier_config.site1_verifier_name.as_str(),
            email_domain: result.disclosed_info.unwrap_or_else(|| "example.com".to_string()),
        })
    } else {
        Template::render("error", context! { error: "Invalid session ID" })
    }
}
// route to serve the signup1 page (site 2 - mDL verifier)
#[get("/signup1")]
fn signup1_page(verifier_config: &State<VerifierConfig>) -> Template {
    println!("*** Serving site 2 signup1 page");

    // set the template meta values
    let context = base_context(verifier_config);
    
    // render the login page
    Template::render("signup1", context)
}

// route to serve the signup2 page (site 2 - mDL verifier)
#[get("/signup2?<session_id>")]
fn signup2_page(session_id: String, verifier_config: &State<VerifierConfig>) -> Template {
    println!("*** Serving site 2 signup2 page");

    let validation_result = verifier_config
        .validation_results
        .lock()
        .unwrap()
        .get(&session_id)
        .cloned();

    if validation_result.is_some() {
        Template::render("signup2", context! {
            site2_verifier_name: verifier_config.site2_verifier_name.as_str(),
        })
    } else {
        Template::render("error", context! { error: "Invalid session ID" })
    }
}
async fn fetch_and_save_jwk(issuer_url: &str, issuer_folder: &str) -> Result<(), String> {
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

    // Save the PEM-encoded key to issuer.pub in the issuer_folder
    let pub_key_path = Path::new(issuer_folder).join("issuer.pub");
    fs::write(&pub_key_path, pem_key).map_err(|err| format!("Failed to save public key: {:?}", err))?;

    println!("Saved issuer's public key to {:?}", pub_key_path);
    Ok(())
}

macro_rules! error_template {
    ($msg:expr, $verifier_config:expr) => {{
        println!("*** {}", $msg);
        let mut context = base_context($verifier_config);
        context.insert("error".to_string(), $msg.to_string());
        return Err(Template::render("login", context));
    }};
}

// route to verify a ZK proof given a ProofInfo, return a status  
#[post("/verify", format = "json", data = "<proof_info>")]
async fn verify(proof_info: Json<ProofInfo>, verifier_config: &State<VerifierConfig>) -> Result<Custom<Redirect>, Template> {
    println!("*** /verify called");
    println!("Schema UID: {}", proof_info.schema_UID);
    println!("Issuer URL: {}", proof_info.issuer_URL);
    println!("Disclosure UID: {}", proof_info.disclosure_uid);
    println!("Proof: {}", proof_info.proof);

    // verify if the schema_UID is one of our supported SCHEMA_UIDS
    if !SCHEMA_UIDS.contains(&proof_info.schema_UID.as_str()) {
        let msg = format!("Unsupported schema UID ({})", proof_info.schema_UID);
        error_template!(msg, verifier_config);
    }

    // Check that the schema and disclosure are compatible
    if !is_disc_supported_by_schema(&proof_info.disclosure_uid, &proof_info.schema_UID) {
        let msg = format!("Disclosure UID {} is not supported by schema {}", proof_info.disclosure_uid, proof_info.schema_UID);
        error_template!(msg, verifier_config);
    }

    let cred_type = match cred_type_from_schema(&proof_info.schema_UID) {
        Ok(cred_type) => cred_type,
        Err(_) => error_template!("Credential type not found", verifier_config),
    };
    
    // Define base folder path and credential-specific folder path
    let base_folder = format!("{}/{}", CRESCENT_DATA_BASE_PATH, proof_info.schema_UID);
    let shared_folder = format!("{}/{}", base_folder, CRESCENT_SHARED_DATA_SUFFIX);
    let issuer_UID = proof_info.issuer_URL.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_");
    let issuer_folder = format!("{}/{}", base_folder, issuer_UID);

    // check if the issuer folder exists, if not create it
    if fs::metadata(&issuer_folder).is_err() {
        println!("Issuer folder does not exist. Creating it: {}", issuer_folder);

        // Create credential-specific folder
        fs::create_dir_all(&issuer_folder).expect("Failed to create credential folder");

        // Copy the base folder content to the new credential-specific folder
        copy_with_symlinks(&shared_folder.as_ref(), &issuer_folder.as_ref());
        println!("Copied base folder to credential-specific folder: {}", issuer_folder);

        if cred_type == "jwt" {
            // Fetch the issuer's public key and save it to issuer.pub 
            fetch_and_save_jwk(&proof_info.issuer_URL, &issuer_folder).await.expect("Failed to fetch and save issuer's public key");
        }
    }

    let paths = CachePaths::new_from_str(&issuer_folder);
    let vp = VerifierParams::<CrescentPairing>::new(&paths).unwrap();

    let show_proof = match read_from_b64url::<ShowProof<CrescentPairing>>(&proof_info.proof) {
        Ok(show_proof) => show_proof, 
        Err(_) => error_template!("Invalid proof; deserialization error", verifier_config),
    };

    let is_valid;
    let disclosed_info;
    if cred_type == "jwt" {
        let (valid, info) = verify_show(&vp, &show_proof);
        is_valid = valid;
        disclosed_info = Some(info);
    } else {
        let age = disc_uid_to_age(&proof_info.disclosure_uid).unwrap(); // disclosure UID validated, so unwrap should be safe
        let (valid, info) = verify_show_mdl(&vp, &show_proof, age);
        is_valid = valid;
        disclosed_info = Some(info);
    }

    if is_valid {
        // Generate a unique session_id
        let session_id = Uuid::new_v4().to_string();

        // Store the validation result in the hashmap
        let validation_result = ValidationResult {
            schema_UID: proof_info.schema_UID.clone(),
            issuer_URL: proof_info.issuer_URL.clone(),
            disclosure_uid: proof_info.disclosure_uid.clone(),
            disclosed_info: disclosed_info.clone(),
        };
        verifier_config.validation_results.lock().unwrap().insert(session_id.clone(), validation_result);

        // Redirect to the resource page or signup2 page with the session_id as a query parameter
        let redirect_url = match cred_type {
            "jwt" => uri!(resource_page(session_id = session_id.clone())).to_string(),
            "mdl" => uri!(signup2_page(session_id = session_id.clone())).to_string(),
            _ => return error_template!("Unsupported credential type", verifier_config),
        };

        Ok(Custom(Status::SeeOther, Redirect::to(redirect_url)))
    } else {
        // return an error template if the proof is invalid
        error_template!("Proof is invalid.", verifier_config);
    }
}

#[launch]
fn rocket() -> _ {
    // Load verifier configuration
    let figment = rocket::Config::figment();
    let site1_verifier_name: String = figment.extract_inner("site1_verifier_name").unwrap_or_else(|_| "Example Verifier".to_string());
    let site1_verifier_domain: String = figment.extract_inner("site1_verifier_domain").unwrap_or_else(|_| "example.com".to_string());
    let site1_verify_url: String = format!("http://{}/verify", site1_verifier_domain);

    let site2_verifier_name: String = figment.extract_inner("site2_verifier_name").unwrap_or_else(|_| "Example Verifier".to_string());
    let site2_verifier_domain: String = figment.extract_inner("site2_verifier_domain").unwrap_or_else(|_| "example.com".to_string());
    let site2_verify_url: String = format!("http://{}/verify", site2_verifier_domain);

    let verifier_config = VerifierConfig {
        site1_verifier_name,
        site1_verifier_domain,
        site1_verify_url,
        site2_verifier_name,
        site2_verifier_domain,
        site2_verify_url,
        validation_results: Mutex::new(HashMap::new()),
    };
    
    rocket::build()
        .manage(verifier_config)
        .mount("/", FileServer::from("static"))
        .mount("/", routes![index_redirect, login_page, resource_page, signup1_page, signup2_page, verify])
    .attach(Template::fairing())
}

#[cfg(test)]
mod test {
    use std::fs;

    use super::*;
    use crate::test::rocket::local::blocking::Client;
    use crescent::{create_client_state, create_show_proof, verify_show, ProverParams};
    use crescent::groth16rand::ClientState;
    use crescent::prep_inputs::{parse_config, prepare_prover_inputs};
    use crescent::rangeproof::RangeProofPK;
    use crescent::structs::{GenericInputsJSON, IOLocations};
    use crescent::utils::{read_from_file, write_to_b64url};

    use rocket::http::Status;

    #[test]
    fn test_verify() {
        // BROKEN TODO: fixing that would require creating a test issuer folder in /data and copy the issuer
        // public key there so the verifier won't fail fetching it.

        // Step 1: generate the proof
        let paths = CachePaths::new_from_str(CRESCENT_DATA_BASE_PATH);
        let jwt = fs::read_to_string(&paths.jwt).expect(&format!("Unable to read JWT file from {}", paths.jwt));
        let issuer_pem = fs::read_to_string(&paths.issuer_pem).expect(&format!("Unable to read issuer public key PEM from {}", paths.issuer_pem));
        let prover_params = ProverParams::<CrescentPairing>::new(&paths).expect("Failed to create prover params");
        let config = parse_config(prover_params.config_str).expect("Failed to parse config");
        let (prover_inputs_json, _prover_aux_json, _public_ios_json) = prepare_prover_inputs(&config, &jwt, &issuer_pem).expect("Failed to prepare prover inputs");
        let prover_inputs = GenericInputsJSON { prover_inputs: prover_inputs_json };
        let mut client_state = create_client_state(&paths, &prover_inputs).expect("Failed to create client state");
        let range_pk: RangeProofPK<CrescentPairing> = read_from_file(&paths.range_pk).expect("Failed to read range proof pk");
        let io_locations_str: String = fs::read_to_string(&paths.io_locations).unwrap();
        let io_locations = IOLocations::new_from_str(&io_locations_str);

        // Create the show proof
        let show_proof = create_show_proof(&mut client_state, &range_pk, &io_locations);
        let show_proof_b64 = write_to_b64url(&show_proof);
        println!("Show proof: {}", show_proof_b64);

        // Step 2: call /verify with the proof
        let issuer_URL = "https://issuer.example.com".to_string();
        let schema_UID = "jwt_corporate_1".to_string();
        let disclosure_uid = "crescent://email_domain".to_string();
        let proof_info = ProofInfo {
            proof: show_proof_b64,
            schema_UID,
            issuer_URL,
            disclosure_uid
        };
        let client = Client::untracked(rocket()).expect("valid rocket instance");
        println!("Calling /verify with proof: {:?}", proof_info);
        let response = client.post("/verify").json(&proof_info).dispatch();    
            
        // check that we get a 303 redirect to the resource page
        assert_eq!(response.status(), Status::SeeOther, "Expected a 303 redirect");
    }    
}
