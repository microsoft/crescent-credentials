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
use crescent::{utils::read_from_b64url, CachePaths, CrescentPairing, ShowProof, VerifierParams, verify_show};
use crescent_sample_setup_service::common::*;

// For now we assume that the verifier and Crescent Service live on the same machine and share disk access.
const CRESCENT_DATA_BASE_PATH : &str = "./data/issuers";
const CRESCENT_SHARED_DATA_SUFFIX : &str = "shared";

// verifer config from Rocket.toml
struct VerifierConfig {
    crescent_verify_url: String,
    verifier_name: String,
    verifier_domain: String,
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
fn base_login_context(verifier_config: &State<VerifierConfig>) -> HashMap<String, String> {
    let verifier_name_str = verifier_config.verifier_name.clone();
    let crescent_verify_url_str = uri!(verify).to_string();

    let mut context = HashMap::new();
    context.insert("verifier_name".to_string(), verifier_name_str);
    context.insert("crescent_verify_url".to_string(), crescent_verify_url_str);
    
    context
}

// redirect from `/` to `/login`
#[get("/")]
fn index_redirect() -> Redirect {
    Redirect::to("/login")
}

// route to serve the login page
#[get("/login")]
fn login_page(verifier_config: &State<VerifierConfig>) -> Template {
    println!("*** Serving login page");

    // set the template meta values
    let context = base_login_context(verifier_config);
    
    // render the login page
    Template::render("login", context)
}

// route to serve the protected resource page after successful verification
#[get("/resource")]
fn resource_page(verifier_config: &State<VerifierConfig>) -> Template {
    println!("*** Serving resource page");
    let verifier_name_str = verifier_config.verifier_name.as_str();

    // render the resource page
    Template::render("resource",
        context! {
            verifier_name: verifier_name_str,
            email_domain: "example.com" // TODO: get it from /verify (passing it as a query params is insecure, even for a demo, so perhaps we can use a cookie or session)
        }
    )
}

// route to serve the protected resource page after successful verification
#[get("/resource_over18")]
fn resource_page_over18(verifier_config: &State<VerifierConfig>) -> Template {
    println!("*** Serving resource page (over 18)");
    let verifier_name_str = verifier_config.verifier_name.as_str();

    // render the resource page
    Template::render("resource_over18",
        context! {
            verifier_name: verifier_name_str,
        }
    )
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
        let mut context = base_login_context($verifier_config);
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

    // Check that the schema and disclosue are compatible
    if !is_disc_supported_by_schema(&proof_info.disclosure_uid, &proof_info.schema_UID) {
        let msg = format!("Disclosure UID {} is not supported by schema {}", proof_info.disclosure_uid, proof_info.schema_UID);
        error_template!(msg, verifier_config);
    }

    let cred_type = match cred_type_from_disc_uid(&proof_info.disclosure_uid) {
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
        // TODO: don't copy shared parameters, just the credential-specific data (need to modify CachePaths)
        //       the params should be per-schema_uid too.
        fs_extra::dir::copy(
            shared_folder,
            &issuer_folder,
            &fs_extra::dir::CopyOptions::new().content_only(true),
        ).expect("Failed to copy base folder content");
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

    if cred_type == "jwt" {
        let (is_valid, email_domain) = verify_show(&vp, &show_proof);

        if is_valid {
            // redirect to the resource page (with status code 303 to ensure a GET request is made)
            println!("*** Proof is valid, email domain is {}. Redirecting to resource page", email_domain);
            Ok(Custom(Status::SeeOther, Redirect::to(uri!(resource_page))))
        } else {
            // return an error template if the proof is invalid
            error_template!("Proof is invalid.", verifier_config);
        }
    } 
    else {    // mdl
        let age = disc_uid_to_age(&proof_info.disclosure_uid).unwrap(); // disclosure UID already validated; should not fail
        let (is_valid, _) = verify_show_mdl(&vp, &show_proof, age);

        if is_valid {
            // redirect to the resource page (with status code 303 to ensure a GET request is made)
            println!("*** Proof is valid, user satisfies {}. Redirecting to resource page", proof_info.disclosure_uid);
            Ok(Custom(Status::SeeOther, Redirect::to(uri!(resource_page_over18))))
        } else {
            // return an error template if the proof is invalid
            error_template!("Proof is invalid.", verifier_config);
        }        
    }
}

#[launch]
fn rocket() -> _ {
    // Load verifier configuration
    let figment = rocket::Config::figment();
    let verifier_name: String = figment.extract_inner("verifier_name").unwrap_or_else(|_| "Example Verifier".to_string());
    let verifier_domain: String = figment.extract_inner("verifier_domain").unwrap_or_else(|_| "example.com".to_string());
    let crescent_verify_url: String = figment.extract_inner("crescent_verify_url").unwrap_or_else(|_| "example.com/verify".to_string());
    
    let verifier_config = VerifierConfig {
        verifier_name,
        verifier_domain,
        crescent_verify_url,
    };
    
    rocket::build()
        .manage(verifier_config)
        .mount("/", FileServer::from("static"))
        .mount("/", routes![index_redirect, login_page, verify, resource_page, resource_page_over18])
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
