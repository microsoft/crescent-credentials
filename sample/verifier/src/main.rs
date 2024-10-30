// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#[macro_use] extern crate rocket;

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

// For now we assume that the Client Helper and Crescent Service live on the same machine and share disk access.
const CRESCENT_DATA_BASE_PATH : &str = "./data/issuers";
const CRESCENT_SHARED_DATA_PATH : &str = "./data/issuers/shared";

// verifer config from Rocket.toml
struct VerifierConfig {
    crescent_verify_url: String,
    crescent_disclosure_uid: String,
    verifier_name: String,
    verifier_domain: String,
}

// struct for the JWT info
#[derive(Serialize, Deserialize, Clone, Debug)]
struct ProofInfo {
    proof: String,
    schema_UID: String,
    issuer_URL: String
}

// helper function to provide the base context for the login page
fn base_login_context(verifier_config: &State<VerifierConfig>) -> HashMap<String, String> {
    let verifier_name_str = verifier_config.verifier_name.clone();
    let crescent_disclosure_uid_str = verifier_config.crescent_disclosure_uid.clone();
    let crescent_verify_url_str = uri!(verify).to_string();

    let mut context = HashMap::new();
    context.insert("verifier_name".to_string(), verifier_name_str);
    context.insert("crescent_verify_url".to_string(), crescent_verify_url_str);
    context.insert("crescent_disclosure_uid".to_string(), crescent_disclosure_uid_str);
    
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

// route to verify a ZK proof given a ProofInfo, return a status  
#[post("/verify", format = "json", data = "<proof_info>")]
async fn verify(proof_info: Json<ProofInfo>, verifier_config: &State<VerifierConfig>) -> Result<Custom<Redirect>, Template> {
    println!("*** /verify called");
    println!("Schema UID: {}", proof_info.schema_UID);
    println!("Issuer URL: {}", proof_info.issuer_URL);
    println!("Proof: {}", proof_info.proof);

    // Define base folder path and credential-specific folder path
    let base_folder = CRESCENT_DATA_BASE_PATH;
    let shared_folder = CRESCENT_SHARED_DATA_PATH;
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

        // Fetch the issuer's public key and save it to issuer.pub
        fetch_and_save_jwk(&proof_info.issuer_URL, &issuer_folder).await.expect("Failed to fetch and save issuer's public key");
    }

    let paths = CachePaths::new_from_str(&issuer_folder);
    let vp = VerifierParams::<CrescentPairing>::new(&paths).unwrap();
    let show_proof = read_from_b64url::<ShowProof<CrescentPairing>>(&proof_info.proof).unwrap();
    let (is_valid, email_domain) = verify_show(&vp, &show_proof);

    if is_valid {
        // redirect to the resource page (with status code 303 to ensure a GET request is made)
        println!("*** Proof is valid. Redirecting to resource page");
        Ok(Custom(Status::SeeOther, Redirect::to(uri!(resource_page))))
    } else {
        // return an error template if the proof is invalid
        println!("*** Proof is invalid. Returning error template");
        let mut context = base_login_context(verifier_config);
        context.insert("error".to_string(), "Invalid proof provided. Access denied.".to_string());
        Err(Template::render("login", context))
    }
}

#[launch]
fn rocket() -> _ {
    // Load verifier configuration
    let figment = rocket::Config::figment();
    let verifier_name: String = figment.extract_inner("verifier_name").unwrap_or_else(|_| "Example Verifier".to_string());
    let verifier_domain: String = figment.extract_inner("verifier_domain").unwrap_or_else(|_| "example.com".to_string());
    let crescent_verify_url: String = figment.extract_inner("crescent_verify_url").unwrap_or_else(|_| "example.com/verify".to_string());
    let crescent_disclosure_uid: String = figment.extract_inner("crescent_disclosure_uid").unwrap_or_else(|_| "crescent://email_domain".to_string());

    let verifier_config = VerifierConfig {
        verifier_name,
        verifier_domain,
        crescent_verify_url,
        crescent_disclosure_uid
    };
    
    rocket::build()
        .manage(verifier_config)
        .mount("/", FileServer::from("static"))
        .mount("/", routes![index_redirect, login_page, verify, resource_page])
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
        let schema_UID = "https://schemas.crescent.dev/jwt/012345".to_string();
        let proof_info = ProofInfo {
            proof: show_proof_b64,
            schema_UID: schema_UID,
            issuer_URL: issuer_URL
        };
        let client = Client::untracked(rocket()).expect("valid rocket instance");
        println!("Calling /verify with proof: {:?}", proof_info);
        let response = client.post("/verify").json(&proof_info).dispatch();    
            
        // check that we get a 303 redirect to the resource page
        assert_eq!(response.status(), Status::SeeOther, "Expected a 303 redirect");
    }    
}
