// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#[macro_use] extern crate rocket;

use crescent::ProofSpec;
use rocket::serde::{Serialize, Deserialize};
use rocket::serde::json::Json;
use rocket_dyn_templates::{context, Template};
use rocket::response::Redirect;
use rocket::response::status::Custom;
use rocket::State;
use rocket::fs::{FileServer, NamedFile};
use rocket::http::Status;
use std::collections::{HashMap, HashSet};
use serde_json::{json, Value};
use jsonwebkey::JsonWebKey;
use std::path::Path;
use std::fs;
use std::sync::Mutex;
use uuid::Uuid;
use crescent::{utils::read_from_b64url, CachePaths, CrescentPairing, ShowProof, VerifierParams, verify_show};
use crescent_sample_setup_service::common::*;
use sha2::{Digest, Sha256};

// For now we assume that the verifier and Crescent Service live on the same machine and share disk access.
const CRESCENT_DATA_BASE_PATH : &str = "./data/issuers";
const CRESCENT_SHARED_DATA_SUFFIX : &str = "shared";

#[derive(Clone)]
struct ValidationResult {
    disclosed_info: Option<String>,
}

// verifer config from Rocket.toml
struct VerifierConfig {
    // server port
    port: String,

    // site 1 (JWT verifier)
    site1_verify_url: String,
    site1_verifier_name: String,
    site1_verifier_domain: String,
    site1_disclosure_uid: String,
    site1_proof_spec: String,

    // site 2 (mDL verifier)
    site2_verify_url: String,
    site2_verifier_name: String,
    site2_verifier_domain: String,
    site2_disclosure_uid: String,
    site2_proof_spec: String,

    // holds active session IDs (in a real system, these would be removed
    // after a timeout period)
    active_session_ids: Mutex<HashSet<String>>,

    // holds validation state
    validation_results: Mutex<HashMap<String, ValidationResult>>,
}

// struct for the JWT info
#[derive(Serialize, Deserialize, Clone, Debug)]
struct ProofInfo {
    proof: String,
    schema_uid: String,
    issuer_url: String,
    disclosure_uid: String,
    session_id: String,
}

// helper function to provide the base context for the login page
fn base_context(verifier_config: &State<VerifierConfig>) -> HashMap<String, String> {
    let site1_verifier_name_str = verifier_config.site1_verifier_name.clone();
    let site1_verify_url_str = verifier_config.site1_verify_url.clone();
    let site1_disclosure_uid_str = verifier_config.site1_disclosure_uid.clone();
    let site1_proof_spec_str = verifier_config.site1_proof_spec.clone();
    let site2_verifier_name_str = verifier_config.site2_verifier_name.clone();
    let site2_verify_url_str = verifier_config.site2_verify_url.clone();
    let site2_disclosure_uid_str = verifier_config.site2_disclosure_uid.clone();
    let site2_proof_spec_str = verifier_config.site2_proof_spec.clone();

    // encode the proof spec in b64url
    let site1_proof_spec_b64url = base64_url::encode(site1_proof_spec_str.as_bytes());
    let site2_proof_spec_b64url = base64_url::encode(site2_proof_spec_str.as_bytes());

    let session_id = Uuid::new_v4().to_string();
    verifier_config.active_session_ids.lock().unwrap().insert(session_id.clone());

    let mut context = HashMap::new();
    context.insert("site1_verifier_name".to_string(), site1_verifier_name_str);
    context.insert("site1_verify_url".to_string(), site1_verify_url_str);
    context.insert("site1_disclosure_uid".to_string(), site1_disclosure_uid_str);
    context.insert("site1_proof_spec_b64url".to_string(), site1_proof_spec_b64url);
    context.insert("site2_verifier_name".to_string(), site2_verifier_name_str);
    context.insert("site2_verify_url".to_string(), site2_verify_url_str);
    context.insert("site2_disclosure_uid".to_string(), site2_disclosure_uid_str);
    context.insert("site2_proof_spec_b64url".to_string(), site2_proof_spec_b64url);
    context.insert("session_id".to_string(), session_id);
    
    context
}

// route to serve the index page
#[get("/")]
fn index_page(verifier_config: &State<VerifierConfig>) -> Template {
    println!("*** Serving the index page");

    Template::render("index", context! {
        port: verifier_config.port.as_str(),
        site1_verifier_name: verifier_config.site1_verifier_name.as_str(),
        site2_verifier_name: verifier_config.site2_verifier_name.as_str(),
        site1_verifier_domain: verifier_config.site1_verifier_domain.as_str(),
        site2_verifier_domain: verifier_config.site2_verifier_domain.as_str(),
    })
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

fn get_email_domain(disclsosed_info : &Option<String>) -> String {

    match disclsosed_info {
        Some(info) => {
            match serde_json::from_str::<Value>(&info) {
                Ok(j) =>{
                    j.get("email_value").unwrap_or(&json!("ERROR: email key not found")).as_str().unwrap_or("ERROR: email domain is not a string").to_string()
                }
                Err(_) => "ERROR: domain not found".to_string()
            }
            
        }
        None => "ERROR: domain not found".to_string()
    }
}

// route to serve the protected resource page after successful verification  (site 1 - JWT verifier)
#[get("/resource?<session_id>")]
fn resource_page(session_id: String, verifier_config: &State<VerifierConfig>) -> Template {
    println!("*** Serving site 1 resource page");

    if session_id == "test" {
        Template::render("resource", context! {
            site1_verifier_name: verifier_config.site1_verifier_name.as_str(),
            email_domain: "TEST",
            country: "US",
            preferred_language: "en",
        })
    } else {
        let validation_result = verifier_config
            .validation_results
            .lock()
            .unwrap()
            .get(&session_id)
            .cloned();

        if let Some(result) = validation_result {
            Template::render("resource", context! {
                site1_verifier_name: verifier_config.site1_verifier_name.as_str(),               
                email_domain: get_email_domain(&result.disclosed_info),
                country: get_disclosed_claim("tenant_ctry_value", &result.disclosed_info),
                preferred_language: "en", // eventually, we can: get_disclosed_claim("xms_tpl_value", &result.disclosed_info),
            })
        } else {
            Template::render("error", context! { error: "Invalid session ID" })
        }
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

    if session_id == "test" {
        Template::render("signup2", context! {
            site2_verifier_name: verifier_config.site2_verifier_name.as_str(),
            email_domain: "TEST",
        })
    } else {
        let validation_result = verifier_config
            .validation_results
            .lock()
            .unwrap()
            .get(&session_id)
            .cloned();

        if validation_result.is_some() {
            // Determine site2_age based on site2_disclosure_uid
            let site2_age = match verifier_config.site2_disclosure_uid.as_str() {
                "crescent://over_18" => 18,
                "crescent://over_21" => 21,
                "crescent://over_65" => 65,
                _ => {
                    return Template::render("error", context! { error: "Unrecognized disclosure UID" });
                },
            };
            Template::render("signup2", context! {
                site2_verifier_name: verifier_config.site2_verifier_name.as_str(),
                site2_age: site2_age,
            })
        } else {
            Template::render("error", context! { error: "Invalid session ID" })
        }
    }
}

fn get_disclosed_claim(claim: &str, disclsosed_info : &Option<String>) -> String {
    match disclsosed_info {
        Some(info) => {
            match serde_json::from_str::<Value>(&info) {
                Ok(j) =>{
                    j.get(claim).unwrap_or(&json!("ERROR: disclosed claims not found")).as_str().unwrap_or("ERROR: disclosed claims is not a string").to_string()
                }
                Err(_) => "ERROR: disclosed claims not found".to_string()
            }
            
        }
        None => "ERROR: disclosed claims not found".to_string()
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
    println!("Session ID: {}", proof_info.session_id);
    println!("Schema UID: {}", proof_info.schema_uid);
    println!("Issuer URL: {}", proof_info.issuer_url);
    println!("Disclosure UID: {}", proof_info.disclosure_uid);
    println!("Proof: {}", proof_info.proof);

    // check if session_id is present in active_session_ids
    if !verifier_config.active_session_ids.lock().unwrap().contains(&proof_info.session_id) {
        let msg = format!("Unknown session ID ({})", proof_info.session_id);
        error_template!(msg, verifier_config);
    }

    // verify if the schema_uid is one of our supported SCHEMA_UIDS
    if !SCHEMA_UIDS.contains(&proof_info.schema_uid.as_str()) {
        let msg = format!("Unsupported schema UID ({})", proof_info.schema_uid);
        error_template!(msg, verifier_config);
    }

    // Check that the schema and disclosure are compatible
    if !is_disc_supported_by_schema(&proof_info.disclosure_uid, &proof_info.schema_uid) {
        let msg = format!("Disclosure UID {} is not supported by schema {}", proof_info.disclosure_uid, proof_info.schema_uid);
        error_template!(msg, verifier_config);
    }

    let cred_type = match cred_type_from_schema(&proof_info.schema_uid) {
        Ok(cred_type) => cred_type,
        Err(_) => error_template!("Credential type not found", verifier_config),
    };

    // Parse the challenge session ID as a byte array for the presentation message
    let challenge = proof_info.session_id.clone();

    // Define base folder path and credential-specific folder path
    let base_folder = format!("{}/{}", CRESCENT_DATA_BASE_PATH, proof_info.schema_uid);
    let shared_folder = format!("{}/{}", base_folder, CRESCENT_SHARED_DATA_SUFFIX);
    let issuer_uid = proof_info.issuer_url.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_");
    let issuer_folder = format!("{}/{}", base_folder, issuer_uid);

    // check if the issuer folder exists, if not create it
    if fs::metadata(&issuer_folder).is_err() {
        println!("Issuer folder does not exist. Creating it: {}", issuer_folder);

        // Create credential-specific folder
        fs::create_dir_all(&issuer_folder).expect("Failed to create credential folder");

        // Copy the base folder content to the new credential-specific folder
        match copy_with_symlinks(shared_folder.as_ref(), issuer_folder.as_ref()) {
            Ok(_) => println!("Copied base folder to credential-specific folder: {}", issuer_folder),
            Err(_) => error_template!("Failed to copy base folder to credential-specific folder", verifier_config),
        };

        if cred_type == "jwt" {
            // Fetch the issuer's public key and save it to issuer.pub 
            fetch_and_save_jwk(&proof_info.issuer_url, &issuer_folder).await.expect("Failed to fetch and save issuer's public key (JWT case)");
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
    let config_proof_spec = match cred_type {
        "jwt" => verifier_config.site1_proof_spec.clone(),
        "mdl" => verifier_config.site2_proof_spec.clone(),
        _ => error_template!("Unsupported credential type", verifier_config),
    };
    let mut ps : ProofSpec = serde_json::from_str(&config_proof_spec).unwrap();
    // hash the challenge to use as the presentation message (we need to hash it because device (for device-bound creds) only support signing digests)   
    ps.presentation_message = Some(Sha256::digest(challenge).to_vec());       
    if cred_type == "mdl" {
        let age = disc_uid_to_age(&proof_info.disclosure_uid).unwrap() as u64; // disclosure UID validated, so unwrap should be safe
        ps.range_over_year = Some(std::collections::BTreeMap::from([("birth_date".to_string(), age)]));
    }
    let (valid, info) = verify_show(&vp, &show_proof, &ps);
    is_valid = valid;
    disclosed_info = Some(info);

    println!("Proof is valid: {}", is_valid);
    println!("Disclosed info: {:?}", disclosed_info);

    if is_valid {
        // Store the validation result in the hashmap
        let validation_result = ValidationResult {
            disclosed_info: disclosed_info.clone(),
        };
        verifier_config.validation_results.lock().unwrap().insert(proof_info.session_id.clone(), validation_result);

        // Redirect to the resource page or signup2 page with the session_id as a query parameter
        let redirect_url = match cred_type {
            "jwt" => uri!(resource_page(session_id = proof_info.session_id.clone())).to_string(),
            "mdl" => uri!(signup2_page(session_id = proof_info.session_id.clone())).to_string(),
            _ => error_template!("Unsupported credential type", verifier_config),
        };

        Ok(Custom(Status::SeeOther, Redirect::to(redirect_url)))
    } else {
        // return an error template if the proof is invalid
        error_template!("Proof is invalid.", verifier_config);
    }
}

#[get("/site1-favicon.ico")]
async fn site1_favicon() -> Option<NamedFile> {
    NamedFile::open("static/img/site1-favicon.ico").await.ok()
}

#[get("/site2-favicon.ico")]
async fn site2_favicon() -> Option<NamedFile> {
    NamedFile::open("static/img/site2-favicon.ico").await.ok()
}

#[launch]
fn rocket() -> _ {
    // Load verifier configuration
    let figment = rocket::Config::figment();
    let port: String = figment.extract_inner("port").unwrap_or_else(|_| "8004".to_string());

    let site1_verifier_name: String = figment.extract_inner("site1_verifier_name").unwrap_or_else(|_| "Example Verifier".to_string());
    let site1_verifier_domain: String = figment.extract_inner("site1_verifier_domain").unwrap_or_else(|_| "example.com".to_string());
    let site1_verify_url: String = format!("http://{}:{}/verify", site1_verifier_domain, port);
    let site1_disclosure_uid: String = figment.extract_inner("site1_disclosure_uid").unwrap_or_else(|_| "{}".to_string());
    let site1_proof_spec: String = figment.extract_inner("site1_proof_spec").unwrap_or_else(|_| "{}".to_string());
    
    let site2_verifier_name: String = figment.extract_inner("site2_verifier_name").unwrap_or_else(|_| "Example Verifier".to_string());
    let site2_verifier_domain: String = figment.extract_inner("site2_verifier_domain").unwrap_or_else(|_| "example.com".to_string());
    let site2_verify_url: String = format!("http://{}:{}/verify", site2_verifier_domain, port);
    let site2_disclosure_uid: String = figment.extract_inner("site2_disclosure_uid").unwrap_or_else(|_| "{}".to_string());
    let site2_proof_spec: String = figment.extract_inner("site2_proof_spec").unwrap_or_else(|_| "{}".to_string());
    
    let verifier_config = VerifierConfig {
        port,
        site1_verifier_name,
        site1_verifier_domain,
        site1_verify_url,
        site1_disclosure_uid,
        site1_proof_spec,
        site2_verifier_name,
        site2_verifier_domain,
        site2_verify_url,
        site2_disclosure_uid,
        site2_proof_spec,
        active_session_ids: Mutex::new(HashSet::new()),
        validation_results: Mutex::new(HashMap::new()),
    };
    
    rocket::build()
        .manage(verifier_config)
        .mount("/", FileServer::from("static"))
        .mount("/", routes![index_page, login_page, resource_page, signup1_page, signup2_page, verify, site1_favicon, site2_favicon])
    .attach(Template::fairing())
}
