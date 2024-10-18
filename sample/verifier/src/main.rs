// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#[macro_use] extern crate rocket;

use rocket::serde::{Serialize, Deserialize};
use rocket::serde::json::Json;
use rocket_dyn_templates::{context, Template};
use rocket::response::{Redirect};
use rocket::response::status::Custom;
use rocket::http::Status;
use std::collections::HashMap;

// struct for the JWT info
#[derive(Serialize, Deserialize, Clone)]
struct ProofInfo {
    proof: String,
    schema_UID: String,
    issuer_URL: String
}

// helper function to provide the base context for the login page
fn base_login_context() -> HashMap<&'static str, &'static str> {
    let mut context = HashMap::new();
    context.insert("crescent_verify_url", "http://127.0.0.1:8004/verify");
    context.insert("crescent_disclosure_uid", "crescent://email_domain");
    context
}

// route to serve the login page
#[get("/login")]
fn login_page() -> Template {
    println!("*** Serving login page");
    // Generate the verify URL dynamically using the `uri!` macro
    let verify_url = uri!(verify);

    // set the template meta values
    let context = base_login_context();
    
    // render the login page
    Template::render("login", context)
}

// route to serve the protected resource page after successful verification
#[get("/resource")]
fn resource_page() -> Template {
    println!("*** Serving resource page");
    
    // render the resource page
    Template::render("resource", context! {})
}

// route to verify a ZK proof given a ProofInfo, return a status  
#[post("/verify", format = "json", data = "<proof_info>")]
fn verify(proof_info: Json<ProofInfo>) -> Result<Custom<Redirect>, Template> {
    println!("*** /verify called");
    println!("Schema UID: {}", proof_info.schema_UID);
    println!("Issuer URL: {}", proof_info.issuer_URL);
    println!("Proof: {}", proof_info.proof);

    let is_valid = true;  // Mock condition for validity: TODO: validate proof!

    if is_valid {
        // redirect to the resource page (with status code 303 to ensure a GET request is made)
        println!("*** Proof is valid. Redirecting to resource page");
        Ok(Custom(Status::SeeOther, Redirect::to(uri!(resource_page))))
    } else {
        // return an error template if the proof is invalid
        println!("*** Proof is invalid. Returning error template");
        let mut context = base_login_context();
        context.insert("error", "Invalid proof provided. Access denied.");
        Err(Template::render("login", context))
    }
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![login_page, verify, resource_page])
    .attach(Template::fairing())

}