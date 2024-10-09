// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#[macro_use] extern crate rocket;

use rocket::serde::{Serialize, Deserialize};
use rocket::serde::json::Json;
use rocket_dyn_templates::{context, Template};

// struct for the JWT info
#[derive(Serialize, Deserialize, Clone)]
struct ProofInfo {
    proof: String,
    issuer: String
}

// route to serve the login page
#[get("/login")]
fn login_page() -> Template {
    Template::render("login", context! {})
}

// route to verify a ZK proof given a ProofInfo, return a status  
#[post("/verify", format = "json", data = "<proof_info>")]
fn verify(proof_info: Json<ProofInfo>) -> Json<String> {
    let status = "valid".to_string();
    Json(status)

    // TODO: redirect to the resource page if the proof is valid
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![login_page, verify])
    .attach(Template::fairing())

}