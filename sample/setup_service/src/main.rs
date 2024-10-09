// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#[macro_use] extern crate rocket;

use rocket::serde::{Serialize, Deserialize};
use rocket::serde::json::Json;

// struct for the JWT info
#[derive(Serialize, Deserialize, Clone)]
struct TokenInfo {
    JWT: String,
    issuer: String
}

// route to prepare JWT for ZK proof given a TokenInfo, return a token UID  
#[post("/prepare", format = "json", data = "<token_info>")]
fn prepare(token_info: Json<TokenInfo>) -> Json<String> {
    let token_uid = "token_uid".to_string();
    Json(token_uid)
}

// route to verify if a token UID is ready for presentation
#[get("/state/<token_uid>")]
fn state(token_uid: String) -> Json<String> {
    let state = "ready".to_string();
    Json(state)
}

// route to present a token UID and get a ZK proof
// TODO: should that be a post? with what params?
#[get("/present/<token_uid>")]
fn present(token_uid: String) -> Json<String> {
    let zk_proof = "zk_proof".to_string();
    Json(zk_proof)
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![prepare, state, present])
}
