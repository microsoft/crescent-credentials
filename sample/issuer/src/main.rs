// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#[macro_use] extern crate rocket;
use rocket::serde::{Deserialize, Serialize};
use rocket::serde::json::Json;
use rocket::fs::NamedFile;
use rocket::State;
use jsonwebtoken::{encode, EncodingKey, Header};
use std::path::PathBuf;
use std::fs;
use chrono::{Utc, Duration};

// paths to the private key and JWKS file
const PRIVATE_KEY_PATH : &str = "keys/issuer.prv";
const JWKS_PATH: &str = ".well-known/jwks.json";

// struct for the incoming login request
#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
struct LoginRequest {
    username: String,
    password: String,
}

// struct for the personal claims related to the user
#[derive(Serialize, Clone)]
struct UserClaims {
    sub: String,  // Subject (username)
    role: String, // Custom field, e.g., user role
}

// struct for the full JWT claims, which includes both user-specific and dynamic fields
#[derive(Serialize, Clone)]
struct Claims {
    user_claims: UserClaims,  // Nested user claims
    exp: usize,               // Expiration time (as a timestamp)
    iss: String,              // Issuer field
    aud: String,              // Audience field
}

// struct to hold a user's data
struct User {
    username: String,
    password: String,
    user_claims: UserClaims,
}

// struct to hold the loaded issuer private key
struct PrivateKey {
    key: EncodingKey,
}

#[post("/issue", format = "json", data = "<login>")]
fn issue(login: Json<LoginRequest>, private_key: &State<PrivateKey>, users: &State<Vec<User>>) -> Result<String, &'static str> {
    // find the user based on the username and password provided
    if let Some(user) = users.iter().find(|user| user.username == login.username && user.password == login.password) {
        // Set the dynamic claims and construct the full Claims struct
        let claims = Claims {
            user_claims: user.user_claims.clone(),
            exp: (Utc::now() + Duration::hours(1)).timestamp() as usize,  // Expiration in 1 hour
            iss: "my-issuer".to_string(),
            aud: "my-audience".to_string(),
        };

        // Create a header with RS256 algorithm
        let header = Header::new(jsonwebtoken::Algorithm::RS256);

        // Sign the JWT using the private key from Rocket's state
        let token = encode(
            &header,
            &claims,
            &private_key.key
        )
        .map_err(|_| "Failed to generate token")?;

        // Return the JWT token
        Ok(token)
    } else {
        Err("Invalid credentials\n")
    }
}

// Route to serve the JWKS file
#[get("/.well-known/jwks.json")]
async fn serve_jwks() -> Option<NamedFile> {
    // serve the JWKS file from the specified path
    NamedFile::open(PathBuf::from(JWKS_PATH)).await.ok()
}

#[launch]
fn rocket() -> _ {
    // load the private key at server startup
    let private_key_data = fs::read(PRIVATE_KEY_PATH)
        .expect("Failed to read private key");
    let encoding_key = EncodingKey::from_rsa_pem(&private_key_data)
        .expect("Failed to create encoding key");

    // create the private key struct
    let private_key = PrivateKey {
        key: encoding_key,
    };

    // create a list of users with their personal claims
    let users = vec![
        User {
            username: "user1".to_string(),
            password: "password1".to_string(),
            user_claims: UserClaims {
                sub: "user1".to_string(),
                role: "role1".to_string(),
            },
        },
        User {
            username: "user2".to_string(),
            password: "password2".to_string(),
            user_claims: UserClaims {
                sub: "user2".to_string(),
                role: "role2".to_string(),
            },
        },
    ];

    // launch the Rocket server and manage the private key and user state
    rocket::build()
        .mount("/", routes![issue, serve_jwks])
        .manage(private_key)
        .manage(users)
}
