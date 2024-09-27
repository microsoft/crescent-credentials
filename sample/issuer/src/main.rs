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

// issuer config values
const PRIVATE_KEY_PATH : &str = "keys/issuer.prv"; // private key path
const JWKS_PATH: &str = ".well-known/jwks.json"; // JWKS path

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
    email: String,
    family_name: String,
    given_name: String,
    login_hint: String,
    name: String,
    oid: String,
    onprem_sid: String,
    preferred_username: String,
    rh: String,
    sid: String,
    sub: String,
    upn: String,
    uti: String,
    verified_primary_email: Vec<String>,
    verified_secondary_email: Vec<String>,
}

// struct for the full JWT claims, which includes both user-specific and dynamic fields
// note: this emulates the schema of the Microsoft Entra JWT
#[derive(Serialize, Clone)]
struct Claims {
    // user-specific claims
    user_claims: UserClaims,
    // token-specific claims
    acct: usize,
    aud: String,
    auth_time: usize,
    exp: usize,
    iat: usize,
    ipaddr: String,
    iss: String,
    jti: String,
    nbf: usize,
    tenant_ctry: String,
    tenant_region_scope: String,
    tid: String,
    ver: String,
    xms_pdl: String,
    xms_tpl: String
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
        // set the dynamic claims and construct the full Claims struct
        let current_time = Utc::now(); 
        let claims = Claims {
            user_claims: user.user_claims.clone(),
            acct: 0, // TODO: what is that?
            aud: "relyingparty.example.com".to_string(),
            auth_time: (current_time).timestamp() as usize, // authentication time = now
            exp: (current_time + Duration::hours(1)).timestamp() as usize, // expiration in 3 months (TODO)
            iat: (current_time).timestamp() as usize, // issued at time = now
            ipaddr: "203.0.113.0".to_string(), // user IP address
            iss: "https://localhost:8000".to_string(), // TODO: get ip from config
            jti: "fGYCO1mK2dBWTAfCjGAoTQ".to_string(), // token unique id (what's that value? TODO)
            nbf: (current_time).timestamp() as usize, // not before time = now
            tenant_ctry: "US".to_string(), // tenant country
            tenant_region_scope: "WW".to_string(), // tenant region (what's that? TODO)
            tid: "12345678-1234-abcd-1234-abcdef124567".to_string(), // tenant ID
            ver: "2.0".to_string(),
            xms_pdl: "NAM".to_string(),
            xms_tpl: "en".to_string()
        
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

    // read the kid from the JWK set in JWKS_PATH
    let jwks_data = fs::read(JWKS_PATH)
        .expect("Failed to read JWKS file");
    let jwks: serde_json::Value = serde_json::from_slice(&jwks_data)
        .expect("Failed to parse JWKS file");
    let kid = jwks["keys"][0]["kid"].as_str();
    println!("Loaded JWKS with kid: {:?}", kid);

    // create the private key struct
    let private_key = PrivateKey {
        key: encoding_key,
    };

    // create a list of users with their personal claims
    let users = vec![
        // Alice demo user
        User {
            username: "alice".to_string(),
            password: "password".to_string(),
            user_claims: UserClaims {
                email: "alice@example.com".to_string(),
                family_name: "Example".to_string(),
                given_name: "Alice".to_string(),
                login_hint: "O.aaaaabbbbbbbbbcccccccdddddddeeeeeeeffffffgggggggghhhhhhiiiiiiijjjjjjjkkkkkkklllllllmmmmmmnnnnnnnnnnooooooopppppppqqqqrrrrrrsssssdddd".to_string(),
                name: "Alice Example".to_string(),
                oid: "12345678-1234-abcd-1234-abcdef124567".to_string(),
                onprem_sid: "S-1-2-34-5678901234-1234567890-1234567890-1234567".to_string(),
                preferred_username: "alice@example.com".to_string(),
                rh: "0.aaaaabbbbbccccddddeeeffff12345gggg12345_124_aaaaaaa.".to_string(),
                sid: "12345678-1234-abcd-1234-abcdef124567".to_string(),
                sub: "aaabbbbccccddddeeeeffffgggghhhh123456789012".to_string(),
                upn: "alice@example.com".to_string(),
                uti: "AAABBBBccccdddd1234567".to_string(),
                verified_primary_email: vec!["alice@example.com".to_string()],
                verified_secondary_email: vec!["alice2@example.com".to_string()],
            },
        },
        // Bob demo user
        User {
            username: "user2".to_string(),
            password: "password2".to_string(),
            user_claims: UserClaims {
                email: "bob@example.com".to_string(),
                family_name: "Example".to_string(),
                given_name: "Bob".to_string(),
                login_hint: "O.aaaaabbbbbbbbbcccccccdddddddeeeeeeeffffffgggggggghhhhhhiiiiiiijjjjjjjkkkkkkklllllllmmmmmmnnnnnnnnnnooooooopppppppqqqqrrrrrrsssssdddd".to_string(),
                name: "Bob Example".to_string(),
                oid: "12345678-1234-abcd-1234-abcdef124567".to_string(),
                onprem_sid: "S-1-2-34-5678901234-1234567890-1234567890-1234567".to_string(),
                preferred_username: "bob@example.com".to_string(),
                rh: "0.aaaaabbbbbccccddddeeeffff12345gggg12345_124_aaaaaaa.".to_string(),
                sid: "12345678-1234-abcd-1234-abcdef124567".to_string(),
                sub: "aaabbbbccccddddeeeeffffgggghhhh123456789012".to_string(),
                upn: "bob@example.com".to_string(),
                uti: "AAABBBBccccdddd1234567".to_string(),
                verified_primary_email: vec!["bob@example.com".to_string()],
                verified_secondary_email: vec!["bob2@example.com".to_string()],          
            },
        },
    ];

    // launch the Rocket server and manage the private key and user state
    rocket::build()
        .mount("/", routes![issue, serve_jwks])
        .manage(private_key)
        .manage(users)
}
