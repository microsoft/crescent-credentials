// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// NOTE: this sample is for demonstration purposes only and is not intended for production use.
//       The weak authentication mechanism is used to illustrate a simple JWT issuance flow. In
//       a real system, Crescent provers could interact with standard Identity Providers to obtain
//       JWTs.

#[macro_use] extern crate rocket;

use rocket::fs::NamedFile;
use rocket::http::{Cookie, CookieJar};
use rocket::response::Redirect;
use rocket::serde::{Serialize};
use rocket::response::content::RawHtml;
use rocket::State;
use rocket_dyn_templates::{context, Template};
use std::path::PathBuf;
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use std::fs;

// issuer config values
const PRIVATE_KEY_PATH : &str = "keys/issuer.prv"; // private key path
const JWKS_PATH: &str = ".well-known/jwks.json"; // JWKS path

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
    #[serde(flatten)]
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

// add a new struct for the login form data
#[derive(FromForm)]
struct LoginForm {
    username: String,
    password: String,
}

// route to serve the login page
#[get("/login")]
fn login_page() -> Template {
    Template::render("login", context! {})
}

// route to handle login form submission
#[post("/login", data = "<form>")]
fn login(
    form: rocket::form::Form<LoginForm>,
    jar: &CookieJar<'_>,
    users: &State<Vec<User>>,
) -> Result<Redirect, Template> {
    let login = form.into_inner();

    // authenticate the user.
    if let Some(user) = users
        .iter()
        .find(|user| user.username == login.username && user.password == login.password)
    {
        // store the username in a cookie
        jar.add(Cookie::new("username", user.username.clone()));
        Ok(Redirect::to(uri!(welcome_page)))
    } else {
        // if authentication fails, reload the login page with an error message
        Err(Template::render(
            "login",
            context! {
                error: "Invalid username or password."
            },
        ))
    }
}

// route to serve the welcome page after successful login
#[get("/welcome")]
fn welcome_page(jar: &CookieJar<'_>) -> Result<Template, Redirect> {
    if let Some(cookie) = jar.get("username") {
        let username = cookie.value().to_string();
        Ok(Template::render(
            "welcome",
            context! {
                username: &username
            },
        ))
    } else {
        // if there's no username cookie, redirect to the login page
        Err(Redirect::to(uri!(login_page)))
    }
}

// route to issue JWTs
#[post("/issue")]
fn issue_token(
    jar: &CookieJar<'_>,
    private_key: &State<PrivateKey>,
    users: &State<Vec<User>>,
) -> Result<RawHtml<String>, &'static str> {
    if let Some(cookie) = jar.get("username") {
        let username = cookie.value().to_string();

        // find the user based on the username
        if let Some(user) = users.iter().find(|user| user.username == username) {
            // generate the JWT token
            let current_time = Utc::now();
            let claims = Claims {
                user_claims: user.user_claims.clone(),
                acct: 0,
                aud: "relyingparty.example.com".to_string(),
                auth_time: current_time.timestamp() as usize,
                exp: (current_time + Duration::days(30)).timestamp() as usize,
                iat: current_time.timestamp() as usize,
                ipaddr: "203.0.113.0".to_string(),
                iss: "https://localhost:8000".to_string(),
                jti: "fGYCO1mK2dBWTAfCjGAoTQ".to_string(),
                nbf: current_time.timestamp() as usize,
                tenant_ctry: "US".to_string(),
                tenant_region_scope: "WW".to_string(),
                tid: "12345678-1234-abcd-1234-abcdef124567".to_string(),
                ver: "2.0".to_string(),
                xms_pdl: "NAM".to_string(),
                xms_tpl: "en".to_string(),
            };

            let header = Header::new(jsonwebtoken::Algorithm::RS256);

            let token = encode(&header, &claims, &private_key.key)
                .map_err(|_| "Failed to generate token")?;

            // return the JWT embedded in an HTML page
            let response_html = format!(
                r#"
                <html>
                <body>
                    <h1>Here is your JWT</h1>
                    <textarea id="jwt" rows="10" cols="100">{}</textarea>
                    <p>Copy and use this JWT, or let your browser extension access it.</p>
                </body>
                </html>
                "#,
                token
            );

            Ok(RawHtml(response_html))
        } else {
            Err("User not found.")
        }
    } else {
        Err("User not authenticated.")
    }
}

// route to serve the JWKS file
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
        .mount(
            "/",
            routes![
                login_page,
                login,
                welcome_page,
                issue_token,
                serve_jwks
            ],
        )
        .attach(Template::fairing())
        .manage(private_key)
        .manage(users)
}
