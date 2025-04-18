// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// NOTE: this sample is for demonstration purposes only and is not intended for production use.
//       The weak authentication mechanism is used to illustrate a simple JWT issuance flow. In
//       a real system, Crescent provers could interact with standard Identity Providers to obtain
//       JWTs.

#[macro_use] extern crate rocket;

use rocket::fs::{FileServer, NamedFile};
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
use p256::ecdsa::VerifyingKey;
use p256::pkcs8::DecodePublicKey;

// issuer config values
const PRIVATE_KEY_PATH : &str = "keys/issuer.prv"; // private key path
const DEVICE_PUB_KEY_PATH: &str = "keys/device.pub"; // device public key path
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
    tenant_ctry: String,
    tenant_region_scope: String,
    verified_primary_email: Vec<String>,
    verified_secondary_email: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_key_0: Option<u128>, // optional device-binding key, part 0
    #[serde(skip_serializing_if = "Option::is_none")]
    device_key_1: Option<u128>, // optional device-binding key, part 1
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

// issuer config from Rocket.toml
struct IssuerConfig {
    issuer_name: String,
    issuer_domain: String,
    issuer_kid: String,
    _device_key_binding: bool,
}

// redirect from `/` to `/login`
#[get("/")]
fn index_redirect() -> Redirect {
    Redirect::to("/login")
}

// route to serve the login page
#[get("/login")]
fn login_page(issuer_config: &State<IssuerConfig>) -> Template {
    let issuer_name_str = issuer_config.issuer_name.as_str();
    Template::render("login", context! { issuer_name: issuer_name_str })
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
fn welcome_page(jar: &CookieJar<'_>, issuer_config: &State<IssuerConfig>) -> Result<Template, Redirect> {
    let issuer_name_str = issuer_config.issuer_name.as_str();
    if let Some(cookie) = jar.get("username") {
        let username = cookie.value().to_string();
        Ok(Template::render(
            "welcome",
            context! {
                user_name: &username,
                issuer_name: issuer_name_str
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
    issuer_config: &State<IssuerConfig>
) -> Result<RawHtml<String>, &'static str> {
    if let Some(cookie) = jar.get("username") {
        let username = cookie.value().to_string();
        let issuer_name_str = issuer_config.issuer_name.as_str();
        let issuer_domain_str = issuer_config.issuer_domain.as_str();
        let issuer_kid_str = issuer_config.issuer_kid.as_str();

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
                iss: format!("https://{}", issuer_domain_str),
                jti: "fGYCO1mK2dBWTAfCjGAoTQ".to_string(),
                nbf: current_time.timestamp() as usize,
                tid: "12345678-1234-abcd-1234-abcdef124567".to_string(),
                ver: "2.0".to_string(),
                xms_pdl: "NAM".to_string(),
                xms_tpl: "en".to_string(),
            };

            let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
            header.kid = Some(issuer_kid_str.to_string());

            let token = encode(&header, &claims, &private_key.key)
                .map_err(|_| "Failed to generate token")?;

            // return the JWT embedded in an HTML page
            let response_html = format!(
                r#"
                <html>
                <head>
                    <link rel="stylesheet" href="css/style.css">
                    <meta name="CRESCENT_JWT" content="{}">
                </head>
                <body>
                    <header class="header">
                        <h1>{}</h1>
                    </header>
                    <div class="welcome-container">
                        <h1>Here is your JWT, {}</h1>
                        <textarea id="jwt" rows="10" cols="100">{}</textarea>
                        <p>Copy and use this JWT, or let your browser extension access it.</p>
                    </div>
                </body>
                </html>
                "#,
                token,
                issuer_name_str,
                username,
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

fn parse_device_public_key(device_pub_key: &VerifyingKey) -> (u128, u128) {
    let encoded_point = device_pub_key.to_encoded_point(false); // uncompressed
    let x_bytes = encoded_point.x().expect("Missing x-coordinate");
    assert_eq!(x_bytes.len(), 32); // ensure it's 256-bit

    let pk_x_int = x_bytes;
    let device_key_0 = u128::from_be_bytes(pk_x_int[16..32].try_into().unwrap());
    let device_key_1 = u128::from_be_bytes(pk_x_int[0..16].try_into().unwrap());

    (device_key_0, device_key_1)
}

// create a list of users with their personal claims
fn create_demo_users(issuer_config: &IssuerConfig, device_pub_key: Option<VerifyingKey>) -> Vec<User> {
    let user_domain = issuer_config.issuer_domain.as_str();

    let mut device_key_0 = None;
    let mut device_key_1 = None;
    if let Some(device_pub_key) = device_pub_key {
        let (key0, key1) = parse_device_public_key(&device_pub_key);
        device_key_0 = Some(key0);
        device_key_1 = Some(key1);
    }
    println!("Device key 0: {:?}", device_key_0);
    println!("Device key 1: {:?}", device_key_1);

    vec![
        User {
            username: "alice".to_string(),
            password: "password".to_string(),
            user_claims: UserClaims {
                email: format!("alice@{}", user_domain),
                family_name: "Example".to_string(),
                given_name: "Alice".to_string(),
                login_hint: "O.aaaaabbbbbbbbbcccccccdddddddeeeeeeeffffffgggggggghhhhhhiiiiiiijjjjjjjkkkkkkklllllllmmmmmmnnnnnnnnnnooooooopppppppqqqqrrrrrrsssssdddd".to_string(),
                name: "Alice Example".to_string(),
                oid: "12345678-1234-abcd-1234-abcdef124567".to_string(),
                onprem_sid: "S-1-2-34-5678901234-1234567890-1234567890-1234567".to_string(),
                preferred_username: format!("alice@{}", user_domain),
                rh: "0.aaaaabbbbbccccddddeeeffff12345gggg12345_124_aaaaaaa.".to_string(),
                sid: "12345678-1234-abcd-1234-abcdef124567".to_string(),
                sub: "aaabbbbccccddddeeeeffffgggghhhh123456789012".to_string(),
                upn: format!("alice@{}", user_domain),
                uti: "AAABBBBccccdddd1234567".to_string(),
                tenant_ctry: "US".to_string(), // United States
                tenant_region_scope: "NA".to_string(), // North America
                verified_primary_email: vec![format!("alice@{}", user_domain)],
                verified_secondary_email: vec![format!("alice2@{}", user_domain)],
                device_key_0: device_key_0,
                device_key_1: device_key_1,
            },
        },
        User {
            username: "bob".to_string(),
            password: "password".to_string(),
            user_claims: UserClaims {
                email: format!("bob@{}", user_domain),
                family_name: "Example".to_string(),
                given_name: "Bob".to_string(),
                login_hint: "O.aaaaabbbbbbbbbcccccccdddddddeeeeeeeffffffgggggggghhhhhhiiiiiiijjjjjjjkkkkkkklllllllmmmmmmnnnnnnnnnnooooooopppppppqqqqrrrrrrsssssdddd".to_string(),
                name: "Bob Example".to_string(),
                oid: "12345678-1234-abcd-1234-abcdef124567".to_string(),
                onprem_sid: "S-1-2-34-5678901234-1234567890-1234567890-1234567".to_string(),
                preferred_username: format!("bob@{}", user_domain),
                rh: "0.aaaaabbbbbccccddddeeeffff12345gggg12345_124_aaaaaaa.".to_string(),
                sid: "12345678-1234-abcd-1234-abcdef124567".to_string(),
                sub: "aaabbbbccccddddeeeeffffgggghhhh123456789012".to_string(),
                upn: format!("bob@{}", user_domain),
                uti: "AAABBBBccccdddd1234567".to_string(),
                tenant_ctry: "CA".to_string(), // Canada
                tenant_region_scope: "NA".to_string(), // North America
                verified_primary_email: vec![format!("bob@{}", user_domain)],
                verified_secondary_email: vec![format!("bob2@{}", user_domain)],
                device_key_0: device_key_0,
                device_key_1: device_key_1,
            },
        },
    ]
}

#[get("/favicon.ico")]
async fn favicon() -> Option<NamedFile> {
    NamedFile::open("static/img/favicon.ico").await.ok()
}

#[launch]
fn rocket() -> _ {
    // load the issuer private key at server startup
    let private_key_data = fs::read(PRIVATE_KEY_PATH)
        .expect("Failed to read private key");
    let encoding_key = EncodingKey::from_rsa_pem(&private_key_data)
        .expect("Failed to create encoding key");

    // read the kid from the JWK set in JWKS_PATH
    let jwks_data = fs::read(JWKS_PATH)
        .expect("Failed to read JWKS file");
    let jwks: serde_json::Value = serde_json::from_slice(&jwks_data)
        .expect("Failed to parse JWKS file");
    let issuer_kid = jwks["keys"][0]["kid"].as_str().expect("issuer_kid should exist").to_string();
    println!("Loaded JWKS with kid: {:?}", issuer_kid);

    // create the private key struct
    let private_key = PrivateKey {
        key: encoding_key,
    };

     // Load issuer configuration
     let figment = rocket::Config::figment();
     let issuer_name: String = figment.extract_inner("issuer_name").unwrap_or_else(|_| "Example Issuer".to_string());
     let issuer_domain: String = figment.extract_inner("issuer_domain").unwrap_or_else(|_| "example.com".to_string());
     let device_key_binding: bool = figment.extract_inner("device_key_binding").unwrap_or(false);
     
     let issuer_config = IssuerConfig {
         issuer_name,
         issuer_domain,
         issuer_kid,
         _device_key_binding: device_key_binding,
     };
 
     let mut device_pub_key = None;
     if device_key_binding {
        // read the device public key
        // note: currently, all users share the same device public key, as prepared by the 
        // Crescent provisioning tool. In a real system, each user would have their own key pair
        let device_pub_key_pem = fs::read_to_string(DEVICE_PUB_KEY_PATH)
            .expect("Failed to read device public key");
        device_pub_key = Some(
            VerifyingKey::from_public_key_pem(&device_pub_key_pem)
                .expect("Failed to parse PEM device public key"),
        );
        println!("Loaded device public key: {:?}", device_pub_key);
     }

     // Create demo users based on the issuer config
     let users = create_demo_users(&issuer_config, device_pub_key);

    // launch the Rocket server and manage the private key and user state
    rocket::build()
        .manage(issuer_config)
        .manage(users)
        .manage(private_key)
        .attach(Template::fairing())
        .mount("/", FileServer::from("static"))
        .mount(
            "/",
            routes![
                index_redirect,
                login_page,
                login,
                welcome_page,
                issue_token,
                serve_jwks,
                favicon
            ],
        )
}
