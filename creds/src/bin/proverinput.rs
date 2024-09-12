
use std::{env::current_dir, fs};
use ark_std::path::PathBuf;
use structopt::StructOpt;
use jwt_simple::prelude::*;
use jwt_simple::JWTError;

#[derive(Debug, StructOpt)]
struct Opts {
    
    /// The config.json file used in circuit setup
    #[structopt(parse(from_os_str), long)]
    config: PathBuf,

    /// The issuer's public key
    #[structopt(parse(from_os_str), long)]
    jwk: PathBuf,

    /// The prover's JWT token
    #[structopt(parse(from_os_str), long)]
    jwt: PathBuf,

    /// The output file (optional, defaults to stdout)
    #[structopt(parse(from_os_str), long)]
    outfile: Option<PathBuf>,    
}

fn main() {
    let opts = Opts::from_args();

    println!("got options: {:?}", opts);

    let issuer_pem = fs::read_to_string(opts.jwk).unwrap();
    let issuer_pub = RS256PublicKey::from_pem(&issuer_pem).unwrap();

    let token_str = fs::read_to_string(opts.jwt).unwrap();
    let claims_limited_set = issuer_pub.verify_token::<NoCustomClaims>(&token_str, None);
    if claims_limited_set.is_ok() {
        println!("Token verifies");
    }
    else {
        println!("Token failed to verify");
    }

    let mut parts = token_str.split('.');
    let jwt_header_b64 = parts.next().unwrap();
    let claims_b64 = parts.next().unwrap();
    let signature_b64 = parts.next().unwrap(); 
    

}
