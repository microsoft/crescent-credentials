// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use jwt_simple::prelude::*;
use structopt::StructOpt;
use serde_json::Value;
use serde_json::json;
use std::error::Error;
use std::fs::OpenOptions;
use std::fs;
use ark_std::{path::PathBuf, io::BufWriter};
use crescent::prep_inputs::load_config;
use crescent::return_error;
use crescent::prep_inputs::prepare_prover_inputs;

#[derive(Debug, StructOpt)]
struct Opts {
    /// The config.json file used in circuit setup
    #[structopt(parse(from_os_str), long)]
    config: PathBuf,

    /// The issuer's public key
    #[structopt(parse(from_os_str), long)]
    jwk: PathBuf,

    /// The device public key (optional, for device-bound credentials)
    #[structopt(parse(from_os_str), long)]
    device_key: Option<PathBuf>,

    /// The prover's JWT token
    #[structopt(parse(from_os_str), long)]
    jwt: PathBuf,

    /// The output path (writes prover_inputs.json, prover_aux.json and public_IOs.json here)
    #[structopt(parse(from_os_str), long)]
    outpath: PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    let opts = Opts::from_args();

    // Open config file
    print!("Loading and checking config file... ");
    let config = load_config(opts.config)?;
    println!("done");

    // Load issuer's public key
    let issuer_pem = fs::read_to_string(opts.jwk)?;
    let issuer_pub = RS256PublicKey::from_pem(&issuer_pem)?;

    let token_str = fs::read_to_string(opts.jwt)?;
    let claims_limited_set = issuer_pub.verify_token::<NoCustomClaims>(&token_str, None);
    if claims_limited_set.is_ok() {
        println!("Token verifies");
    } else {
        println!("Token failed to verify");
    }

    let mut parts = token_str.split('.');
    let jwt_header_b64 = parts.next().ok_or("Missing JWT header")?;
    let claims_b64 = parts.next().ok_or("Missing JWT claims")?;
    let _signature_b64 = parts.next().ok_or("Missing JWT signature")?;

    let _jwt_header_decoded = String::from_utf8(base64_url::decode(jwt_header_b64)?)?;
    let _claims_decoded = String::from_utf8(base64_url::decode(claims_b64)?)?;

    let claims: Value =
        serde_json::from_slice(&Base64UrlSafeNoPadding::decode_to_vec(claims_b64, None)?)?;

    println!("Claims:");
    if let Value::Object(map) = claims.clone() {
        for (k, v) in map {
            println!("{k} : {v}");
        }
    } else {
        panic!("Claims are not a JSON object");
    }

    // Load the device public key, if present
    let device_key_pem = if opts.device_key.is_some() {
        Some(fs::read_to_string(opts.device_key.unwrap())?)
    } else {
        None
    };

    let (mut prover_inputs_json, mut prover_aux_json, mut public_ios_json) = 
        prepare_prover_inputs(&config, &token_str, &issuer_pem, device_key_pem.as_deref())?;

    // Check if outpath is a directory and is writable
    if !opts.outpath.is_dir() {
        return_error!("Output path is not a directory");
    }
    if opts.outpath.metadata()?.permissions().readonly() {
        return_error!("Output path is not writeable")
    }

    // Write out prover inputs, public IOs and prover aux data. Always create a file, even if they're empty
    write_json_file(opts.outpath.join("prover_inputs.json"), &mut prover_inputs_json)?;
    write_json_file(opts.outpath.join("prover_aux.json"), &mut prover_aux_json)?;
    write_json_file(opts.outpath.join("public_IOs.json"), &mut public_ios_json)?;

    Ok(())
}

fn write_json_file(path: PathBuf, data: &mut serde_json::Map<String, Value>) -> Result<(), Box<dyn Error>> {
    if data.is_empty() {
        data.insert("_placeholder".to_string(), json!("empty file"));
    }    
    let f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    let buf_writer = BufWriter::new(f);    
    serde_json::to_writer_pretty(buf_writer, data)?;
    Ok(())
}



