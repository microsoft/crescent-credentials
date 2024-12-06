// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use ark_ff::PrimeField;
use jwt_simple::prelude::*;
use serde_json::Value;
use serde_json::json;
use lazy_static::lazy_static;
use std::collections::HashSet;
use num_bigint::BigInt;
use num_traits::FromPrimitive;
use std::ops::{Shl, BitAnd};
use std::error::Error;
use std::fs;
use ark_std::path::PathBuf;
use ark_ff::BigInteger;
use crate::return_error;

// If not set in config.json, the max_jwt_len is set to this value. 
const DEFAULT_MAX_TOKEN_LENGTH : usize = 2048;
const CIRCOM_RS256_LIMB_BITS : usize = 121;
const CIRCOM_ES256_LIMB_BITS : usize = 43;  // Limb size required by ecdsa-p256 circuit
lazy_static! {
    static ref CRESCENT_SUPPORTED_ALGS: HashSet<&'static str> = {
        let mut set = HashSet::new();
        set.insert("RS256");
        set.insert("ES256");
        set
    };
}
lazy_static! {
    static ref CRESCENT_CONFIG_KEYS: HashSet<&'static str> = {
        let mut set = HashSet::new();
        set.insert("alg");
        set.insert("credtype");
        set.insert("max_jwt_len");
        set
    };
}

pub fn pem_key_type(key : &String) -> Result<&str, &str> {

        if RS256PublicKey::from_pem(key).is_ok() {
            Ok("RS256")
        } 
        else if ES256PublicKey::from_pem(key).is_ok() {
            Ok("ES256")
        }
        else {
            Err("Unsupported algorithm")
        }
}

pub fn pem_to_inputs<F>(issuer_pem : &String) -> Result<Vec<F>, Box<dyn std::error::Error>>
    where F: PrimeField 
{
    
    let inputs = match pem_key_type(issuer_pem) {
        Ok("RS256") => {
            let issuer_pub = RS256PublicKey::from_pem(issuer_pem).unwrap();
            let limbs = to_circom_ints(&issuer_pub.to_components().n, CIRCOM_RS256_LIMB_BITS)?;
            limbs.into_iter().map(|x| F::from_le_bytes_mod_order(&x.to_bytes_le().1)).collect::<Vec<F>>()
        }
        Ok("ES256") =>  {
            let issuer_pub = ES256PublicKey::from_pem(issuer_pem).unwrap();
            let x = &issuer_pub.public_key().to_bytes_uncompressed()[1..33];    // byte 1 is 0x04, per SEC1 `Elliptic-Curve-Point-to-Octet-String` 
            let y = &issuer_pub.public_key().to_bytes_uncompressed()[33..65];
            let limbs_x = to_circom_ints(&x.to_vec(), CIRCOM_ES256_LIMB_BITS)?;
            let limbs_y = to_circom_ints(&y.to_vec(), CIRCOM_ES256_LIMB_BITS)?;
            let limbs_x_fe = limbs_x.into_iter().map(|a| F::from_le_bytes_mod_order(&a.to_bytes_le().1)).collect::<Vec<F>>();
            let limbs_y_fe = limbs_y.into_iter().map(|a| F::from_le_bytes_mod_order(&a.to_bytes_le().1)).collect::<Vec<F>>();
            let mut limbs = limbs_x_fe;
            limbs.extend(limbs_y_fe);
            limbs
        }
        Err(e) =>  {
            return Err(e.into());
        }
        _ => {
            return Err("unknown error".into())
        }
    };

    Ok(inputs)

}

pub fn prepare_prover_inputs(config : &serde_json::Map<String, Value>, token_str : &String, issuer_pem : &String ) -> 
Result<(serde_json::Map<String, Value>, 
    serde_json::Map<String, Value>, 
    serde_json::Map<String, Value>), Box<dyn Error>>
{

    let issuer_pub = match config["alg"].as_str().unwrap() {
        "RS256" => RS256PublicKey::from_pem(issuer_pem)?,
        _ => return_error!("Unsupported algorithm"),
    };    

    let claims_limited_set = issuer_pub.verify_token::<NoCustomClaims>(token_str, None);
    if claims_limited_set.is_err() {
        return_error!("Token failed to verify");
    }

    let mut parts = token_str.split('.');
    let jwt_header_b64 = parts.next().ok_or("Missing JWT header")?;
    let claims_b64 = parts.next().ok_or("Missing JWT claims")?;
    let signature_b64 = parts.next().ok_or("Missing JWT signature")?;

    let jwt_header_decoded = String::from_utf8(base64_url::decode(jwt_header_b64)?)?;
    let claims_decoded = String::from_utf8(base64_url::decode(claims_b64)?)?;
    
    let claims: Value =
        serde_json::from_slice(&Base64UrlSafeNoPadding::decode_to_vec(claims_b64, None)?)?;

    // Convert the base64 encoded header and payload to UTF-8 integers in base-10 (e.g., 'e' -> 101, 'y' -> 121, ...)        
    let mut header_utf8 = to_utf8_integers(jwt_header_b64);
    header_utf8.push('.' as u32);
    let payload_utf8 = to_utf8_integers(claims_b64);

    let mut prepad_m = header_utf8.clone();
    prepad_m.append(&mut payload_utf8.clone());

    let mut padded_m = sha256_padding(&prepad_m);

    let msg_len_after_sha2_padding = padded_m.len() as u64;

    if msg_len_after_sha2_padding > config["max_jwt_len"].as_u64().unwrap() {
        let errmsg = format!("Error: JWT too large.  Current token JSON header + payload is {} bytes ({} bytes after SHA256 padding), but maximum length supported is {} bytes.\nThe config file value `max_jwt_len` would have to be increased to {} bytes (currently config['max_jwt_len'] = {})", 
        header_utf8.len() + payload_utf8.len(), 
        msg_len_after_sha2_padding, 
        base64_decoded_size(config["max_jwt_len"].as_u64().unwrap()), 
        header_utf8.len() + payload_utf8.len() + 64, config["max_jwt_len"].as_u64().unwrap()
        );

        return_error!(errmsg);
    }

    // Add additional zero padding for Circom
    while padded_m.len() < config["max_jwt_len"].as_u64().unwrap() as usize {
        padded_m.push(0);
    }
  
    // Begin creating prover's output. Everthing must have string type for Circom
    let mut prover_inputs_json = serde_json::Map::new();
    let mut public_ios_json = serde_json::Map::new();
    let prover_aux_json = serde_json::Map::new();
    prover_inputs_json.insert("message".to_string(), json!(padded_m.into_iter().map(|c| c.to_string()).collect::<Vec<_>>()));

    // Signature
    let alg_str = config["alg"].as_str().unwrap();
    if alg_str == "RS256" {
        let limbs = b64_to_circom_limbs(signature_b64, CIRCOM_RS256_LIMB_BITS)?;
        prover_inputs_json.insert("signature".to_string(), json!(limbs));
    }
    else {
        return_error!(format!("Unsupported algorithm {}", alg_str));
    }

    // Issuer's public key
    if alg_str == "RS256" {
        let modulus_bytes = issuer_pub.to_components().n;
        let limbs = to_circom_limbs(&modulus_bytes, CIRCOM_RS256_LIMB_BITS)?;
        prover_inputs_json.insert("modulus".to_string(), json!(limbs));
        public_ios_json.insert("modulus".to_string(), json!(limbs));
    }
    else {
        return_error!(format!("Unsupported algorithm {}", alg_str));
    }

    // Other values the prover needs
    prover_inputs_json.insert("message_padded_bytes".to_string(), json!(msg_len_after_sha2_padding.to_string()));
    let period_idx = header_utf8.len() - 1;
    prover_inputs_json.insert("period_idx".to_string(), json!(period_idx.to_string()));


    let header_pad = base_64_decoded_header_padding(period_idx)?;
    let header_and_payload = format!("{}{}{}", jwt_header_decoded, header_pad, claims_decoded);
    prepare_prover_claim_inputs(header_and_payload, config, &claims, &mut prover_inputs_json)?;

    Ok((prover_inputs_json, prover_aux_json, public_ios_json))

}

// For each of the claims that are specified in the config file, the prover will need some info about each one
// (e.g., the value, where in the payload it starts and ends)
fn prepare_prover_claim_inputs(header_and_payload: String, config: &serde_json::Map<String, Value>, claims: &Value, prover_inputs_json : &mut  serde_json::Map<String, Value>) -> Result<(), Box<dyn Error>> {
    let msg = header_and_payload;

    if !is_minified(&msg) {
        return_error!("JSON is not minified, Circom circuit will fail.")
    }
    let keys = config.keys();

    for key in keys {
        if CRESCENT_CONFIG_KEYS.contains(key.as_str()) {
            continue;
        }

        let name = key.clone();
        let name = name.as_str();

        let entry = config[name].as_object().ok_or(format!("Config file entry for claim {}, does not have object type", name))?;

        let type_string = entry["type"].as_str().ok_or(format!("Config file entry for claim {}, is missing 'type'", name))?;

        let claim_name = format!("\"{}\"", name);
        let (claim_l, claim_r) = find_value_interval(&msg, &claim_name, type_string)?;

        let name_l = format!("{}_l", name);
        let name_r = format!("{}_r", name);

        prover_inputs_json.insert(name_l, json!(claim_l.to_string()));
        prover_inputs_json.insert(name_r, json!(claim_r.to_string()));

        if entry.contains_key("reveal") {
            let reveal = entry["reveal"].as_bool().ok_or("reveal for predicate {} is not of type bool")?;
            if reveal {
                match type_string {
                    "number" => {
                        prover_inputs_json.insert(format!("{}_value", name), json!(claims[name].clone().to_string()));
                    }
                    "string" => {
                        let max_claim_byte_len = entry["max_claim_byte_len"].as_u64().unwrap();    // validated by load_config
                        let packed = if entry.contains_key("reveal_domain_only") && 
                                        entry["reveal_domain_only"].as_bool().ok_or("reveal_domain_only is not of type bool")? {
                            let domain = get_domain(claims[name].as_str().ok_or("invalid_type")?)?;
                            pack_string_to_int_unquoted(domain, max_claim_byte_len.try_into()?)?
                        }
                        
                        else {
                            pack_string_to_int(claims[name].as_str().ok_or("invalid_type")?, max_claim_byte_len.try_into()?)?
                        };
                        prover_inputs_json.insert(format!("{}_value", name), json!(packed));
                    }
                    _ => {
                        return_error!("Can only reveal number types and string types as a single field element for now. See also `reveal_bytes`.")
                    }
                }
            }
        }
    }


    Ok(())
}

fn get_domain(s: &str) -> Result<&str, Box<std::io::Error>> {
    match s.find('@') {
        Some(at_index) => Ok(&s[at_index + 1..]),
        None => return_error!("No @ symbol found in input to get_domain()"),
    }    
}

fn pack_string_to_int(s: &str, n_bytes: usize) -> Result<String, Box<std::io::Error>> {
    // Must match function "RevealClaimValue" in match_claim.circom, so we add quotes to the string

    //First convert "s" to bytes and pad with zeros
    let s_quoted = format!("\"{}\"",s);
    pack_string_to_int_unquoted(&s_quoted, n_bytes)
}
fn pack_string_to_int_unquoted(s: &str, n_bytes: usize) -> Result<String, Box<std::io::Error>> {
    // Must match function "RevealDomainOnly" in match_claim.circom

    //First convert "s" to bytes and pad with zeros
    let s_bytes = s.bytes();
    if s_bytes.len() > n_bytes {
        return_error!(format!("String to large to convert to integer of n_bytes = {}", n_bytes));
    }
    let mut s_bytes = s_bytes.collect::<Vec<u8>>();
    for _ in 0 .. n_bytes - s_bytes.len() {
        s_bytes.push(0x00);
    }
    // Convert to an integer with base-256 digits equal to s_bytes
    let mut n = BigInt::from_u32(0).unwrap();
    let twofiftysix = BigInt::from_u32(256).unwrap();
    for i in 0..s_bytes.len() {
        assert!(i < u32::MAX as usize);
        n += s_bytes[i] * twofiftysix.pow(i as u32);
    }
    
    Ok(n.to_str_radix(10))
}

pub fn unpack_int_to_string_unquoted(s_int: &ark_ff::BigInteger256) -> Result<String, Box<std::io::Error>> {

    let s_bytes = s_int.to_bytes_le();
    let string = String::from_utf8(s_bytes);
    if string.is_err() {
        return_error!("Failed to convert to string");
    }
    Ok(string.unwrap())
}

fn find_value_interval(msg: &str, claim_name: &str, type_string: &str) -> Result<(usize, usize), Box<dyn Error>> {
    let l = msg.find(claim_name).ok_or(format!("Failed to find claim {} in token payload", claim_name))?;
    let value_start = l + claim_name.len();
    let mut r = 0;
    match type_string {
        "string" => {
            let close_quote = msg[value_start+2..].find("\"").ok_or(format!("Parse error, no closing quote, claim {}", claim_name))?;
            r = close_quote + value_start + 3;
        },
        "number" => {
            for (i, c) in msg[value_start + 1..].chars().enumerate() {
                if "0123456789".find(c).is_none() {
                    r = value_start + 1 + i;
                    break;
                }
            }
        },
        "bool" => {
            for (i, c) in msg[value_start + 1..].chars().enumerate() {
                if "truefalse".find(c).is_none() {
                    r = value_start + 1 + i;
                    break;
                }
            }            
        },
        "null" => {
            r = value_start + 4;
        }, 
        "array" => {
            let mut nested_level = 0;
            for (i, c) in msg[value_start..].chars().enumerate() {
                if c == '[' {
                    nested_level += 1;
                }
                else if c == ']' {
                    nested_level -= 1;
                    if nested_level == 0 {
                        r = value_start + i + 1;
                        break;
                    }
                }
            }
        },
        "object" => {
            let mut nested_level = 0;
            for (i, c) in msg[value_start..].chars().enumerate() {
                if c == '{' {
                    nested_level += 1;
                }
                else if c == '}' {
                    nested_level -= 1;
                    if nested_level == 0 {
                        r = value_start + i + 1;
                        break;
                    }
                }
            }
        },
        _ => return_error!(format!("Unsupported claim type: {}", type_string)),
    }
    Ok((l,r))
}

fn is_minified(msg: &str) -> bool {
    // Check for extra spaces, e.g.,
    //     "exp" : 123456789
    // is not sufficiently minified, but
    //     "exp":123456789
    // is minified. Our Circom circuit currently does not support extra space(s).
    if msg.contains("\": ") {
        return false;
    }
    true
}
    
// This function creates zero-padding to go between the JSON header and payload
// in order to match what the Circom base64 decoder outputs.
// If the header must include padding "=" or "==" to be a multiple of four for base64
// decoding, then the decoding circuit outputs 0's for these padding characters.
// (Software decoders don't have this output, but it's quite awkward to do in a circuit)
fn base_64_decoded_header_padding(header_len: usize) -> Result<String, Box<dyn std::error::Error>> {

    if header_len % 4 == 0 {
        Ok("".to_string())
    }
    else if header_len % 4 == 1 {
        return_error!("Invalid period_idx, the base64 encoding of the header is invalid");
    }
    else if header_len % 4 == 2 {
        Ok("\0\0".to_string())
    }
    else if header_len % 4 == 3 {
        Ok("\0".to_string())
    }
    else {
        panic!();
    }

}

// Convert integer n to limbs, encoded as strings
fn to_circom_limbs(n_bytes: &[u8], limb_size: usize)-> Result<Vec<String>, Box<dyn std::error::Error>> {
    let limbs = to_circom_ints(n_bytes, limb_size)?;
    Ok(limbs.into_iter().map(|l| l.to_str_radix(10)).collect())
}

// Convert integer n to limbs
fn to_circom_ints(n_bytes: &[u8], limb_size: usize)-> Result<Vec<BigInt>, Box<dyn std::error::Error>> {
    let n = BigInt::from_bytes_be(num_bigint::Sign::Plus, n_bytes);    
    let num_limbs = (n.bits() as usize + limb_size - 1) / limb_size;

    // Extract the limbs
    let one = BigInt::from_u32(1).unwrap();
    let mut limbs = Vec::with_capacity(num_limbs);
    let msk = one.clone().shl(limb_size) - &one;

    for i in 0..num_limbs {
        let limb = (&n >> (i * limb_size)).bitand(&msk);
        limbs.push(limb);
    }

    Ok(limbs)
}

fn b64_to_circom_limbs(n_b64: &str, limb_size: usize) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let n_bytes = base64_url::decode(n_b64)?;
    to_circom_limbs(&n_bytes, limb_size)
}

fn sha256_padding(prepad_m: &[u32]) -> Vec<u32> {
    // Calculate the message length in bits
    let msg_length_bits = (prepad_m.len() * 8) as u64;

    // Create a mutable vector to hold the padded message
    let mut padded_m = prepad_m.to_vec();

    // Append the padding byte 0x80
    padded_m.push(0x80);

    // Append zero bytes until the length of the padded message is congruent to 448 modulo 512
    while (padded_m.len()) % 64 != 56 {
        padded_m.push(0);
    }

    // Append the original message length as a 64-bit big-endian integer
    padded_m.extend_from_slice(&msg_length_bits.to_be_bytes().map(|b| b as u32));

    padded_m
}

fn base64_decoded_size(encoded_len : u64) -> u64 {
    ((encoded_len+3)/4)*3
}

fn to_utf8_integers(input_bytes: &str) -> Vec<u32> {
    input_bytes.chars().map(|c| c as u32).collect()
}

pub fn load_config(path: PathBuf) -> Result<serde_json::Map<String, Value>, Box<dyn Error>> {
    let config_str = fs::read_to_string(path)?;
    parse_config(config_str)
}

pub fn parse_config(config_str: String) -> Result<serde_json::Map<String, Value>, Box<dyn Error>> {
    let mut config_v: Value = serde_json::from_str(&config_str)?;
    let config: &mut serde_json::Map<String, Value> = config_v.as_object_mut().ok_or("Invalid config")?;

    // Validate config
    if !config.contains_key("alg") {
        return_error!("'alg' field is missing from config file");
    }

    let alg_copy = config.get("alg").unwrap().clone();
    let alg = alg_copy.as_str().ok_or("alg field is not a string")?;    
    if !CRESCENT_SUPPORTED_ALGS.contains(alg) {
        return_error!(format!("{} algorithm is unsupported", config["alg"]));
    }

    // Set defaults
    if !config.contains_key("max_jwt_len") {
        config.insert("max_jwt_len".to_string(), json!(DEFAULT_MAX_TOKEN_LENGTH));
    }
    else {
        if !config["max_jwt_len"].is_u64() {
            return_error!("max_jwt_len must have integer type");
        }
        let max_jwt_len = config["max_jwt_len"].as_u64().ok_or("Invalid value for max_jwt_len")?;
        if max_jwt_len % 64 != 0 {
            let round = (64 - (max_jwt_len % 64)) + max_jwt_len;
            config["max_jwt_len"] = json!(round);
            println!("Warning: max_jwt_len not a multiple of 64. Rounded from {} to {}", max_jwt_len, round);
        }
    }

    // For all the config entries about claims (e.g, "email", "exp", etc.) make sure that if the claim 
    // is to be revealed, that max_claim_byte_len is set
    for (key, _) in config.clone() {
        if !CRESCENT_CONFIG_KEYS.contains(key.as_str()) {
            let claim_entry = config.get(key.as_str()).unwrap().as_object().ok_or("expected object type")?.clone();
            if claim_entry.contains_key("reveal") && claim_entry["reveal"].as_bool().unwrap_or(false) && !claim_entry.contains_key("max_claim_byte_len") {
                return_error!(format!("Config entry for claim {} has reveal flag set but is missing 'max_claim_byte_len'", key));
            }
        }
    }

    Ok(config.clone())

}