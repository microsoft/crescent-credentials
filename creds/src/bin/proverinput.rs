use ark_ec::pairing::prepare_g2;
use ark_std::path::PathBuf;
use std::fs;
//use jwt_simple::reexports::anyhow::Ok;
use jwt_simple::prelude::*;
use structopt::StructOpt;
//use jwt_simple::JWTError;
use serde_json::Value;
use serde_json::json;
use std::error::Error;
use std::io::ErrorKind;
use lazy_static::lazy_static;
use std::collections::HashSet;
use num_bigint::BigInt;
use num_traits::FromPrimitive;
use std::ops::{Shl, BitAnd};
use base64_url::decode;

lazy_static! {
    static ref CRESCENT_SUPPORTED_ALGS: HashSet<&'static str> = {
        let mut set = HashSet::new();
        set.insert("HS256");
        set.insert("RS256");
        set.insert("ES256");
        set
    };
}
lazy_static! {
    static ref CRESCENT_CONFIG_KEYS: HashSet<&'static str> = {
        let mut set = HashSet::new();
        set.insert("alg");
        set.insert("reveal_all_claims");
        set.insert("defer_sig_ver");
        set.insert("max_jwt_len");
        set
    };
}

const DEFAULT_MAX_TOKEN_LENGTH : usize = 2048;
const CIRCOM_RS256_LIMB_BITS : usize = 121;

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

fn main() -> Result<(), Box<dyn Error>> {
    let opts = Opts::from_args();

    //     println!("got options: {:?}", opts);

    // Open config file
    print!("Loading an checking config file... ");
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
    let signature_b64 = parts.next().ok_or("Missing JWT signature")?;

    let jwt_header_decoded = String::from_utf8(base64_url::decode(jwt_header_b64)?)?;
    let claims_decoded = String::from_utf8(base64_url::decode(claims_b64)?)?;

    // DEBUG 
    let claims: Value =
        serde_json::from_slice(&Base64UrlSafeNoPadding::decode_to_vec(claims_b64, None)?)?;


    println!("Claims:");
    if let Value::Object(map) = claims.clone() {
        for (k, v) in map {
            println!("{} : {}", k, v);
        }
    } else {
        panic!("Claims are not a JSON object");
    }

    // END DEBUG

    //let mut header_bytes = base64_url::decode(jwt_header_b64)?;

    // Convert the base64 encoded header and payload to UTF-8 integers in base-10 (e.g., 'e' -> 101, 'y' -> 121, ...)        
    let mut header_utf8 = to_utf8_integers(jwt_header_b64);
    header_utf8.push('.' as u32);
    let payload_utf8 = to_utf8_integers(claims_b64);

    let mut prepad_m = header_utf8.clone();
    prepad_m.append(&mut payload_utf8.clone());

    let mut padded_m = sha256_padding(&prepad_m);

    let msg_len_after_SHA2_padding = padded_m.len() as u64;

    if msg_len_after_SHA2_padding > config["max_jwt_len"].as_u64().unwrap() {
        let errmsg = format!("Error: JWT too large.  Current token JSON header + payload is {} bytes ({} bytes after SHA256 padding), but maximum length supported is {} bytes.\nThe config file value `max_jwt_len` would have to be increased to {} bytes (currently config['max_jwt_len'] = {})", 
        header_utf8.len() + payload_utf8.len(), 
        msg_len_after_SHA2_padding, 
        base64_decoded_size(config["max_jwt_len"].as_u64().unwrap()), 
        header_utf8.len() + payload_utf8.len() + 64, config["max_jwt_len"].as_u64().unwrap()
        );

        return_error!(errmsg);
    }

    // Add additional zero padding for Circom
    while padded_m.len() < config["max_jwt_len"].as_u64().unwrap() as usize {
        padded_m.push(0);
    }

    // TODO: add code to support 'defer_sig_ver' option
    // Original python for outputting the digest:
    // sha256hash = hashlib.sha256(bytes(prepad_m))
    // digest_hex_str = sha256hash.hexdigest()
    // digest_bits = hex_string_to_binary_array(digest_hex_str, 256)
    // digest_b64 = base64url_encode(sha256hash.digest())
    // digest_limbs = digest_to_limbs(digest_hex_str)
    // if config['defer_sig_ver']:
    //     prover_aux_data["digest"] = digest_hex_str.upper().strip();
    //     print_debug("digest: ", digest_hex_str.upper().strip())    
    if config["defer_sig_ver"].as_bool().unwrap() {
        todo!("Not yet implemented");
    }

    // Begin creating prover's output. Everthing must have string type for Circom
    let mut prover_inputs_json = serde_json::Map::new();
    let mut public_ios_json = serde_json::Map::new();
    let mut prover_aux_data = serde_json::Map::new();
    prover_inputs_json.insert("message".to_string(), json!(padded_m.into_iter().map(|c| c.to_string()).collect::<Vec<_>>()));

    // Signature
    if config["alg"].as_str().unwrap() == "RS256" {
        let limbs = b64_to_circom_limbs(signature_b64, CIRCOM_RS256_LIMB_BITS)?;
        prover_inputs_json.insert("signature".to_string(), json!(limbs));
    }
    else if config["alg"].as_str().unwrap() == "ES256K" {
        todo!("Not yet implemented");
    }
    else {
        return_error!("Unsupported algorithm {}");
    }

    // Issuer's public key
    if config["alg"].as_str().unwrap() == "RS256" {
        let modulus_bytes = issuer_pub.to_components().n;
        let limbs = to_circom_limbs(&modulus_bytes, CIRCOM_RS256_LIMB_BITS)?;
        prover_inputs_json.insert("modulus".to_string(), json!(limbs));
        public_ios_json.insert("modulus".to_string(), json!(limbs));
    }
    else if config["alg"].as_str().unwrap() == "ES256K" {
        todo!("Not yet implemented");
    }
    else {
        return_error!("Unsupported algorithm {}");
    }

    if config["defer_sig_ver"].as_bool().unwrap() {
        // Output "digest_248" to prover_inputs.json
        todo!("Not yet implemented");
    }

    // Other values the prover needs
    prover_inputs_json.insert("message_padded_bytes".to_string(), json!(msg_len_after_SHA2_padding.to_string()));
    let period_idx = header_utf8.len() - 1;
    prover_inputs_json.insert("period_idx".to_string(), json!(period_idx.to_string()));


    let header_pad = base_64_decoded_header_padding(period_idx)?;
    let header_and_payload = format!("{}{}{}", jwt_header_decoded, header_pad, claims_decoded);
    prepare_prover_claim_inputs(header_and_payload, &config, &claims, &mut prover_inputs_json)?;


    println!("{}", serde_json::to_string_pretty(&prover_inputs_json)?);


    Ok(())
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
                        let max_claim_byte_len = config["max_claim_byte_len"].as_u64().unwrap();    // validated by load_config
                        let packed = pack_string_to_int(claims[name].as_str().ok_or("invalid_type")?, max_claim_byte_len.try_into()?)?;
                        prover_inputs_json.insert(format!("{}_value", name), json!(packed));
                    }
                    _ => {
                        return_error!("Can only reveal number types and string types as a single field element for now. See also `reveal_bytes`.")
                    }
                }
            }
        }
        
        if entry.contains_key("predicates") {
            let predicates = entry["predicates"].as_array().ok_or(format!("predicates for entry {} must be an array", name))?;
            for p in predicates {
                let predicate = p.as_object().ok_or(format!("A predicate for entry {} is not an object", name))?;
                // Some predicates might have additional inputs, and others do not
                // E.g., AssertMicrosoftDomain has no extra inputs, but AssertEmailDomain needs the domain as special input. 
                // TODO: we don't implement this for now in Rust (it's python though)
                if predicate.contains_key("special_inputs") {
                    return_error!("Support for predicates with 'special_inputs' not implemented ");
                }

            }
        }

    }


    Ok(())
}

fn pack_string_to_int(s: &str, n_bytes: usize) -> Result<String, Box<std::io::Error>> {
    // Must match function "RevealClaimValue" in match_claim.circom
    // so we add quotes to the string TODO: maybe reveal the unquoted claim value instead?

    //First convert "s" to bytes and pad with zeros
    let s_quoted = format!("\"{}\"",s);
    let s_bytes = s_quoted.bytes();
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
            for (i, c) in msg[value_start..].chars().enumerate() {
                if "truefalse".find(c).is_none() {
                    r = value_start + i;
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


fn is_minified(msg: &String) -> bool {
    // Check for extra spaces, e.g.,
    //     "exp" : 123456789
    // is not sufficiently minified, but
    //     "exp":123456789
    // is minified. Our Circom circuit currently does not support extra space(s).
    if msg.find("\": ").is_some() {
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

fn to_circom_limbs(n_bytes: &Vec<u8>, limb_size: usize)-> Result<Vec<String>, Box<dyn std::error::Error>> {
    let n = BigInt::from_bytes_be(num_bigint::Sign::Plus, &n_bytes);    
    let num_limbs = (n.bits() as usize + limb_size - 1) / limb_size;

    // Extract the limbs
    let one = BigInt::from_u32(1).unwrap();
    let mut limbs = Vec::with_capacity(num_limbs);
    let msk = one.clone().shl(limb_size) - &one;

    for i in 0..num_limbs {
        let limb = (&n >> (i * limb_size)).bitand(&msk);
        limbs.push(limb);
    }

    // Convert to strings before returning
    Ok(limbs.into_iter().map(|l| l.to_str_radix(10)).collect())
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

#[macro_export]
macro_rules! return_error {
    ($msg:expr) => {
        return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, $msg)))
    };
}

fn load_config(path: PathBuf) -> Result<serde_json::Map<String, Value>, Box<dyn Error>> {
    let config_str = fs::read_to_string(path)?;
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
    if !config.contains_key("reveal_all_claims") {
        config.insert("reveal_all_claims".to_string(), json!(false));
    }
    else {
        if !config["reveal_all_claims"].is_boolean() {
            return_error!("reveal_all_claims must have boolean type");
        }
    }
    if !config.contains_key("defer_sig_ver") {
        config.insert("defer_sig_ver".to_string(), json!(false));
    }
    else {
        if !config["defer_sig_ver"].is_boolean() {
            return_error!("defer_sig_ver must have boolean type");
        }
    }    

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

    // Additional checks
    if config["defer_sig_ver"].as_bool().unwrap() {
        if alg != "ES256K" {
            return_error!("The 'defer_sig_ver' option is only valid with the ES256K algorithm");
        }
    }

    // For all the config entries about claims (e.g, "email", "exp", etc.) make sure that if the claim 
    // is to be revealed, that max_claim_byte_len is set
    for (key, _) in config.clone() {
        if !CRESCENT_CONFIG_KEYS.contains(key.as_str()) {
            let claim_entry = config.get(key.as_str()).unwrap().as_object().ok_or("expected object type")?.clone();
            if claim_entry.contains_key("reveal") && claim_entry["reveal"].as_bool().unwrap_or(false) {
                if !claim_entry.contains_key("max_claim_byte_len") {
                    return_error!(format!("Config entry for claim {} has reveal flag set but is missing 'max_claim_byte_len'", key));
                }
            }
        }
    }

    Ok(config.clone())
}
