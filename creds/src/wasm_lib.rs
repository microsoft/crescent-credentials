// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::create_show_proof;
use crate::create_show_proof_mdl;
use crate::utils::write_to_b64url;
use crate::ClientState;
use crate::IOLocations;
use crate::ProofSpec;
use crate::RangeProofPK;
use crate::DEFAULT_PROOF_SPEC;
use ark_bn254::Bn254 as ECPairing;
use ark_serialize::CanonicalDeserialize;
use base64_url::decode;
use wasm_bindgen::prelude::wasm_bindgen;
use sha2::{Digest, Sha256};
use crate::device::TestDevice;
use std::collections::HashMap;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[wasm_bindgen]
extern "C" {
    pub fn js_now_seconds() -> u64;
}

#[wasm_bindgen(start)]
pub fn main() {
    console_error_panic_hook::set_once();
}

fn disc_uid_to_age(disc_uid: &str) -> Result<usize, &'static str> {
    match disc_uid {
        "crescent://over_18" => Ok(18),
        "crescent://over_21" => Ok(21),
        "crescent://over_65" => Ok(65),
        _ => Err("disc_uid_to_age: invalid disclosure uid"),
    }
}

#[wasm_bindgen]
pub fn create_show_proof_wasm(
    client_state_b64url: String,
    range_pk_b64url: String,
    io_locations_str: String,
    disc_uid: String,
    challenge: String,
    proof_spec: String,
    device_priv_key: Option<String>,
) -> Result<String, String> {

    let msg = format!(
        "create_show_proof_wasm inputs: client_state_b64url: {}, range_pk_b64url: {}, io_locations_str: {}, disc_uid: {}, challenge: {}, proof_spec: {}, device_priv_key: {}",
        client_state_b64url, range_pk_b64url, io_locations_str, disc_uid, challenge, proof_spec, device_priv_key.as_deref().unwrap_or("None")
    );
    log(&msg);

    if client_state_b64url.is_empty() {
        return Err("Received empty client_state_b64url".to_string());
    }
    if range_pk_b64url.is_empty() {
        return Err("Received empty range_pk_b64url".to_string());
    }
    if disc_uid.is_empty() {
        return Err("Received empty disc_uid".to_string());
    }
    if io_locations_str.is_empty() {
        return Err("Received empty io_locations_str".to_string());
    }
    if challenge.is_empty() {
        return Err("Received empty challenge".to_string());
    }
    if proof_spec.is_empty() {
        return Err("Received empty proof_spec".to_string());
    }

    let client_state_bytes = decode(&client_state_b64url)
        .map_err(|_| "Failed to decode base64url client_state".to_string())?;
    let range_pk_bytes = decode(&range_pk_b64url)
        .map_err(|_| "Failed to decode base64url range_pk".to_string())?;

    let client_state_result =
        ClientState::<ECPairing>::deserialize_uncompressed(&client_state_bytes[..]);
    let range_pk_result =
        RangeProofPK::<ECPairing>::deserialize_uncompressed(&range_pk_bytes[..]);
    let io_locations = IOLocations::new_from_str(&io_locations_str);

    let proof_spec_bytes =
        base64_url::decode(&proof_spec).map_err(|_| "Failed to decode base64url proof_spec".to_string())?;
    let proof_spec_string = String::from_utf8(proof_spec_bytes)
        .map_err(|_| "Decoded proof_spec is not valid UTF-8".to_string())?;
    println!("Parsed proof spec from b64: {:?}", proof_spec_string);

    let proof_spec_result: Result<ProofSpec, serde_json::Error> =
        serde_json::from_str(&proof_spec_string);

    match (client_state_result, range_pk_result, proof_spec_result) {
        (Ok(mut client_state), Ok(range_pk), Ok(mut proof_spec)) => {
            log("Successfully deserialized client-state, range-pk, and proof-spec");

            proof_spec.presentation_message = Some(Sha256::digest(challenge).to_vec());

            // create the device signature (if cred is device-bound)
            let device_signature = if proof_spec.device_bound.unwrap_or(false) {
                if let Some(key) = &device_priv_key {
                    let device = TestDevice::new_from_pem(key);
                    Some(device.sign(proof_spec.presentation_message.as_ref().unwrap()))
                } else {
                    None
                }
            } else {
                None
            };

            let show_proof = if &client_state.credtype == "mdl" {
                let age = disc_uid_to_age(&disc_uid)
                    .map_err(|_| "Disclosure UID does not have associated age parameter".to_string())? as u64;

                proof_spec.range_over_year = Some(std::collections::BTreeMap::from([
                    ("birth_date".to_string(), age),
                ]));

                create_show_proof_mdl(
                    &mut client_state,
                    &range_pk,
                    &proof_spec,
                    &io_locations,
                    device_signature,
                )
                .map_err(|e| format!("create_show_proof_mdl failed: {:?}", e))?
            } else {
                create_show_proof(
                    &mut client_state,
                    &range_pk,
                    &io_locations,
                    &proof_spec,
                    device_signature,
                )
                .map_err(|e| format!("create_show_proof failed: {:?}", e))?
            };

            let show_proof_b64 = write_to_b64url(&show_proof);
            Ok(show_proof_b64)
        }
        (Err(e), _, _) => {
            Err(format!("Failed to deserialize client state: {:?}", e))
        }
        (_, Err(e), _) => {
            Err(format!("Failed to deserialize range pk: {:?}", e))
        }
        (_, _, Err(e)) => {
            Err(format!("Failed to deserialize proof-spec: {:?}", e))
        } 
    }
}
