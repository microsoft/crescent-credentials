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

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[wasm_bindgen]
extern "C" {
    pub fn js_now_seconds() -> u64;
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
) -> String {
    if client_state_b64url.is_empty() {
        return "Error: Received empty client_state_b64url".to_string();
    }
    if range_pk_b64url.is_empty() {
        return "Error: Received empty range_pk_b64url".to_string();
    }
    if disc_uid.is_empty() {
        return "Error: Received empty disc_uid".to_string();
    }
    if io_locations_str.is_empty() {
        return "Error: Received empty io_locations_str".to_string();
    }

    let client_state_bytes = match decode(&client_state_b64url) {
        Ok(bytes) => bytes,
        Err(_) => return "Error: Failed to decode base64url client_state".to_string(),
    };
    let range_pk_bytes = match decode(&range_pk_b64url) {
        Ok(bytes) => bytes,
        Err(_) => return "Error: Failed to decode base64url range_pk".to_string(),
    };

    let client_state_result =
        ClientState::<ECPairing>::deserialize_uncompressed(&client_state_bytes[..]);
    let range_pk_result = RangeProofPK::<ECPairing>::deserialize_uncompressed(&range_pk_bytes[..]);
    let io_locations = IOLocations::new_from_str(&io_locations_str);
    let proof_spec_result: Result<ProofSpec, serde_json::Error> =
        serde_json::from_str(DEFAULT_PROOF_SPEC);

    match (client_state_result, range_pk_result, proof_spec_result) {
        (Ok(mut client_state), Ok(range_pk), Ok(mut proof_spec)) => {
            let msg =
                "Successfully deserialized client-state, range-pk, and proof-spec".to_string();

            log(&msg);

            let show_proof = if &client_state.credtype == "mdl" {
                let age = disc_uid_to_age(&disc_uid).map_err(|_| {
                    "Disclosure UID does not have associated age parameter".to_string()
                });
                create_show_proof_mdl(
                    &mut client_state,
                    &range_pk,
                    Some(challenge.as_bytes()),
                    &io_locations,
                )
            } else {
                proof_spec.presentation_message = Some(challenge.into());
                create_show_proof(&mut client_state, &range_pk, &io_locations, &proof_spec, None).unwrap()
            };

            let show_proof_b64 = write_to_b64url(&show_proof);
            let msg = format!("show_proof_b64: {:?}", show_proof_b64);
            msg
        }
        (Err(e), _, _) => {
            let msg = format!("Error: Failed to deserialize client state: {:?}", e);
            msg
        }
        (_, Err(e), _) => {
            let msg = format!("Error: Failed to deserialize range pk: {:?}", e);
            msg
        }
        (_, _, Err(e)) => {
            let msg = format!("Error: Failed to deserialize proof-spec: {:?}", e);
            msg
        }
    }
}
