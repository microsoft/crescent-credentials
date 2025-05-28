// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::{fs, path::PathBuf, error::Error};
use ark_bn254::{Bn254 as ECPairing, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_groth16::{Groth16, PreparedVerifyingKey, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{end_timer, rand::thread_rng, start_timer};

use groth16rand::{ShowGroth16, ShowRange};
use num_bigint::BigUint;
use num_traits::Num;
use prep_inputs::{create_proof_spec_internal, pem_to_inputs, unpack_int_to_string_unquoted};
use serde::{Deserialize, Serialize};
use serde_json::{json,Value};
use sha2::{Digest, Sha256};
use utils::{read_from_file, strip_quotes, write_to_file};
use crate::rangeproof::{RangeProofPK, RangeProofVK};
use crate::structs::{PublicIOType, IOLocations, GenericInputsJSON};
use crate::groth16rand::ClientState;
use crate::utils::utc_now_seconds;
use crate::device::{DeviceProof, ECDSASig};
use crate::daystamp::days_to_be_age;


#[cfg(not(feature = "wasm"))]
use {
    ark_circom::{CircomBuilder, CircomConfig},
    crate::structs::ProverInput,
};

#[cfg(feature = "wasm")]
pub use wasm_lib::create_show_proof_wasm;

#[cfg(feature = "wasm")]
pub mod wasm_lib;

pub mod daystamp;
pub mod dlog;
pub mod groth16rand;
pub mod prep_inputs;
pub mod rangeproof;
pub mod structs;
pub mod utils;
pub mod device;

const RANGE_PROOF_INTERVAL_BITS: usize = 32;
const SHOW_PROOF_VALIDITY_SECONDS: u64 = 300;    // The verifier only accepts proofs fresher than this
pub const DEFAULT_PROOF_SPEC : &str = r#"{"revealed" : ["email"]}"#;

pub type CrescentPairing = ECPairing;
pub type CrescentFr = Fr;

/// Parameters required to create Groth16 proofs
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProverParams<E: Pairing> {
    pub groth16_params : ProvingKey<E>,
    pub groth16_pvk : PreparedVerifyingKey<E>,
    pub config_str : String
}
impl<E: Pairing> ProverParams<E> {
    pub fn new(paths : &CachePaths) -> Result<Self, SerializationError> {
        let prover_params : ProverParams<E> = read_from_file(&paths.prover_params)?;
        Ok(prover_params)
    }
}

/// Parameters required to create show/presentation proofs
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ShowParams<'b, E: Pairing> {
    range_pk: RangeProofPK<'b, E>
}
impl<'b, E: Pairing> ShowParams<'b, E> {
    pub fn new(paths : &CachePaths) -> Result<Self, SerializationError> {
        let range_pk : RangeProofPK<'b, E> = read_from_file(&paths.range_pk)?;
        Ok(Self{range_pk})
    }
}

/// Parameters required to verify show/presentation proofs
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifierParams<E: Pairing> {
    pub vk : VerifyingKey<E>,
    pub pvk : PreparedVerifyingKey<E>,
    pub range_vk: RangeProofVK<E>,
    pub io_locations_str: String, // Stored as String since IOLocations does not implement CanonicalSerialize
    pub issuer_pem: String, 
    pub config_str: String
}
impl<E: Pairing> VerifierParams<E> {
    pub fn new(paths : &CachePaths) -> Result<Self, SerializationError> {
        let pvk : PreparedVerifyingKey<E> = read_from_file(&paths.groth16_pvk)?;
        let vk : VerifyingKey<E> = read_from_file(&paths.groth16_vk)?;
        let range_vk : RangeProofVK<E> = read_from_file(&paths.range_vk)?;
        let io_locations_str = std::fs::read_to_string(&paths.io_locations)?;
        let issuer_pem = std::fs::read_to_string(&paths.issuer_pem)?;
        let config_str = std::fs::read_to_string(&paths.config)?;
        Ok(Self{vk, pvk, range_vk, io_locations_str, issuer_pem, config_str})
    }
}

// Proof specification describing what is to be proven during a Show proof.  Currently supporting selective disclosure
// of attributes as field elements or hashed values, and range proofs.
// The range proof for the expiration date ("exp" for JWT, "valid_until" for mDL) is in the future is always done.
#[derive(Serialize, Deserialize, Debug)]
pub struct ProofSpec {
    pub revealed: Vec<String>,
    pub range_over_year: Option<std::collections::BTreeMap<String, u64>>,
    pub presentation_message: Option<Vec<u8>>,
    pub device_bound: Option<bool>,
}

#[derive(Serialize)]
pub(crate) struct ProofSpecInternal {
    pub revealed: Vec<String>,
    pub range_over_year: Vec<(String, u64)>,
    pub hashed: Vec<String>, 
    pub presentation_message : Option<Vec<u8>>,
    pub device_bound: bool,
    pub config_str: String
}

/// Structure to hold all the parts of a show/presentation proof
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ShowProof<E: Pairing> {
    pub show_groth16: ShowGroth16<E>,
    pub show_range_exp: ShowRange<E>, // non-expired range proof (always perfomed)
    pub show_range_attr: Vec<ShowRange<E>>, // selective attribute range proofs
    pub revealed_inputs: Vec<E::ScalarField>, 
    pub revealed_preimages: Option<String>,
    pub inputs_len: usize, 
    pub cur_time: u64,
    pub device_proof: Option<DeviceProof<E::G1>>
}

/// Central struct to configure the paths data stored between operations
pub struct CachePaths {
   pub _base: String,
   pub jwt : String,
   pub issuer_pem : String,
   pub config : String,
   pub io_locations: String,
   pub wasm: String,
   pub r1cs: String,
   pub _cache: String,
   pub range_pk: String,
   pub range_vk: String,
   pub groth16_vk: String,
   pub groth16_pvk: String,
   pub prover_params: String,   
   pub client_state: String, 
   pub show_proof: String,
   pub mdl_prover_inputs: String, 
   pub proof_spec: String,
   pub device_pub_pem: String,
   pub device_prv_pem: String
}

impl CachePaths {
    pub fn new(base_path: PathBuf) -> Self{
        let base_path_str = base_path.into_os_string().into_string().unwrap();
        Self::new_from_str(&base_path_str)
    }

    pub fn new_from_str(base_path: &str) -> Self {
        let base_path_str = format!("{}/", base_path);
        if fs::metadata(&base_path_str).is_err() {
            println!("base_path = {}", base_path_str);
            panic!("invalid path");
        }
        println!("base_path_str = {}", base_path_str);
        let cache_path = format!("{}cache/", base_path_str);
    
        if fs::metadata(&cache_path).is_ok() {
            println!("Found directory {} to store data", cache_path);
        } else {
            println!("Creating directory {} to store data", cache_path);
            fs::create_dir(&cache_path).unwrap();        
        }

        CachePaths {
            _base: base_path_str.clone(),
            jwt: format!("{}token.jwt", base_path_str),
            issuer_pem: format!("{}issuer.pub", base_path_str),
            config: format!("{}config.json", base_path_str),
            io_locations: format!("{}io_locations.sym", base_path_str),
            wasm: format!("{}main.wasm", base_path_str),
            r1cs: format!("{}main_c.r1cs", base_path_str),
            _cache: cache_path.clone(),
            range_pk: format!("{}range_pk.bin", &cache_path),
            range_vk: format!("{}range_vk.bin", &cache_path),
            groth16_vk: format!("{}groth16_vk.bin", &cache_path),
            groth16_pvk: format!("{}groth16_pvk.bin", &cache_path),
            prover_params: format!("{}prover_params.bin", &cache_path),
            client_state: format!("{}client_state.bin", &cache_path),
            show_proof: format!("{}show_proof.bin", &cache_path),
            mdl_prover_inputs: format!("{}prover_inputs.json", &base_path_str),
            proof_spec: format!("{}proof_spec.json", &base_path_str),
            device_pub_pem: format!("{}device.pub", &base_path_str),
            device_prv_pem: format!("{}device.prv", &base_path_str),
        }             
    }
}

#[cfg(not(feature = "wasm"))]
pub fn run_zksetup(base_path: PathBuf) -> i32 {

    let paths = CachePaths::new(base_path);

    let circom_timer = start_timer!(|| "Reading R1CS instance and witness generator");
    let cfg = CircomConfig::<ECPairing>::new(
        &paths.wasm,
        &paths.r1cs,
    )
    .unwrap();
    let builder = CircomBuilder::new(cfg);
    let circom = builder.setup();
    end_timer!(circom_timer);

    let groth16_setup_timer = start_timer!(|| "Generating Groth16 system parameters");
    let mut rng = thread_rng();
    let params =
        Groth16::<ECPairing>::generate_random_parameters_with_reduction(circom, &mut rng)
            .unwrap();

    let vk = params.vk.clone();
    let pvk = Groth16::<ECPairing>::process_vk(&params.vk).unwrap();  
    end_timer!(groth16_setup_timer);

    let range_setup_timer = start_timer!(|| "Generating parameters for range proofs");    
    let (range_pk, range_vk) = RangeProofPK::<ECPairing>::setup(RANGE_PROOF_INTERVAL_BITS);
    end_timer!(range_setup_timer);
    
    let serialize_timer = start_timer!(|| "Writing everything to files");
    write_to_file(&range_pk, &paths.range_pk);
    write_to_file(&range_vk, &paths.range_vk);    
    write_to_file(&vk, &paths.groth16_vk);
    write_to_file(&pvk, &paths.groth16_pvk);

    let config_str = fs::read_to_string(&paths.config).unwrap_or_else(|_| panic!("Unable to read config from {} ", paths.config));
    let prover_params = ProverParams{groth16_params: params, groth16_pvk: pvk, config_str};
    write_to_file(&prover_params, &paths.prover_params);    
    end_timer!(serialize_timer);

    0
}

#[cfg(not(feature = "wasm"))]
pub fn create_client_state(paths : &CachePaths, prover_inputs: &GenericInputsJSON, prover_aux: Option<&String>, credtype : &str) -> Result<ClientState<ECPairing>, SerializationError>
{
    let circom_timer = start_timer!(|| "Reading R1CS Instance and witness generator WASM");
    let cfg = CircomConfig::<ECPairing>::new(
        &paths.wasm,
        &paths.r1cs,
    )
    .unwrap();
    let mut builder = CircomBuilder::new(cfg);
    prover_inputs.push_inputs(&mut builder);
    end_timer!(circom_timer);

    let load_params_timer = start_timer!(||"Reading ProverParams params from file");
    let prover_params : ProverParams<ECPairing> = read_from_file(&paths.prover_params)?;
    end_timer!(load_params_timer);
    
    let build_timer = start_timer!(|| "Witness Generation");
    let circom = builder.build().unwrap();
    end_timer!(build_timer);    
    let inputs = circom.get_public_inputs().unwrap();

    // println!("Inputs for groth16 proof: ");
    // for (i, input) in inputs.clone().into_iter().enumerate() {
    //     println!("input {}  =  {:?}", i, input.into_bigint().to_string());
    // }

    let mut rng = thread_rng();
    let prove_timer = start_timer!(|| "Groth16 prove");    
    let proof = Groth16::<ECPairing>::prove(&prover_params.groth16_params, circom, &mut rng).unwrap();    
    end_timer!(prove_timer);

    let pvk : PreparedVerifyingKey<ECPairing> = read_from_file(&paths.groth16_pvk)?;
    let verify_timer = start_timer!(|| "Groth16 verify");
    let verified =
        Groth16::<ECPairing>::verify_with_processed_vk(&pvk, &inputs, &proof).unwrap();
    assert!(verified);
    end_timer!(verify_timer);

    let mut client_state = ClientState::<ECPairing>::new(
        inputs.clone(),
        prover_aux.cloned(),
        proof.clone(),
        prover_params.groth16_params.vk.clone(),
        pvk.clone(),
        prover_params.config_str.clone()
    );
    client_state.credtype = credtype.to_string();

    Ok(client_state)
}

pub fn create_show_proof(client_state: &mut ClientState<ECPairing>, range_pk : &RangeProofPK<ECPairing>, io_locations: &IOLocations, proof_spec: &ProofSpec, device_signature: Option<Vec<u8>>) -> Result<ShowProof<ECPairing>, Box<dyn Error>>
{
    // Create Groth16 rerandomized proof for showing
    let exp_value_pos = io_locations.get_io_location("exp_value").unwrap();
    let mut io_types = vec![PublicIOType::Hidden; client_state.inputs.len()];
    io_types[exp_value_pos - 1] = PublicIOType::Committed;

    for i in io_locations.get_public_key_indices() {
        io_types[i] = PublicIOType::Revealed;
    }

    let proof_spec = create_proof_spec_internal(proof_spec, &client_state.config_str)?;

    // For the attributes revealed as field elements, we set the position to Revealed and send the value
    let mut revealed_inputs = vec![];
    for attr in &proof_spec.revealed {
        let io_loc = match io_locations.get_io_location(&format!("{}_value", &attr)) {
            Ok(loc) => loc,
            Err(_) => {
                return_error!(
                    format!("Asked to reveal hashed attribute {}, but did not find it in io_locations\nIO locations: {:?}", attr, io_locations.get_all_names()));
            }
        };

        io_types[io_loc - 1] = PublicIOType::Revealed;
        revealed_inputs.push(client_state.inputs[io_loc - 1]);
    }

    // For the attributes revealed as digests, we provide the preimage, the verifier will hash it to get the field element
    let mut revealed_preimages = serde_json::Map::new();
    for attr in &proof_spec.hashed {
        let io_loc = match io_locations.get_io_location(&format!("{}_digest", &attr)) {
            Ok(loc) => loc,
            Err(_) => {
                return_error!(
                    format!("Asked to reveal hashed attribute {}, but did not find it in io_locations\nIO locations: {:?}", attr, io_locations.get_all_names()));
            }
        };        

        io_types[io_loc - 1] = PublicIOType::Revealed;

        if client_state.aux.is_none() {
            return_error!(format!("Proof spec asked to reveal hashed attribute {}, but client state is missing aux data", attr));
        }
        let aux = serde_json::from_str::<Value>(client_state.aux.as_ref().unwrap()).unwrap();
        let aux = aux.as_object().unwrap();
        revealed_preimages.insert(attr.clone(), json!(aux[attr].clone().to_string()));
    }

    // If the credential is device bound, the public key attributes must be committed
    if proof_spec.device_bound {
        let device_key_0_pos = io_locations.get_io_location("device_key_0_value").unwrap();
        let device_key_1_pos = io_locations.get_io_location("device_key_1_value").unwrap();
        io_types[device_key_0_pos - 1] = PublicIOType::Committed;
        io_types[device_key_1_pos - 1] = PublicIOType::Committed;
    }

    // Serialize the proof spec as the context
    let context_str = serde_json::to_string(&proof_spec).unwrap();
    let show_groth16 = client_state.show_groth16(Some(context_str.as_bytes()), &io_types);
    
    // Create fresh range proof 
    let time_sec = utc_now_seconds();
    let cur_time = Fr::from( time_sec );

    let mut com_exp_value = client_state.committed_input_openings[0].clone();
    com_exp_value.m -= cur_time;
    com_exp_value.c -= com_exp_value.bases[0] * cur_time;
    let show_range_exp = client_state.show_range(&com_exp_value, RANGE_PROOF_INTERVAL_BITS, range_pk);

    let device_proof = 
    if proof_spec.device_bound {
        assert!(client_state.committed_input_openings.len() >= 3);
        let com0 = client_state.committed_input_openings[1].clone();
        let com1 = client_state.committed_input_openings[2].clone();
        let sig = ECDSASig::new_from_bytes(&proof_spec.presentation_message.unwrap(), &device_signature.unwrap());
        let aux = serde_json::from_str::<Value>(client_state.aux.as_ref().unwrap()).unwrap();
        let aux = aux.as_object().unwrap();
        let x = BigUint::from_str_radix(aux["device_pub_x"].as_str().unwrap(), 10).unwrap();
        let y = BigUint::from_str_radix(aux["device_pub_y"].as_str().unwrap(), 10).unwrap();
        Some(DeviceProof::prove(&com0, &com1, &sig, &x, &y))
    } else {
        None
    };

    // Assemble proof
    let revealed_preimages = if proof_spec.hashed.is_empty() { 
        assert!(revealed_preimages.is_empty());
        None 
    } else {
        Some(serde_json::to_string(&revealed_preimages).unwrap())
    };
    let show_range_attr= vec![]; // no attribute range proofs for JWT yet
    Ok(ShowProof{ show_groth16, show_range_exp, show_range_attr, revealed_inputs, revealed_preimages, inputs_len: client_state.inputs.len(), cur_time: time_sec, device_proof})
}

// TODO: with SD and DB, that starts looking a lot like the JWT function; merge!
pub fn create_show_proof_mdl(client_state: &mut ClientState<ECPairing>, range_pk : &RangeProofPK<ECPairing>, proof_spec: &ProofSpec, io_locations: &IOLocations) -> Result<ShowProof<ECPairing>, Box<dyn Error>>
{
    // Create Groth16 rerandomized proof for showing

    let proof_spec = create_proof_spec_internal(proof_spec, &client_state.config_str)?;

    // commit the expiration date (for non-expired range proof)
    let valid_until_value_pos = io_locations.get_io_location("valid_until_value").unwrap();
    let mut io_types = vec![PublicIOType::Hidden; client_state.inputs.len()];
    io_types[valid_until_value_pos - 1] = PublicIOType::Committed;
    // for each range proofed attribute, set the position to Committed
    for (attr, _) in &proof_spec.range_over_year {
        let io_loc = io_locations.get_io_location(&format!("{}_value", &attr)).unwrap();
        io_types[io_loc - 1] = PublicIOType::Committed;
    }

    for i in io_locations.get_public_key_indices() {
        io_types[i] = PublicIOType::Revealed;
    }

    // For the attributes revealed as field elements, we set the position to Revealed and send the value
    let mut revealed_inputs = vec![];
    for attr in &proof_spec.revealed {
        let io_loc = io_locations.get_io_location(&format!("{}_value", &attr)).unwrap();
        io_types[io_loc - 1] = PublicIOType::Revealed;
        revealed_inputs.push(client_state.inputs[io_loc - 1]);
    }

    // For the attributes revealed as digests, we provide the preimage, the verifier will hash it to get the field element
    let mut revealed_preimages = serde_json::Map::new();
    for attr in &proof_spec.hashed {
        let io_loc = match io_locations.get_io_location(&format!("{}_digest", &attr)) {
            Ok(loc) => loc,
            Err(_) => {
                return_error!(
                    format!("Asked to reveal hashed attribute {}, but did not find it in io_locations\nIO locations: {:?}", attr, io_locations.get_all_names()));
            }
        };        

        io_types[io_loc - 1] = PublicIOType::Revealed;

        if client_state.aux.is_none() {
            return_error!(format!("Proof spec asked to reveal hashed attribute {}, but client state is missing aux data", attr));
        }
        let aux = serde_json::from_str::<Value>(client_state.aux.as_ref().unwrap()).unwrap();
        let aux = aux.as_object().unwrap();
        revealed_preimages.insert(attr.clone(), json!(aux[attr].clone().to_string()));
    }

    // Serialize the proof spec as the context
    let context_str = serde_json::to_string(&proof_spec).unwrap();
    let show_groth16 = client_state.show_groth16(Some(context_str.as_bytes()), &io_types);    
    
    // Create fresh range proof for validUntil
    let time_sec = utc_now_seconds();
    let cur_time = Fr::from(time_sec);

    let mut com_valid_until_value = client_state.committed_input_openings[0].clone();
    com_valid_until_value.m -= cur_time;
    com_valid_until_value.c -= com_valid_until_value.bases[0] * cur_time;
    let show_range_exp = client_state.show_range(&com_valid_until_value, RANGE_PROOF_INTERVAL_BITS, range_pk);

    let mut show_range_attr= vec![];
    let mut commitment_index = 1; // skip the first one (validUntil)
    // for each range-proofed attribute, create a fresh range proof that the attribute is at least "age" years old // TODO: generalize to non-age attributes
    for (_, age) in &proof_spec.range_over_year {
        let days_in_age = Fr::from(days_to_be_age(*age) as u64);
        let mut com_attr = client_state.committed_input_openings[commitment_index].clone();
        com_attr.m -= days_in_age;
        com_attr.c -= com_attr.bases[0] * days_in_age;

        let show_range_a = client_state.show_range(&com_attr, RANGE_PROOF_INTERVAL_BITS, range_pk);       

        show_range_attr.push(show_range_a);
        commitment_index += 1;
    }

    // Assemble proof and return
    Ok(ShowProof{ show_groth16, show_range_exp, show_range_attr, revealed_inputs, revealed_preimages: None, inputs_len: client_state.inputs.len(), cur_time: time_sec, device_proof: None})
}

fn sort_by_io_location(attrs: &[String], io_locations: &IOLocations) -> Vec<String> {
    let mut attrs_with_locs: Vec<(usize, String)> = attrs
        .iter()
        .map(|attr| {
            let io_loc = io_locations.get_io_location(&format!("{}_digest", attr)).unwrap();
            (io_loc, attr.clone())
        })
        .collect();
    attrs_with_locs.sort_by_key(|k| k.0);
    attrs_with_locs.into_iter().map(|(_, attr)| attr).collect()
}

pub fn verify_show(vp : &VerifierParams<ECPairing>, show_proof: &ShowProof<ECPairing>, proof_spec: &ProofSpec) -> (bool, String)
{
    let io_locations = IOLocations::new_from_str(&vp.io_locations_str);
    let exp_value_pos = io_locations.get_io_location("exp_value").unwrap();
    let mut io_types = vec![PublicIOType::Hidden; show_proof.inputs_len];
    io_types[exp_value_pos - 1] = PublicIOType::Committed;
    for i in io_locations.get_public_key_indices() {
        io_types[i] = PublicIOType::Revealed;
    }

    let proof_spec = create_proof_spec_internal(proof_spec, &vp.config_str);
    if proof_spec.is_err() {
        println!("Failed to create internal proof spec");
        return (false, "".to_string());
    }
    let proof_spec = proof_spec.unwrap();

    // Set disclosed attributes to Revealed
    for attr in &proof_spec.revealed {
        let io_loc = io_locations.get_io_location(&format!("{}_value", &attr));
        if io_loc.is_err() {
            println!("Asked to reveal attribute {}, but did not find it in io_locations", attr);
            println!("IO locations: {:?}", io_locations.get_all_names());
            return (false, "".to_string());
        }
        let io_loc = io_loc.unwrap();
        io_types[io_loc - 1] = PublicIOType::Revealed;
    }

    // For the attributes revealed as digests, we hash the provided preimage to get the field element
    let mut revealed_hashed = vec![];
    let mut preimages = json!(serde_json::Value::Null);
    if !proof_spec.hashed.is_empty() {
        assert!(show_proof.revealed_preimages.is_some());
        let preimages0 = serde_json::from_str::<Value>(show_proof.revealed_preimages.as_ref().unwrap());
        if preimages0.is_err() {
            println!("Failed to deserialize revealed_preimages");
            return (false, "".to_string());
        }
        preimages = preimages0.unwrap();

        let hashed_attributes = sort_by_io_location(&proof_spec.hashed, &io_locations);
    
        for attr in &hashed_attributes {
            let io_loc = io_locations.get_io_location(&format!("{}_digest", &attr));
            if io_loc.is_err() {
                println!("Asked to reveal hashed attribute {}, but did not find it in io_locations", attr);
                println!("IO locations: {:?}", io_locations.get_all_names());
                return (false, "".to_string());
            }
            let io_loc = io_loc.unwrap();
            io_types[io_loc - 1] = PublicIOType::Revealed;

            let preimage = preimages.get(attr);
            if preimage.is_none() {
                println!("Error: preimage for hashed attribute {} not provided by prover", attr);
                return(false, "".to_string());
            }
            
            let data = match preimage.unwrap() {
                Value::String(s) =>  {
                    s.as_bytes()
                },     
                _ =>  {
                    println!("Error: preimage has unsupported type");
                    return(false, "".to_string());
                }
            };
            let digest = Sha256::digest(data);
            let digest248 = &digest[0..digest.len()-1];
            let digest_uint = utils::bits_to_num(digest248);
            let digest_scalar = utils::biguint_to_scalar::<CrescentFr>(&digest_uint);
            revealed_hashed.push(digest_scalar);
        }
    }

    // If the credential is device bound, the device public key attributes must be committed
    if proof_spec.device_bound {
        let device_key_0_pos = io_locations.get_io_location("device_key_0_value").unwrap();
        let device_key_1_pos = io_locations.get_io_location("device_key_1_value").unwrap();
        io_types[device_key_0_pos - 1] = PublicIOType::Committed;
        io_types[device_key_1_pos - 1] = PublicIOType::Committed;
    }

    // Create an inputs vector with the revealed inputs and the issuer's public key
    let public_key_inputs = pem_to_inputs::<<ECPairing as Pairing>::ScalarField>(&vp.issuer_pem);
    if public_key_inputs.is_err() {
        print!("Error: Failed to convert issuer public key to input values");
        return (false, "".to_string());
    }

    let mut inputs = vec![];
    inputs.extend(revealed_hashed);
    inputs.extend(public_key_inputs.unwrap());
    inputs.extend(show_proof.revealed_inputs.clone());
    
    let context_str = serde_json::to_string(&proof_spec).unwrap();

    let verify_timer = std::time::Instant::now();
    let ret = show_proof.show_groth16.verify(&vp.vk, &vp.pvk, Some(context_str.as_bytes()), &io_types, &inputs);
    if !ret {
        println!("show_groth16.verify failed");
        return (false, "".to_string());
    }
    let cur_time = Fr::from(show_proof.cur_time);
    let now_seconds = utc_now_seconds();
    let delta = now_seconds.saturating_sub(show_proof.cur_time);
    println!("Proof created {} seconds ago", delta);    

    if delta > SHOW_PROOF_VALIDITY_SECONDS {
        println!("Invalid show proof -- older than {} seconds", SHOW_PROOF_VALIDITY_SECONDS);
        return (false, "".to_string());
    }

    let mut ped_com_exp_value = show_proof.show_groth16.commited_inputs[0];
    ped_com_exp_value -= vp.pvk.vk.gamma_abc_g1[exp_value_pos] * cur_time;
    let ret = show_proof.show_range_exp.verify(
        &ped_com_exp_value,
        RANGE_PROOF_INTERVAL_BITS,
        &vp.range_vk,
        &io_locations,
        &vp.pvk,
        "exp_value",
    );
    if !ret {
        println!("show_range.verify failed");
        return (false, "".to_string());
    }

    if proof_spec.device_bound {
        let device_key_0_pos = io_locations.get_io_location("device_key_0_value").unwrap();
        let device_key_1_pos = io_locations.get_io_location("device_key_1_value").unwrap();        
        let com0 = show_proof.show_groth16.commited_inputs[1];
        let com1 = show_proof.show_groth16.commited_inputs[2];
        let bases0 = vec![vp.pvk.vk.gamma_abc_g1[device_key_0_pos], vp.pvk.vk.delta_g1];
        let bases1 = vec![vp.pvk.vk.gamma_abc_g1[device_key_1_pos], vp.pvk.vk.delta_g1];
        let ret = DeviceProof::verify(show_proof.device_proof.as_ref().unwrap(), &com0.into(), &com1.into(), &bases0, &bases1);
        if !ret {
            println!("DeviceProof.verify failed");
            return (false, "".to_string());            
        }
    }
    
    println!("Verification time: {:?}", verify_timer.elapsed());  

    // Add the revealed attributes to the output, after converting from field element to string
    let mut revealed = serde_json::Map::<String, Value>::new();
    for (revealed_idx, attr_name) in proof_spec.revealed.iter().enumerate() {
        let attr_name = attr_name.clone() + "_value";
        let unpacked = unpack_int_to_string_unquoted( &show_proof.revealed_inputs[revealed_idx].into_bigint());
        if unpacked.is_err() {
            println!("Error: Proof was valid, but failed to unpack '{}' attribute, {:?}", attr_name, unpacked.err().unwrap());
            return (false, "".to_string());
        }
        let attr_value = &unpacked.unwrap().clone();
        revealed.insert(attr_name.clone(), json!(attr_value));
    }

    // Add the hashed revealed attributes to the output
    for attr_name in &proof_spec.hashed {
        let attr_value = preimages.get(attr_name);
        if attr_value.is_none() {
            println!("Error: Proof was valid, but failed to find hashed attribute '{}'", attr_name);
            return(false, "".to_string());
        }
        let value = match attr_value.unwrap() {
            Value::String(s) => {
                json!(strip_quotes(s))
            },
            _ => attr_value.unwrap().clone()
        };
        revealed.insert(attr_name.clone(), value);
    }


    (true, serde_json::to_string(&revealed).unwrap())
}

pub fn verify_show_mdl(vp : &VerifierParams<ECPairing>, show_proof: &ShowProof<ECPairing>, proof_spec: &ProofSpec) -> (bool, String)
{
    let proof_spec = create_proof_spec_internal(proof_spec, &vp.config_str);
    if proof_spec.is_err() {
        println!("Failed to create internal proof spec: {:?}", proof_spec.err().unwrap());
        return (false, "".to_string());
    }
    let proof_spec = proof_spec.unwrap();

    let io_locations = IOLocations::new_from_str(&vp.io_locations_str);
    let valid_until_value_pos = io_locations.get_io_location("valid_until_value").unwrap();
    let mut io_types = vec![PublicIOType::Hidden; show_proof.inputs_len];
    io_types[valid_until_value_pos - 1] = PublicIOType::Committed;
    // for each range proofed attribute, set the position to Committed
    for (attr, _) in &proof_spec.range_over_year {
        let io_loc = match io_locations.get_io_location(&format!("{}_value", &attr)) {
            Ok(loc) => loc,
            Err(_) => {
                println!("Asked to prove range for attribute {}, but did not find it in io_locations", attr);
                return (false, "".to_string());
            }
        };
        io_types[io_loc - 1] = PublicIOType::Committed;
    }

    for i in io_locations.get_public_key_indices() {
        io_types[i] = PublicIOType::Revealed;
    }

    // Set attributes to Revealed
    for attr in &proof_spec.revealed {
        let io_loc = io_locations.get_io_location(&format!("{}_value", &attr));
        if io_loc.is_err() {
            println!("Asked to reveal attribute {}, but did not find it in io_locations", attr);
            println!("IO locations: {:?}", io_locations.get_all_names());
            return (false, "".to_string());
        }
        let io_loc = io_loc.unwrap();
        io_types[io_loc - 1] = PublicIOType::Revealed;
    }

    // TODO: hashed attributes (see JWT)

    // If the credential is device bound, the device public key attributes must be committed
    if proof_spec.device_bound {
        // TODO
    }

    // Create an inputs vector with the inputs from the prover, and the issuer's public key
    let public_key_inputs = pem_to_inputs::<<ECPairing as Pairing>::ScalarField>(&vp.issuer_pem);
    if public_key_inputs.is_err() {
        print!("Error: Failed to convert issuer public key to input values");
        return (false, "".to_string());
    }
    let mut inputs = vec![];
    // inputs.extend(revealed_hashed); TODO: uncomment when hashed attributes are implemented
    inputs.extend(public_key_inputs.unwrap());
    inputs.extend(show_proof.revealed_inputs.clone());
    
    let context_str = serde_json::to_string(&proof_spec).unwrap();

    let verify_timer = std::time::Instant::now();
    let ret: bool = show_proof.show_groth16.verify(&vp.vk, &vp.pvk, Some(context_str.as_bytes()), &io_types, &inputs);
    if !ret {
        println!("show_groth16.verify failed");
        return (false, "".to_string());
    }
    let cur_time = Fr::from(show_proof.cur_time);
    let now_seconds = utc_now_seconds();
    let delta = now_seconds.saturating_sub(show_proof.cur_time);
    println!("Proof created {} seconds ago", delta);    

    if delta > SHOW_PROOF_VALIDITY_SECONDS {
        println!("Invalid show proof -- older than {} seconds", SHOW_PROOF_VALIDITY_SECONDS);
        return (false, "".to_string());
    }  

    let mut ped_com_valid_until_value = show_proof.show_groth16.commited_inputs[0];
    ped_com_valid_until_value -= vp.pvk.vk.gamma_abc_g1[valid_until_value_pos] * cur_time;
    let ret = show_proof.show_range_exp.verify(
        &ped_com_valid_until_value,
        RANGE_PROOF_INTERVAL_BITS,
        &vp.range_vk,
        &io_locations,
        &vp.pvk,
        "valid_until_value",
    );
    if !ret {
        println!("show_range_exp.verify failed");
        return (false, "".to_string());
    }      

    for (i, show_range_attr) in show_proof.show_range_attr.iter().enumerate() {
        let commitment_index = i + 1; // skip the first one (validUntil)
        let attr_name = &proof_spec.range_over_year[i].0;
        let attr_label = format!("{}_value", &attr_name);
        let age = proof_spec.range_over_year[i].1;
        let days_in_age = Fr::from(days_to_be_age(age) as u64);
        let mut ped_com_attr_value = show_proof.show_groth16.commited_inputs[commitment_index];
        let io_pos = match io_locations.get_io_location(&attr_label) {
            Ok(loc) => loc,
            Err(_) => {
                println!("Asked to prove range for attribute {}, but did not find it in io_locations", attr_name);
                return (false, "".to_string());
            }
        };
        ped_com_attr_value -= vp.pvk.vk.gamma_abc_g1[io_pos] * days_in_age;

        let ret = show_range_attr.verify(
            &ped_com_attr_value,
            RANGE_PROOF_INTERVAL_BITS,
            &vp.range_vk,
            &io_locations,
            &vp.pvk,
            &attr_label,
        );
        if !ret {
            println!("show_range_attr.verify failed");
            return (false, "".to_string());
        }
        println!("range proof for {} over {} succeeded", attr_name, age);
    }

    if proof_spec.device_bound {
        // TODO
    }

    println!("Verification time: {:?}", verify_timer.elapsed());  

    // Add the revealed attributes to the output, after converting from field element to string
    let mut revealed = serde_json::Map::<String, Value>::new();
    for (revealed_idx, attr_name) in proof_spec.revealed.iter().enumerate() {
        let attr_name_label = attr_name.clone() + "_value";
        let unpacked = unpack_int_to_string_unquoted( &show_proof.revealed_inputs[revealed_idx].into_bigint());
        if unpacked.is_err() {
            println!("Error: Proof was valid, but failed to unpack '{}' attribute, {:?}", attr_name_label, unpacked.err().unwrap());
            return (false, "".to_string());
        }
        let attr_value = &unpacked.unwrap().clone();
        revealed.insert(attr_name_label.clone(), json!(attr_value));
    }

    // Add the hashed revealed attributes to the output
    // TODO

    (true, serde_json::to_string(&revealed).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{device::TestDevice, prep_inputs::{parse_config, prepare_prover_inputs}};
    use serial_test::serial;

    // We run the end-to-end tests with [serial] because they use a lot of memory, 
    // if two are run at the same time some machines do not have enough RAM

    #[test]
    #[serial]
    pub fn end_to_end_test_rs256_sd() {
        run_test("rs256-sd", "jwt");
    }
    #[test]
    #[serial]
    pub fn end_to_end_test_rs256_db() {
        run_test("rs256-db", "jwt");
    }

    #[test]
    #[serial]
    pub fn end_to_end_test_mdl1() {
        run_test("mdl1", "mdl");
    }

    fn run_test(name: &str, cred_type: &str) {
        let base_path = PathBuf::from(format!("test-vectors/{}", name));
        let paths = CachePaths::new(base_path.clone());

        println!("Runing end-to-end-test for {}, credential type {}", name, cred_type);
        println!("Requires that `../setup/run_setup.sh {}` has already been run", name);
        println!("These tests are slow; best run with the `--release` flag"); 

        println!("Running zksetup");
        let ret = run_zksetup(base_path);
        assert!(ret == 0);

        println!("Running prove (creating client state)");
        let config_str = fs::read_to_string(&paths.config).unwrap_or_else(|_| panic!("Unable to read config from {} ", paths.config));
        let config = parse_config(&config_str).expect("Failed to parse config");
    
        let (prover_inputs, prover_aux) = 
        if cred_type == "mdl" {
            (GenericInputsJSON::new(&paths.mdl_prover_inputs), None)
        }
        else {
            let jwt = fs::read_to_string(&paths.jwt).unwrap_or_else(|_| panic!("Unable to read JWT file from {}", paths.jwt));
            let issuer_pem = fs::read_to_string(&paths.issuer_pem).unwrap_or_else(|_| panic!("Unable to read issuer public key PEM from {} ", paths.issuer_pem));   
            let device_pub_pem = fs::read_to_string(&paths.device_pub_pem).ok();
            let (prover_inputs_json, prover_aux_json, _public_ios_json) = 
                prepare_prover_inputs(&config, &jwt, &issuer_pem, device_pub_pem.as_deref()).expect("Failed to prepare prover inputs");    
            (GenericInputsJSON{prover_inputs: prover_inputs_json}, Some(json!(prover_aux_json).to_string()))
        };
            
        let client_state = create_client_state(&paths, &prover_inputs, prover_aux.as_ref(), cred_type).unwrap();
        // We read and write the client state and proof to disk for testing, to be consistent with the command-line tool
        write_to_file(&client_state, &paths.client_state);
        let mut client_state: ClientState<CrescentPairing> = read_from_file(&paths.client_state).unwrap();

        println!("Running show");
        let pm = "some presentation message".to_string();
        let io_locations = IOLocations::new(&paths.io_locations);    
        let range_pk : RangeProofPK<CrescentPairing> = read_from_file(&paths.range_pk).unwrap();
        assert!(PathBuf::from(&paths.proof_spec).exists());
        let ps_raw = fs::read_to_string(&paths.proof_spec).expect("Proof spec file exists, but failed while reading it");
        let mut proof_spec : ProofSpec = serde_json::from_str(&ps_raw).unwrap();
        proof_spec.presentation_message = Some(pm.as_bytes().to_vec());
        let proof = if cred_type == "mdl" {
            create_show_proof_mdl(&mut client_state, &range_pk, &proof_spec, &io_locations)
        } else {
            let device_signature = 
            if proof_spec.device_bound.is_some() && proof_spec.device_bound.unwrap() {
                let device = TestDevice::new_from_file(&paths.device_prv_pem);
                Some(device.sign(proof_spec.presentation_message.as_ref().unwrap()))
            } else {
                None
            };

            create_show_proof(&mut client_state, &range_pk, &io_locations, &proof_spec, device_signature)
        };
        assert!(proof.is_ok());
        let show_proof = proof.unwrap();

        write_to_file(&show_proof, &paths.show_proof);
        let show_proof : ShowProof<CrescentPairing> = read_from_file(&paths.show_proof).unwrap();

        print!("Running verify");
        let pvk : PreparedVerifyingKey<CrescentPairing> = read_from_file(&paths.groth16_pvk).unwrap();
        let vk : VerifyingKey<CrescentPairing> = read_from_file(&paths.groth16_vk).unwrap();
        let range_vk : RangeProofVK<CrescentPairing> = read_from_file(&paths.range_vk).unwrap();
        let io_locations_str = std::fs::read_to_string(&paths.io_locations).unwrap();
        let issuer_pem = std::fs::read_to_string(&paths.issuer_pem).unwrap();
    
        let vp = VerifierParams{vk, pvk, range_vk, io_locations_str, issuer_pem, config_str: config_str.clone()};
        assert!(PathBuf::from(&paths.proof_spec).exists());
        let ps_raw = fs::read_to_string(&paths.proof_spec).expect("Proof spec file exists, but failed while reading it");
        let mut proof_spec : ProofSpec = serde_json::from_str(&ps_raw).unwrap();
        proof_spec.presentation_message = Some(pm.as_bytes().to_vec());
        let (verify_result, _data) = if cred_type == "mdl" {
            verify_show_mdl(&vp, &show_proof, &proof_spec)
        } else {
            verify_show(&vp, &show_proof, &proof_spec)
        };
        assert!(verify_result);
    }

}
