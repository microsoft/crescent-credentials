// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::daystamp::days_to_be_age;
#[cfg(not(feature = "wasm"))]
use {
    ark_circom::{CircomBuilder, CircomConfig},
    crate::structs::ProverInput,
};
use std::{fs, path::PathBuf, error::Error};
use std::time::{SystemTime, UNIX_EPOCH};>>>>>>> origin/fix_rand-core_build_errors
use ark_bn254::{Bn254 as ECPairing, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_groth16::{Groth16, PreparedVerifyingKey, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{end_timer, rand::thread_rng, start_timer};
use groth16rand::{ShowGroth16, ShowRange};
use prep_inputs::{create_proof_spec_internal, pem_to_inputs, unpack_int_to_string_unquoted};
use serde::{Deserialize, Serialize};
use serde_json::{json,Value};
use sha2::{Digest, Sha256};
use utils::{read_from_file, strip_quotes, write_to_file};
use crate::rangeproof::{RangeProofPK, RangeProofVK};
use crate::structs::{PublicIOType, IOLocations};
use crate::{
    groth16rand::ClientState,
    structs::{GenericInputsJSON},
};
#[cfg(feature = "wasm")]
use {
    wasm_bindgen::prelude::wasm_bindgen,
    utils::write_to_b64url,
}

pub mod daystamp;
pub mod dlog;
pub mod groth16rand;
pub mod prep_inputs;
pub mod rangeproof;
pub mod structs;
pub mod utils;

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
// of attributes as field elements or hashed values.  Will likely be extended in the future to support other predicates.
// The range proof that "exp" is in the future is always done.
#[derive(Serialize, Deserialize)]
pub struct ProofSpec {
    pub revealed: Vec<String>,
    pub presentation_message: Option<String>,
}
#[derive(Serialize)]
pub(crate) struct ProofSpecInternal {
    pub revealed: Vec<String>,
    pub hashed: Vec<String>, 
    pub presentation_message : Option<Vec<u8>>,
    pub config_str: String
}

/// Structure to hold all the parts of a show/presentation proof
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ShowProof<E: Pairing> {
    pub show_groth16: ShowGroth16<E>,
    pub show_range: ShowRange<E>,
    pub show_range2: Option<ShowRange<E>>, 
    pub revealed_inputs: Vec<E::ScalarField>, 
    pub revealed_preimages: Option<String>,
    pub inputs_len: usize, 
    pub cur_time: u64
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
   pub proof_spec: String
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


#[cfg(feature = "wasm")]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
extern "C" {
    fn js_timestamp() -> u64;
}

#[cfg(feature = "wasm")]
pub fn disc_uid_to_age(disc_uid : &str) -> Result<usize, &'static str> {
    match disc_uid {
        "crescent://over_18" => Ok(18),
        "crescent://over_21" => Ok(21),
        "crescent://over_65" => Ok(65),
        _ => Err("disc_uid_to_age: invalid disclosure uid"),
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn create_show_proof_wasm(
    client_state_bytes: Vec<u8>,
    range_pk_bytes: Vec<u8>,
    io_locations_str: String,
    disc_uid: String,
) -> String {
    if client_state_bytes.is_empty() {
        return "Error: Received empty client_state_bytes".to_string();
    }
    if range_pk_bytes.is_empty() {
        return "Error: Received empty range_pk_bytes".to_string();
    }
    if disc_uid.is_empty() {
        return "Error: Received empty disc_uid".to_string();
    }
    if io_locations_str.is_empty() {
        return "Error: Received empty io_locations_str".to_string();
    }

    let client_state_result = ClientState::<ECPairing>::deserialize_uncompressed(&client_state_bytes[..]);
    let range_pk_result = RangeProofPK::<ECPairing>::deserialize_uncompressed(&range_pk_bytes[..]);
    let io_locations = IOLocations::new_from_str(&io_locations_str);

    match (client_state_result, range_pk_result) {
        (Ok(mut client_state), Ok(range_pk)) => {
            let msg = "Successfully deserialized client state and range pk".to_string();            

            let show_proof = 
            if &client_state.credtype == "mdl" {
                let age = disc_uid_to_age(&disc_uid).map_err(|_| "Disclosure UID does not have associated age parameter".to_string());
                create_show_proof_mdl(&mut client_state, &range_pk, None, &io_locations, age.expect("Age not valid."))
            }
            else {
                create_show_proof(&mut client_state, &range_pk, None, &io_locations)     
            };

            let show_proof_b64 = write_to_b64url(&show_proof);
            let msg = format!("show_proof_b64: {:?}", show_proof_b64);
            msg
        }
        (Err(e), _) => {
            let msg = format!("Error: Failed to deserialize client state: {:?}", e);
            msg
        }
        (_, Err(e)) => {
            let msg = format!("Error: Failed to deserialize range pk: {:?}", e);
            msg
        }
    }

}

pub fn create_show_proof(client_state: &mut ClientState<ECPairing>, range_pk : &RangeProofPK<ECPairing>, io_locations: &IOLocations, proof_spec: &ProofSpec) -> Result<ShowProof<ECPairing>, Box<dyn Error>>
{
    // Create Groth16 rerandomized proof for showing
    let exp_value_pos = io_locations.get_io_location("exp_value").unwrap();
    // The IOs are exp, email, family_name, given_name, tenant_ctry, tenant_region_scope.  Hidden by default
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

    // Serialize the proof spec as the context
    let context_str = serde_json::to_string(&proof_spec).unwrap();
    let show_groth16 = client_state.show_groth16(Some(context_str.as_bytes()), &io_types);
    
    // Create fresh range proof 
    let time_sec; 

    #[cfg(feature = "wasm")]
    {
        time_sec = js_timestamp();
    }
    #[cfg(not(feature = "wasm"))]
    {
        time_sec = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap()
    .as_secs();
    }
    let cur_time = Fr::from( time_sec );

    let mut com_exp_value = client_state.committed_input_openings[0].clone();
    com_exp_value.m -= cur_time;
    com_exp_value.c -= com_exp_value.bases[0] * cur_time;
    let show_range = client_state.show_range(&com_exp_value, RANGE_PROOF_INTERVAL_BITS, range_pk);

    // Assemble proof
    let revealed_preimages = if proof_spec.hashed.is_empty() { 
        assert!(revealed_preimages.is_empty());
        None 
    } else {
        Some(serde_json::to_string(&revealed_preimages).unwrap())
    };
    Ok(ShowProof{ show_groth16, show_range, show_range2: None, revealed_inputs, revealed_preimages, inputs_len: client_state.inputs.len(), cur_time: time_sec})
}

pub fn create_show_proof_mdl(client_state: &mut ClientState<ECPairing>, range_pk : &RangeProofPK<ECPairing>, pm: Option<&[u8]>, io_locations: &IOLocations, age: usize) -> ShowProof<ECPairing>
{
    // Create Groth16 rerandomized proof for showing
    let valid_until_value_pos = io_locations.get_io_location("valid_until_value").unwrap();
    let dob_value_pos = io_locations.get_io_location("dob_value").unwrap();
    
    let mut io_types = vec![PublicIOType::Revealed; client_state.inputs.len()];
    io_types[valid_until_value_pos - 1] = PublicIOType::Committed;
    io_types[dob_value_pos - 1] = PublicIOType::Committed;

    let revealed_inputs : Vec<<ECPairing as Pairing>::ScalarField> = vec![];

    let show_groth16 = client_state.show_groth16(pm, &io_types);    
    
    // Create fresh range proof for validUntil
    let time_sec; 
    #[cfg(feature = "wasm")]
    {
        time_sec = js_timestamp();
    }
    #[cfg(not(feature = "wasm"))]
    {
        time_sec = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap()
    .as_secs();
    }
    let cur_time = Fr::from(time_sec);

    let mut com_valid_until_value = client_state.committed_input_openings[0].clone();
    com_valid_until_value.m -= cur_time;
    com_valid_until_value.c -= com_valid_until_value.bases[0] * cur_time;
    let show_range = client_state.show_range(&com_valid_until_value, RANGE_PROOF_INTERVAL_BITS, range_pk);

    // Create fresh range proof for birth_date; prove age is over 21
    let days_in_21y = Fr::from(days_to_be_age(age) as u64);
    let mut com_dob = client_state.committed_input_openings[1].clone();
    com_dob.m -= days_in_21y;
    com_dob.c -= com_dob.bases[0] * days_in_21y;
    let show_range2 = client_state.show_range(&com_dob, RANGE_PROOF_INTERVAL_BITS, range_pk);       

    // Assemble proof and return
    ShowProof{ show_groth16, show_range, show_range2: Some(show_range2), revealed_inputs, revealed_preimages: None, inputs_len: client_state.inputs.len(), cur_time: time_sec}
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
    
    // println!("Verifier got revealed inputs  : {:?}", &show_proof.revealed_inputs);
    // println!("Created inputs: ");
    // for (i, input) in inputs.clone().into_iter().enumerate() {
    //     println!("input {}  =  {:?}", i, input.into_bigint().to_string());
    // }
    
    let context_str = serde_json::to_string(&proof_spec).unwrap();

    let verify_timer = std::time::Instant::now();
    let ret = show_proof.show_groth16.verify(&vp.vk, &vp.pvk, Some(context_str.as_bytes()), &io_types, &inputs);
    if !ret {
        println!("show_groth16.verify failed");
        return (false, "".to_string());
    }
    let cur_time = Fr::from(show_proof.cur_time);
    let now_seconds = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let delta = 
        if show_proof.cur_time < now_seconds {
            now_seconds - show_proof.cur_time
        } else {
            0
    };
    println!("Proof created {} seconds ago", delta);    

    if delta > SHOW_PROOF_VALIDITY_SECONDS {
        println!("Invalid show proof -- older than {} seconds", SHOW_PROOF_VALIDITY_SECONDS);
        return (false, "".to_string());
    }

    let mut ped_com_exp_value = show_proof.show_groth16.commited_inputs[0];
    ped_com_exp_value -= vp.pvk.vk.gamma_abc_g1[exp_value_pos] * cur_time;
    let ret = show_proof.show_range.verify(
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

pub fn verify_show_mdl(vp : &VerifierParams<ECPairing>, show_proof: &ShowProof<ECPairing>, pm: Option<&[u8]>, age: usize) -> (bool, String)
{
    let io_locations = IOLocations::new_from_str(&vp.io_locations_str);
    let valid_until_value_pos = io_locations.get_io_location("valid_until_value").unwrap();
    let dob_value_pos = io_locations.get_io_location("dob_value").unwrap();
    let mut io_types = vec![PublicIOType::Revealed; show_proof.inputs_len];
    io_types[valid_until_value_pos - 1] = PublicIOType::Committed;
    io_types[dob_value_pos - 1] = PublicIOType::Committed;

    // Create an inputs vector with the inputs from the prover, and the issuer's public key
    let public_key_inputs = pem_to_inputs::<<ECPairing as Pairing>::ScalarField>(&vp.issuer_pem);
    if public_key_inputs.is_err() {
        print!("Error: Failed to convert issuer public key to input values");
        return (false, "".to_string());
    }
    let mut inputs = public_key_inputs.unwrap();
    inputs.extend(show_proof.revealed_inputs.clone());     
    

    // println!("Verifier got revealed inputs: {:?}", &show_proof.revealed_inputs);
    // println!("Created inputs:");
    // for (i, input) in inputs.clone().into_iter().enumerate() {
    //     println!("input {} =  {:?}", i, input.into_bigint().to_string());
    // }

    let verify_timer = std::time::Instant::now();
    show_proof.show_groth16.verify(&vp.vk, &vp.pvk, pm, &io_types, &inputs);
    let ret = show_proof.show_groth16.verify(&vp.vk, &vp.pvk, pm, &io_types, &inputs);
    if !ret {
        println!("show_groth16.verify failed");
        return (false, "".to_string());
    }
    let cur_time = Fr::from(show_proof.cur_time);
    let now_seconds = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let delta = 
        if show_proof.cur_time < now_seconds {
            now_seconds - show_proof.cur_time
        } else {
            0
    };
    println!("Proof created {} seconds ago", delta);    

    if delta > SHOW_PROOF_VALIDITY_SECONDS {
        println!("Invalid show proof -- older than {} seconds", SHOW_PROOF_VALIDITY_SECONDS);
        return (false, "".to_string());
    }  

    let mut ped_com_valid_until_value = show_proof.show_groth16.commited_inputs[0];
    ped_com_valid_until_value -= vp.pvk.vk.gamma_abc_g1[valid_until_value_pos] * cur_time;
    let ret = show_proof.show_range.verify(
        &ped_com_valid_until_value,
        RANGE_PROOF_INTERVAL_BITS,
        &vp.range_vk,
        &io_locations,
        &vp.pvk,
        "valid_until_value",
    );
    if !ret {
        println!("show_range.verify failed");
        return (false, "".to_string());
    }      

    if show_proof.show_range2.is_none() {
        println!("mDL proof is invalid; missing second range proof");
        return (false, "".to_string());
    }
    let days_in_age = Fr::from(days_to_be_age(age) as u64);
    let mut ped_com_dob = show_proof.show_groth16.commited_inputs[1];
    ped_com_dob -= vp.pvk.vk.gamma_abc_g1[dob_value_pos] * days_in_age;
    let ret = show_proof.show_range2.as_ref().unwrap().verify(
        &ped_com_dob,
        RANGE_PROOF_INTERVAL_BITS,
        &vp.range_vk,
        &io_locations,
        &vp.pvk,
        "dob_value",
    );
    if !ret {
        println!("show_range2.verify failed");
        return (false, "".to_string());
    }      

    println!("Verification time: {:?}", verify_timer.elapsed());  

    println!("mDL is valid, holder is over {} years old", age);

    (true, "".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prep_inputs::{parse_config, prepare_prover_inputs};
    use serial_test::serial;

    const MDL_AGE_GT : usize = 18; 

    // We run the end-to-end tests with [serial] because they use a lot of memory, 
    // if two are run at the same time some machines do not have enough RAM

    #[test]
    #[serial]
    pub fn end_to_end_test_rs256() {
        run_test("rs256", "jwt");
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
    
        let prover_inputs = 
        if cred_type == "mdl" {
            GenericInputsJSON::new(&paths.mdl_prover_inputs)
        }
        else {
            let jwt = fs::read_to_string(&paths.jwt).unwrap_or_else(|_| panic!("Unable to read JWT file from {}", paths.jwt));
            let issuer_pem = fs::read_to_string(&paths.issuer_pem).unwrap_or_else(|_| panic!("Unable to read issuer public key PEM from {} ", paths.issuer_pem));   
            let (prover_inputs_json, _prover_aux_json, _public_ios_json) = 
                prepare_prover_inputs(&config, &jwt, &issuer_pem).expect("Failed to prepare prover inputs");    
            GenericInputsJSON{prover_inputs: prover_inputs_json}
        };
            
        let client_state = create_client_state(&paths, &prover_inputs, None, cred_type).unwrap();
        // We read and write the client state and proof to disk for testing, to be consistent with the command-line tool
        write_to_file(&client_state, &paths.client_state);
        let mut client_state: ClientState<CrescentPairing> = read_from_file(&paths.client_state).unwrap();

        println!("Running show");
        let pm = "some presentation message".to_string();
        let io_locations = IOLocations::new(&paths.io_locations);    
        let range_pk : RangeProofPK<CrescentPairing> = read_from_file(&paths.range_pk).unwrap();
        let show_proof = if client_state.credtype == "mdl" {
            create_show_proof_mdl(&mut client_state, &range_pk, Some(pm.as_bytes()), &io_locations, MDL_AGE_GT)  
        } else {
            let mut proof_spec: ProofSpec = serde_json::from_str(DEFAULT_PROOF_SPEC).unwrap();
            proof_spec.presentation_message = Some(pm.clone());
            let proof = create_show_proof(&mut client_state, &range_pk, &io_locations, &proof_spec);
            assert!(proof.is_ok());
            proof.unwrap()
        };

        write_to_file(&show_proof, &paths.show_proof);
        let show_proof : ShowProof<CrescentPairing> = read_from_file(&paths.show_proof).unwrap();

        print!("Running verify");
        let pvk : PreparedVerifyingKey<CrescentPairing> = read_from_file(&paths.groth16_pvk).unwrap();
        let vk : VerifyingKey<CrescentPairing> = read_from_file(&paths.groth16_vk).unwrap();
        let range_vk : RangeProofVK<CrescentPairing> = read_from_file(&paths.range_vk).unwrap();
        let io_locations_str = std::fs::read_to_string(&paths.io_locations).unwrap();
        let issuer_pem = std::fs::read_to_string(&paths.issuer_pem).unwrap();
    
        let vp = VerifierParams{vk, pvk, range_vk, io_locations_str, issuer_pem, config_str: config_str.clone()};
    
        let (verify_result, _data) = if show_proof.show_range2.is_some() {
            verify_show_mdl(&vp, &show_proof, Some(pm.as_bytes()), MDL_AGE_GT)
        } else {
            let mut proof_spec: ProofSpec = serde_json::from_str(DEFAULT_PROOF_SPEC).unwrap();
            proof_spec.presentation_message = Some(pm);
            verify_show(&vp, &show_proof, &proof_spec)
        };
        assert!(verify_result);
    }

}
