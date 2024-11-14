// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::{fs, path::PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use ark_bn254::{Bn254 as ECPairing, Fr};
use ark_circom::{CircomBuilder, CircomConfig};
use ark_crypto_primitives::snark::SNARK;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_groth16::{Groth16, PreparedVerifyingKey, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{end_timer, rand::thread_rng, start_timer};
use groth16rand::{ShowGroth16, ShowRange};
use prep_inputs::{parse_config, unpack_int_to_string_unquoted, prepare_prover_inputs};
use utils::{read_from_file, write_to_file};
use crate::rangeproof::{RangeProofPK, RangeProofVK};
use crate::structs::{PublicIOType, IOLocations};
use crate::{
    groth16rand::ClientState,
    structs::{GenericInputsJSON, ProverInput},
};
use crate::daystamp::days_to_be_age;

pub mod dlog;
pub mod groth16rand;
pub mod rangeproof;
pub mod structs;
pub mod utils;
pub mod prep_inputs;
pub mod daystamp;

const RANGE_PROOF_INTERVAL_BITS: usize = 32;
const SHOW_PROOF_VALIDITY_SECONDS: u64 = 300;    // The verifier only accepts proofs fresher than this
const MDL_AGE_GREATER_THAN : usize = 18;         // mDL show proofs will prove that the holder is older than this value (in years)

pub type CrescentPairing = ECPairing;


/// Parameters required to create Groth16 proofs
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProverParams<E: Pairing> {
    pub groth16_params : ProvingKey<E>,
    pub groth16_pvk : PreparedVerifyingKey<E>,
    pub config_str : String
}
impl<E: Pairing> ProverParams<E> {
    pub fn new(paths : &CachePaths) -> Result<Self, SerializationError> {
        let groth16_params : ProvingKey<E> = read_from_file(&paths.groth16_params)?;
        let groth16_pvk : PreparedVerifyingKey<E> = read_from_file(&paths.groth16_pvk)?;
        let config_str = fs::read_to_string(&paths.config)?;
        Ok(Self{groth16_params, groth16_pvk, config_str})
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
    vk : VerifyingKey<E>,
    pvk : PreparedVerifyingKey<E>,
    range_vk: RangeProofVK<E>,
    io_locations_str: String // Stored as String since IOLocations does not implement CanonicalSerialize
}
impl<E: Pairing> VerifierParams<E> {
    pub fn new(paths : &CachePaths) -> Result<Self, SerializationError> {
        let pvk : PreparedVerifyingKey<E> = read_from_file(&paths.groth16_pvk)?;
        let vk : VerifyingKey<E> = read_from_file(&paths.groth16_vk)?;
        let range_vk : RangeProofVK<E> = read_from_file(&paths.range_vk)?;
        let io_locations_str = std::fs::read_to_string(&paths.io_locations)?;
        Ok(Self{vk, pvk, range_vk, io_locations_str})
    }
}

/// Structure to hold all the parts of a show/presentation proof
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ShowProof<E: Pairing> {
    pub show_groth16: ShowGroth16<E>,
    pub show_range: ShowRange<E>,
    pub show_range2: Option<ShowRange<E>>, 
    pub revealed_inputs: Vec<E::ScalarField>, 
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
   pub groth16_params: String,
   pub prover_params: String,   
   pub client_state: String, 
   pub show_proof: String,
   pub mdl_prover_inputs: String
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
        print!("base_path_str = {}\n", base_path_str);
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
            groth16_params: format!("{}groth16_params.bin", &cache_path),
            prover_params: format!("{}prover_params.bin", &cache_path),
            client_state: format!("{}client_state.bin", &cache_path),
            show_proof: format!("{}show_proof.bin", &cache_path),
            mdl_prover_inputs: format!("{}prover_inputs.json", &base_path_str),
        }             
    }
}

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
    write_to_file(&params, &paths.groth16_params);
    write_to_file(&vk, &paths.groth16_vk);
    write_to_file(&pvk, &paths.groth16_pvk);

    let config_str = fs::read_to_string(&paths.config).expect(&format!("Unable to read config from {} ", paths.config));
    let prover_params = ProverParams{groth16_params: params, groth16_pvk: pvk, config_str};
    write_to_file(&prover_params, &paths.prover_params);    
    end_timer!(serialize_timer);

    return 0;
}

pub fn create_client_state(paths : &CachePaths, prover_inputs: &GenericInputsJSON) -> Result<ClientState<ECPairing>, SerializationError>
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

    let load_params_timer = start_timer!(||"Reading Groth16 params from file");
    let params : ProvingKey<ECPairing> = read_from_file(&paths.groth16_params)?;
    end_timer!(load_params_timer);
    
    let build_timer = start_timer!(|| "Witness Generation");
    let circom = builder.build().unwrap();
    end_timer!(build_timer);    
    let inputs = circom.get_public_inputs().unwrap();

    let mut rng = thread_rng();
    let prove_timer = start_timer!(|| "Groth16 prove");    
    let proof = Groth16::<ECPairing>::prove(&params, circom, &mut rng).unwrap();    
    end_timer!(prove_timer);

    let pvk : PreparedVerifyingKey<ECPairing> = read_from_file(&paths.groth16_pvk)?;
    let verify_timer = start_timer!(|| "Groth16 verify");
    let verified =
        Groth16::<ECPairing>::verify_with_processed_vk(&pvk, &inputs, &proof).unwrap();
    assert!(verified);
    end_timer!(verify_timer);

    let client_state = ClientState::<ECPairing>::new(
        inputs.clone(),
        proof.clone(),
        params.vk.clone(),
        pvk.clone(),
    );

    Ok(client_state)
}

pub fn run_prover(
    base_path: PathBuf,
) {
    let paths = CachePaths::new(base_path);
    let config_str = fs::read_to_string(&paths.config).expect(&format!("Unable to read config from {} ", paths.config));
    let config = parse_config(config_str).expect("Failed to parse config");

    let prover_inputs = 
    if config.contains_key("credtype") && config.get("credtype").unwrap() == "mdl" {
        GenericInputsJSON::new(&paths.mdl_prover_inputs)
    }
    else {
        let jwt = fs::read_to_string(&paths.jwt).expect(&format!("Unable to read JWT file from {}", paths.jwt));
        let issuer_pem = fs::read_to_string(&paths.issuer_pem).expect(&format!("Unable to read issuer public key PEM from {} ", paths.issuer_pem));   
        let (prover_inputs_json, _prover_aux_json, _public_ios_json) = 
            prepare_prover_inputs(&config, &jwt, &issuer_pem).expect("Failed to prepare prover inputs");    
        GenericInputsJSON{prover_inputs: prover_inputs_json}
    };
        
    let mut client_state = create_client_state(&paths, &prover_inputs).unwrap();

    if config.contains_key("credtype") && config.get("credtype").unwrap() == "mdl" {
        client_state.credtype = "mdl".to_string();
        println!("Set credtype to mdl");
    }

    write_to_file(&client_state, &paths.client_state);

}


pub fn create_show_proof(client_state: &mut ClientState<ECPairing>, range_pk : &RangeProofPK<ECPairing>, io_locations: &IOLocations) -> ShowProof<ECPairing>
{

    // Create Groth16 rerandomized proof for showing
    let exp_value_pos = io_locations.get_io_location("exp_value").unwrap();
    let email_value_pos = io_locations.get_io_location("email_value").unwrap();
    // The IOs are exp, email_domain and the 17 limbs of the RSA modulus. We make them revealed
    // TODO: don't add the modulus to revealed inputs, the verifier should know it. Maybe just a key identifier    
    // TODO: seems error-prone to do this by hand; make a function to reveal 
    // by name e.g, set_revealed("modulus")
    let mut io_types = vec![PublicIOType::Revealed; client_state.inputs.len()];
    io_types[exp_value_pos - 1] = PublicIOType::Committed;
    io_types[email_value_pos -1] = PublicIOType::Revealed;
    let mut revealed_inputs = client_state.inputs.clone();
    revealed_inputs.remove(exp_value_pos - 1);  
    let show_groth16 = client_state.show_groth16(&io_types);
    
    // Create fresh range proof 
    let time_sec = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap()
    .as_secs();
    let cur_time = Fr::from( time_sec );

    let mut com_exp_value = client_state.committed_input_openings[0].clone();
    com_exp_value.m -= cur_time;
    com_exp_value.c -= com_exp_value.bases[0] * cur_time;
    let show_range = client_state.show_range(&com_exp_value, RANGE_PROOF_INTERVAL_BITS, &range_pk);

    // Assemble proof
    let show_proof = ShowProof{ show_groth16, show_range, show_range2: None, revealed_inputs, inputs_len: client_state.inputs.len(), cur_time: time_sec};

    show_proof
}

pub fn create_show_proof_mdl(client_state: &mut ClientState<ECPairing>, range_pk : &RangeProofPK<ECPairing>, io_locations: &IOLocations, age: usize) -> ShowProof<ECPairing>
{
    // Create Groth16 rerandomized proof for showing
    let valid_until_value_pos = io_locations.get_io_location("valid_until_value").unwrap();
    let dob_value_pos = io_locations.get_io_location("dob_value").unwrap();
    
    let mut io_types = vec![PublicIOType::Revealed; client_state.inputs.len()];
    io_types[valid_until_value_pos - 1] = PublicIOType::Committed;
    io_types[dob_value_pos - 1] = PublicIOType::Committed;
    let mut revealed_inputs = client_state.inputs.clone();
    revealed_inputs.remove(valid_until_value_pos - 1);
    revealed_inputs.remove(dob_value_pos - 2);  // minus 2 because there's one less after removing valid_until_value
    let show_groth16 = client_state.show_groth16(&io_types);    
    
    // Create fresh range proof for validUntil
    let time_sec = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap()
    .as_secs();
    let cur_time = Fr::from( time_sec );

    let mut com_valid_until_value = client_state.committed_input_openings[0].clone();
    com_valid_until_value.m -= cur_time;
    com_valid_until_value.c -= com_valid_until_value.bases[0] * cur_time;
    let show_range = client_state.show_range(&com_valid_until_value, RANGE_PROOF_INTERVAL_BITS, &range_pk);

    // Create fresh range proof for birth_date; prove age is over 21
    let days_in_21y = Fr::from(days_to_be_age(age) as u64);
    let mut com_dob = client_state.committed_input_openings[1].clone();
    com_dob.m -= days_in_21y;
    com_dob.c -= com_dob.bases[0] * days_in_21y;
    let show_range2 = client_state.show_range(&com_dob, RANGE_PROOF_INTERVAL_BITS, &range_pk);       

    // Asssemble proof and return
    let show_proof = ShowProof{ show_groth16, show_range, show_range2: Some(show_range2), revealed_inputs, inputs_len: client_state.inputs.len(), cur_time: time_sec};

    show_proof
}

fn _show_groth16_proof_size(show_groth16: &ShowGroth16<ECPairing>) -> usize {
    print!("Show_Groth16 proof size: ");
    let rand_proof_size = show_groth16.rand_proof.compressed_size();
    print!("{} (rand_proof) + ", rand_proof_size);
    let com_hidden_inputs_size = show_groth16.com_hidden_inputs.compressed_size();
    print!("{} (com_hidden_inputs) + ", com_hidden_inputs_size);
    let pok_inputs_size = show_groth16.pok_inputs.compressed_size();
    print!("{} (pok_inputs) + ", pok_inputs_size);
    let committed_inputs_size = show_groth16.commited_inputs.compressed_size();
    print!("{} (committed_inputs) ", committed_inputs_size);
    let total = rand_proof_size + com_hidden_inputs_size + pok_inputs_size + committed_inputs_size;
    println!(" = {} bytes total", total);
    total
}


fn show_proof_size(show_proof: &ShowProof<ECPairing>) -> usize {

    print!("Show proof size: ");
    let groth16_size = show_proof.show_groth16.compressed_size();
    print!("{} (Groth16 proof) + ", groth16_size);
    let show_range_size = show_proof.show_range.compressed_size();
    print!("{} (range proof) ", show_range_size);

    let show_range2_size = 
    if show_proof.show_range2.is_some() {
        let tmp = show_proof.show_range2.compressed_size();
        print!("{} + (range proof2) ", tmp);        
        tmp
    } else {
        0
    };

    let total = groth16_size + show_range_size + show_range2_size;
    println!(" = {} bytes total", total);

    total
}

pub fn run_show(
    base_path: PathBuf
) {
    let proof_timer = std::time::Instant::now();    
    let paths = CachePaths::new(base_path);
    let io_locations = IOLocations::new(&paths.io_locations);    
    let mut client_state: ClientState<ECPairing> = read_from_file(&paths.client_state).unwrap();
    let range_pk : RangeProofPK<ECPairing> = read_from_file(&paths.range_pk).unwrap();
    
    let show_proof = if client_state.credtype == "mdl" {
        create_show_proof_mdl(&mut client_state, &range_pk, &io_locations, MDL_AGE_GREATER_THAN)  
    } else {
        create_show_proof(&mut client_state, &range_pk, &io_locations)
    };
    println!("Proving time: {:?}", proof_timer.elapsed());

    //let _ = show_groth16_proof_size(&show_proof.show_groth16);
    let _ = show_proof_size(&show_proof);

    write_to_file(&show_proof, &paths.show_proof);
}

pub fn verify_show(vp : &VerifierParams<ECPairing>, show_proof: &ShowProof<ECPairing>) -> (bool, String)
{
    let io_locations = IOLocations::new_from_str(&vp.io_locations_str);
    let exp_value_pos = io_locations.get_io_location("exp_value").unwrap();
    let email_value_pos = io_locations.get_io_location("email_value").unwrap();
    let mut io_types = vec![PublicIOType::Revealed; show_proof.inputs_len];
    io_types[exp_value_pos - 1] = PublicIOType::Committed;
    io_types[email_value_pos - 1] = PublicIOType::Revealed;

    // println!("Verifier got revealed inputs: {:?}", &show_proof.revealed_inputs);
    // for (i, input) in show_proof.revealed_inputs.clone().into_iter().enumerate() {
    //     println!("input {} =  {:?}", i, input.into_bigint().to_string());
    // }

    let verify_timer = std::time::Instant::now();
    let ret = show_proof.show_groth16.verify(&vp.vk, &vp.pvk, &io_types, &show_proof.revealed_inputs);
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

    let mut ped_com_exp_value = show_proof.show_groth16.commited_inputs[0].clone();
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

    // TODO: it's currently hacky how the verifier knows which revealed inputs correspond 
    // to what.  In this example we have to subtract 2 (rather than 1) from email_value pos to account for
    // the committed attribute.  When we refactor revealed inputs and the modulus IOs we can address this.
    let domain = match unpack_int_to_string_unquoted( &show_proof.revealed_inputs[email_value_pos - 2].into_bigint()) {
        Ok(domain) => domain,
        Err(e) => {
            println!("Proof was valid, but failed to unpack domain string, {:?}", e);
            return (false, "".to_string());
        }
    };
    println!("Token is valid, Prover revealed email domain: {}", domain);

    (true, domain)
}

pub fn verify_show_mdl(vp : &VerifierParams<ECPairing>, show_proof: &ShowProof<ECPairing>, age: usize) -> (bool, String)
{
    let io_locations = IOLocations::new_from_str(&vp.io_locations_str);
    // TODO: load public_IOs file and take modulus from there.  
    // Or maybe the verifier should work directly from the issuer's public key?

    let valid_until_value_pos = io_locations.get_io_location("valid_until_value").unwrap();
    let dob_value_pos = io_locations.get_io_location("dob_value").unwrap();
    let mut io_types = vec![PublicIOType::Revealed; show_proof.inputs_len];
    io_types[valid_until_value_pos - 1] = PublicIOType::Committed;
    io_types[dob_value_pos - 1] = PublicIOType::Committed;
    

    // println!("Verifier got revealed inputs: {:?}", &show_proof.revealed_inputs);
    // for (i, input) in show_proof.revealed_inputs.clone().into_iter().enumerate() {
    //     println!("input {} =  {:?}", i, input.into_bigint().to_string());
    // }

    let verify_timer = std::time::Instant::now();
    show_proof.show_groth16.verify(&vp.vk, &vp.pvk, &io_types, &show_proof.revealed_inputs);
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

    let mut ped_com_valid_until_value = show_proof.show_groth16.commited_inputs[0].clone();
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

    if !show_proof.show_range2.is_some() {
        println!("mDL proof is invalid; missing second range proof");
        return (false, "".to_string());
    }
    let days_in_21y = Fr::from(days_to_be_age(age) as u64);
    let mut ped_com_dob = show_proof.show_groth16.commited_inputs[1].clone();
    ped_com_dob -= vp.pvk.vk.gamma_abc_g1[dob_value_pos] * days_in_21y;
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

pub fn run_verifier(base_path: PathBuf) {
    let paths = CachePaths::new(base_path);
    let show_proof : ShowProof<ECPairing> = read_from_file(&paths.show_proof).unwrap();
    let pvk : PreparedVerifyingKey<ECPairing> = read_from_file(&paths.groth16_pvk).unwrap();
    let vk : VerifyingKey<ECPairing> = read_from_file(&paths.groth16_vk).unwrap();
    let range_vk : RangeProofVK<ECPairing> = read_from_file(&paths.range_vk).unwrap();
    let io_locations_str = std::fs::read_to_string(&paths.io_locations).unwrap();
    // TODO: load public_IOs file and take modulus from there.  
    // Or maybe the verifier should work directly from the issuer's public key?

    let vp = VerifierParams{vk, pvk, range_vk, io_locations_str};

    let (verify_result, data) = if show_proof.show_range2.is_some() {
        verify_show_mdl(&vp, &show_proof, MDL_AGE_GREATER_THAN)
    } else {
        verify_show(&vp, &show_proof)
    };

    if verify_result {
        println!("Verify succeeded, got data '{}'", data);
    }
    else {
        println!("Verify failed")
    }

}
