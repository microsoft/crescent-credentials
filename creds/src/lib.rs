#![allow(unused_variables, unused_imports)] // TODO: remove this 

use std::{env::current_dir, fs, path::PathBuf};
use ark_bn254::{Bn254 as ECPairing, Fr};
//use ark_bls12_381::Bls12_381 as ECPairing;
use ark_circom::{CircomBuilder, CircomConfig};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_std::io::BufWriter;
use ark_std::{end_timer, rand::thread_rng, start_timer};
use crate::rangeproof::RangeProofPK;
use crate::structs::{PublicIOType, IOLocations};
use crate::{
    groth16rand::ClientState,
    structs::{GenericInputsJSON, ProverInput},
};

use std::time::{SystemTime, UNIX_EPOCH};
use std::{
    env,
    fs::OpenOptions,
};
use std::error::Error;

pub mod dlog;
pub mod groth16rand;
pub mod rangeproof;
pub mod structs;
pub mod utils;


pub fn run_zksetup(base_path: PathBuf) -> i32 {

    let base_path_str = base_path.into_os_string().into_string().unwrap();
    let base_path_str = format!("{}/", base_path_str);
    if fs::metadata(&base_path_str).is_err() {
        println!("base_path = {}", base_path_str);
        return -1;  // TODO: use error types
    }
    print!("base_path_str = {}\n", base_path_str);

    let prover_inputs_path = format!("{}prover_inputs.json", base_path_str);
    let io_locations_path = format!("{}io_locations.sym", base_path_str);
    let wasm_path = format!("{}main.wasm", base_path_str);
    let r1cs_path = format!("{}main_c.r1cs", base_path_str);
    let cache_path = format!("{}/cache/", base_path_str);
    let groth16_params_file = format!("{}groth16_params.bin", &cache_path);

    if fs::metadata(&cache_path).is_ok() {
        println!("Found directory {} to store data", cache_path);
    } else {
        println!("Creating directory {} to store data", cache_path);
        fs::create_dir(&cache_path).unwrap();        
    }


    let io_locations = IOLocations::new(&io_locations_path);
    let prover_inputs = GenericInputsJSON::new(&prover_inputs_path);        

    let circom_timer = start_timer!(|| "Circom Reading");
    let cfg = CircomConfig::<ECPairing>::new(
        &wasm_path,
        &r1cs_path,
    )
    .unwrap();
    let mut builder = CircomBuilder::new(cfg);
    prover_inputs.push_inputs(&mut builder);

    let circom = builder.setup();
    end_timer!(circom_timer);

    let mut rng = thread_rng();
    let params =
        Groth16::<ECPairing>::generate_random_parameters_with_reduction(circom, &mut rng)
            .unwrap();

    let build_timer = start_timer!(|| "Building");
    let circom = builder.build().unwrap();
    end_timer!(build_timer);

    let f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(groth16_params_file)
        .unwrap();
    let buf_writer = BufWriter::new(f);
    params.serialize_uncompressed(buf_writer).unwrap();

    return 0;
}

pub fn run_prover(
    input_file: PathBuf,
    r1cs_file: PathBuf,
    pk_file: PathBuf,
    witness_generator_file: PathBuf,
    proof_file: PathBuf,
) {
    todo!("Not implemented");
}

pub fn run_show(
    input_file: PathBuf,
    r1cs_file: PathBuf,
    pk_file: PathBuf,
    witness_generator_file: PathBuf,
    proof_file: PathBuf,
) {
    todo!("Not implemented");
}

pub fn run_verifier(input_file: PathBuf, vk_file: PathBuf, proof_file: PathBuf) {
    todo!("Not implemented");
}