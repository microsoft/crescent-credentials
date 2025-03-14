// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use ark_groth16::{VerifyingKey,PreparedVerifyingKey};
use ark_serialize::CanonicalSerialize;
use crescent::device::TestDevice;
use crescent::groth16rand::{ClientState, ShowGroth16};
use crescent::rangeproof::{RangeProofPK, RangeProofVK};
use crescent::utils::{read_from_file, string_to_byte_vec, write_to_file};
use crescent::{create_client_state, create_show_proof, create_show_proof_mdl, run_zksetup, verify_show, verify_show_mdl, CachePaths, ShowProof, VerifierParams, ProofSpec};
use crescent::CrescentPairing;
use crescent::prep_inputs::{prepare_prover_inputs, parse_config};
use crescent::structs::{GenericInputsJSON, IOLocations, ProverInput};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::env::current_dir;
use std::{fs, path::PathBuf};

use structopt::StructOpt;

const MDL_AGE_GREATER_THAN : usize = 18;         // mDL show proofs will prove that the holder is older than this value (in years)



fn main() {
    let root = current_dir().unwrap();
    let opt = Opt::from_args();

    match opt.cmd {
        Command::Zksetup{ name } => {
            let name_path = format!("test-vectors/{}", name);
            let base_path = root.join(name_path);
            let ret = run_zksetup(base_path);
            if ret == 0 {
                
            }
        }
        Command::Prove { name } | Command::Prepare { name } => {
            let name_path = format!("test-vectors/{}", name);
            let base_path = root.join(name_path);
            run_prover(base_path);
        }
        Command::Show { name, presentation_message } => {
            let name_path = format!("test-vectors/{}", name);
            let base_path = root.join(name_path);
            run_show(base_path, presentation_message);
        }        
        Command::Verify { name, presentation_message } => {
            let name_path = format!("test-vectors/{}", name);
            let base_path = root.join(name_path);
            run_verifier(base_path, presentation_message);
        }
    }
}

#[derive(Debug, StructOpt)]
#[structopt(name = "Credential selective disclosure application", about = "Selectively reveal claims or prove predicates for a credential.")]
pub struct Opt {
    #[structopt(subcommand)]
    pub cmd: Command,
}

#[derive(Debug, StructOpt)]
pub enum Command {
    #[structopt(about = "Setup parameters for the ZK proof systems (public params for the Groth16 and Show proofs).")]
    Zksetup {
        #[structopt(long)]
        name: String,
    },

    #[structopt(about = "Run prover. (deprecated, use `prepare` instead)")]
    Prove {
        #[structopt(long)]
        name: String,
    },
    #[structopt(about = "Prepare credential before show.")]
    Prepare {
        #[structopt(long)]
        name: String,
    },    

    #[structopt(about = "Generate a presentation proof to Show a credential.")]
    Show {
        #[structopt(long)]
        name: String,
        #[structopt(long, about = "Optional presentation message to include in the proof.")]
        presentation_message: Option<String>,
    },    

    #[structopt(about = "Verifier a presentation proof.")]
    Verify {
        #[structopt(long)]
        name: String,
        #[structopt(long, about = "Optional presentation message to include in the proof.")]
        presentation_message: Option<String>,
    },
}


pub fn run_prover(
    base_path: PathBuf,
) {
    let paths = CachePaths::new(base_path);
    let config_str = fs::read_to_string(&paths.config).unwrap_or_else(|_| panic!("Unable to read config from {} ", paths.config));
    let config = parse_config(&config_str).expect("Failed to parse config");

    let client_state = 
    if config.contains_key("credtype") && config.get("credtype").unwrap() == "mdl" {
        let prover_inputs = GenericInputsJSON::new(&paths.mdl_prover_inputs);
        create_client_state(&paths, &prover_inputs, None, "mdl").unwrap()
    }
    else {
        let jwt = fs::read_to_string(&paths.jwt).unwrap_or_else(|_| panic!("Unable to read JWT file from {}", paths.jwt));
        let issuer_pem = fs::read_to_string(&paths.issuer_pem).unwrap_or_else(|_| panic!("Unable to read issuer public key PEM from {} ", paths.issuer_pem));   
        let device_pub_pem = fs::read_to_string(&paths.device_pub_pem).ok();
        let (prover_inputs_json, prover_aux_json, _public_ios_json) = 
            prepare_prover_inputs(&config, &jwt, &issuer_pem, device_pub_pem.as_deref()).expect("Failed to prepare prover inputs");    
        let prover_inputs = GenericInputsJSON{prover_inputs: prover_inputs_json};
        let prover_aux_string = json!(prover_aux_json).to_string();
        create_client_state(&paths, &prover_inputs, Some(&prover_aux_string), "jwt").unwrap()
    };

    write_to_file(&client_state, &paths.client_state);
}

fn _show_groth16_proof_size(show_groth16: &ShowGroth16<CrescentPairing>) -> usize {
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

fn show_proof_size(show_proof: &ShowProof<CrescentPairing>) -> usize {

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

    let device_proof_size = if show_proof.device_proof.is_some() {
        let tmp = show_proof.device_proof.compressed_size();
        print!("{} + (device signature proof)", tmp);
        tmp
    } else {
        0
    };

    let total = groth16_size + show_range_size + show_range2_size + device_proof_size;
    println!(" = {} bytes total", total);

    total
}

fn load_proof_spec(proof_spec_file_path : &str, presentation_message: Option<String>) -> ProofSpec {
    let ps_raw = if PathBuf::from(proof_spec_file_path).exists() {
        println!("Using proof spec file {}", proof_spec_file_path);
        fs::read_to_string(proof_spec_file_path).expect("Proof spec file exists, but failed while reading it")
    } else {
        println!("Proof spec file not found; using default (looked for file: {}) ", proof_spec_file_path);
        crescent::DEFAULT_PROOF_SPEC.to_string()
    };
    let mut ps : ProofSpec = serde_json::from_str(&ps_raw).unwrap();

    if ps.presentation_message.is_some() && presentation_message.is_some() {
        println!("Error: presentation message was provided twice, once in the proof specification file ({}) and once as a command line option.", proof_spec_file_path);
        panic!("Multiple presentation messages");
    }
    if presentation_message.is_some() {
        ps.presentation_message = string_to_byte_vec(presentation_message);
    }

    if ps.device_bound.is_some() && ps.device_bound.unwrap() {
        let pm_bytes = ps.presentation_message.expect("Presentation message is required for device-bound credentials");
        // We hash here in the CLI tool, but applications calling the
        // API can hash themselves, setting the message to be signed as 
        // whatever the application needs.         
        let digest = Sha256::digest(pm_bytes);  
        ps.presentation_message = Some(digest.to_vec());
    }          

    ps
}

pub fn run_show(
    base_path: PathBuf,
    presentation_message: Option<String>
) {
    let proof_timer = std::time::Instant::now();    
    let paths = CachePaths::new(base_path);
    let io_locations = IOLocations::new(&paths.io_locations);    
    let mut client_state: ClientState<CrescentPairing> = read_from_file(&paths.client_state).unwrap();
    let range_pk : RangeProofPK<CrescentPairing> = read_from_file(&paths.range_pk).unwrap();
    
    let show_proof = if client_state.credtype == "mdl" {
        let pm = string_to_byte_vec(presentation_message);
        create_show_proof_mdl(&mut client_state, &range_pk, pm.as_deref(), &io_locations, MDL_AGE_GREATER_THAN)  
    } else {
        let proof_spec = load_proof_spec(&paths.proof_spec, presentation_message);

        let device_signature = 
        if proof_spec.device_bound.is_some() && proof_spec.device_bound.unwrap() {
            let device = TestDevice::new_from_file(&paths.device_prv_pem);
            Some(device.sign(proof_spec.presentation_message.as_ref().unwrap()))
        } else {
            None
        };

        create_show_proof(&mut client_state, &range_pk, &io_locations, &proof_spec, device_signature).unwrap()
    };
    println!("Proving time: {:?}", proof_timer.elapsed());

    let _ = show_proof_size(&show_proof);

    write_to_file(&show_proof, &paths.show_proof);
}

pub fn run_verifier(base_path: PathBuf, presentation_message: Option<String>) {
    let paths = CachePaths::new(base_path);
    let show_proof : ShowProof<CrescentPairing> = read_from_file(&paths.show_proof).unwrap();
    let pvk : PreparedVerifyingKey<CrescentPairing> = read_from_file(&paths.groth16_pvk).unwrap();
    let vk : VerifyingKey<CrescentPairing> = read_from_file(&paths.groth16_vk).unwrap();
    let range_vk : RangeProofVK<CrescentPairing> = read_from_file(&paths.range_vk).unwrap();
    let io_locations_str = std::fs::read_to_string(&paths.io_locations).unwrap();
    let issuer_pem = std::fs::read_to_string(&paths.issuer_pem).unwrap();
    let config_str = std::fs::read_to_string(&paths.config).unwrap();
    let vp = VerifierParams{vk, pvk, range_vk, io_locations_str, issuer_pem, config_str};
    
    let (verify_result, data) = if show_proof.show_range2.is_some() {
        let pm = string_to_byte_vec(presentation_message);
        verify_show_mdl(&vp, &show_proof, pm.as_deref(), MDL_AGE_GREATER_THAN)
    } else {
        let proof_spec = load_proof_spec(&paths.proof_spec, presentation_message);  
        verify_show(&vp, &show_proof, &proof_spec)
    };

    if verify_result {
        println!("Verify succeeded, got data '{}'", data);
    }
    else {
        println!("Verify failed")
    }

}