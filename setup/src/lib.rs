use ark_std::{end_timer, start_timer};
use reader::generate_witness_from_wasm_with_input_file;
use spartan2::{traits::Group, SNARK};
use std::{env::current_dir, fs, path::PathBuf};

use crate::{
    circuit::{CircomCircuitSetup, CircomCircuitProve, R1CSDimension},
    reader::{
        generate_witness_from_bin_with_input_file,
        load_input_from_json_file, load_r1cs, load_r1cs_dimension,
    },
    utils::{deserialize_from_file, serialize_into_file},
};

mod circuit;
mod file;
mod reader;
mod utils;

pub(crate) type G = pasta_curves::pallas::Point;
pub(crate) type Fr = <G as Group>::Scalar;
//pub(crate) type EE = spartan2::provider::ipa_pc::EvaluationEngine<G>;
pub(crate) type EE = spartan2::provider::hyrax_pc::HyraxEvaluationEngine<G>;
pub(crate) type S = spartan2::spartan::snark::RelaxedR1CSSNARK<G, EE>;

pub fn run_setup(r1cs_file: PathBuf, pk_file: PathBuf, vk_file: PathBuf) {
    let total_timer = start_timer!(|| "Running setup (total time) ...");
    let timer = start_timer!(|| "Loading R1CS instance (Circom-generated) ...");
    let r1cs = load_r1cs(&r1cs_file);
    end_timer!(timer);

    // The CircomCircuit type implements bellperson's Circuit trait so we can use it directly with Spartan2
    let timer = start_timer!(|| "Creating a Circom circuit ...");
    let circom_circuit = CircomCircuitSetup {
        r1cs,
    };
    end_timer!(timer);

    let timer = start_timer!(|| "Calling spartan2::setup ...");
    let (pk, vk) = SNARK::<G, S, CircomCircuitSetup<Fr>>::setup(circom_circuit).unwrap();
    end_timer!(timer);

    // Serialize
    let timer = start_timer!(|| "Serializing the prover key ...");
    serialize_into_file("Proving key", &pk_file, pk);
    end_timer!(timer);
    let timer = start_timer!(|| "Serializing the verifier key ...");
    serialize_into_file("Verification key", &vk_file, vk);
    end_timer!(timer);
    end_timer!(total_timer);
}

pub fn run_prover(
    input_file: PathBuf,
    r1cs_file: PathBuf,
    pk_file: PathBuf,
    witness_generator_file: PathBuf,
    proof_file: PathBuf,
) {
    let total_timer = start_timer!(|| "Generating proof (total time) ...");
    let timer = start_timer!(|| "Loading R1CS instance (Circom-generated) ...");
    let r1cs_dimension = load_r1cs_dimension(&r1cs_file);
    end_timer!(timer);

    let timer = start_timer!(|| "Creating a Circom circuit object ...");
    let circom_circuit = create_circom_circuit(
        witness_generator_file,
        input_file,
        r1cs_dimension,
    )
    .unwrap();
    end_timer!(timer);

    let timer = start_timer!(|| "Loading the prover key...");
    let pk: spartan2::ProverKey<G, S> = deserialize_from_file(&pk_file);
    end_timer!(timer);

    // produce a SNARK
    let timer = start_timer!(|| "Calling spartan2::prove ...");
    let res = SNARK::prove(&pk, circom_circuit);
    assert!(res.is_ok());
    let snark = res.unwrap();
    end_timer!(timer);

    // Serialize the SNARK
    let timer = start_timer!(|| "Serializing the SNARK ...");
    serialize_into_file("Spartan proof", &proof_file, snark);
    end_timer!(timer);
    end_timer!(total_timer);
}

pub fn run_verifier(input_file: PathBuf, vk_file: PathBuf, proof_file: PathBuf) {
    let total_timer = start_timer!(|| "Verifying proof (total time) ...");
    let timer = start_timer!(|| "Loading the verification key...");
    let vk = deserialize_from_file(&vk_file);
    end_timer!(timer);
    let timer = start_timer!(|| "Loading the proof...");
    let snark: SNARK<G, S, CircomCircuitProve<_>> = deserialize_from_file(&proof_file);
    end_timer!(timer);
    let timer = start_timer!(|| "Loading the inputs and outputs...");
    let public_i: Vec<Fr> = load_input_from_json_file(&input_file);
    end_timer!(timer);

    // verify the SNARK
    let timer = start_timer!(|| "Calling spartan2::verify ...");
    let res = snark.verify(&vk, &public_i);
    end_timer!(timer);
    assert!(res.is_ok());    
    println!("Proof verifies");
    end_timer!(total_timer);
}

fn create_circom_circuit(
    witness_generator_file: PathBuf,
    input_file: PathBuf,
    r1cs_dimension: R1CSDimension,
) -> Result<CircomCircuitProve<Fr>, std::io::Error> {
    let root = current_dir().unwrap();
    let witness_generator_output = root.join("circom_witness.wtns");
    let ext = witness_generator_file.extension();
    let is_wasm = ext.is_some() && ext.unwrap().eq_ignore_ascii_case("wasm");

    let witness = if is_wasm {
        generate_witness_from_wasm_with_input_file::<<G as Group>::Scalar>(
            &witness_generator_file,
            &input_file,
            &witness_generator_output,
            true, // toggle logging
        )
    } else {
        generate_witness_from_bin_with_input_file::<<G as Group>::Scalar>(
            &witness_generator_file,
            &input_file,
            &witness_generator_output,
            true, // toggle logging
        )
    };

    let circuit = CircomCircuitProve {
        r1cs_dimension,
        witness,
    };

    fs::remove_file(witness_generator_output)?;

    Ok(circuit)
}
