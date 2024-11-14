// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_ff::PrimeField;
use ark_groth16::Groth16;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_std::{rand::SeedableRng, UniformRand, Zero};
use crescent::{groth16rand::ClientState, rangeproof::RangeProofPK, structs::{IOLocations, PublicIOType}};
use std::collections::BTreeMap;

const NUM_CONSTRAINTS: usize = (1 << 10) - 100;
const NUM_VARIABLES: usize = (1 << 10) - 100;
const NUM_INPUTS: usize = 5;

#[derive(Copy)]
struct DummyCircuit<F: PrimeField> {
    pub a: Option<F>,
    pub b: Option<F>,
    pub num_variables: usize,
    pub num_constraints: usize,
    pub num_inputs: usize,
}

impl<F: PrimeField> Clone for DummyCircuit<F> {
    fn clone(&self) -> Self {
        DummyCircuit {
            a: self.a.clone(),
            b: self.b.clone(),
            num_variables: self.num_variables.clone(),
            num_constraints: self.num_constraints.clone(),
            num_inputs: self.num_inputs.clone(),
        }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for DummyCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

            Ok(a * b)
        })?;

        for _ in 0..self.num_inputs - 1 {
            let _ = cs.new_input_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        }

        for _ in 0..(self.num_variables - self.num_inputs - 2) {
            let _ = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        }

        for _ in 0..self.num_constraints - 1 {
            cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        }

        cs.enforce_constraint(lc!(), lc!(), lc!())?;

        Ok(())
    }
}

#[test]
pub fn range_test() {
    let rng = &mut ark_std::rand::rngs::StdRng::seed_from_u64(0u64);
    let circuit: DummyCircuit<ark_ff::Fp<ark_ff::MontBackend<ark_bn254::FrConfig, 4>, 4>> =
        DummyCircuit::<Fr> {
            a: Some(Fr::from(7u32)),
            b: Some(<Fr>::rand(rng)),
            num_variables: NUM_VARIABLES,
            num_constraints: NUM_CONSTRAINTS,
            num_inputs: NUM_INPUTS,
        };

    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, rng).unwrap();
    let mut inputs = Vec::new();
    inputs.push(circuit.a.unwrap() * circuit.b.unwrap());
    for _ in 0..circuit.num_inputs - 1 {
        inputs.push(circuit.a.unwrap());
    }

    let proof =
        Groth16::<Bn254>::create_proof_with_reduction(circuit.clone(), &pk, Fr::zero(), Fr::zero())
            .unwrap();
    let pvk = Groth16::<Bn254>::process_vk(&vk).unwrap();
    assert!(Groth16::<Bn254>::verify_with_processed_vk(&pvk, &inputs, &proof).unwrap());

    let mut client_state =
        ClientState::<Bn254>::new(inputs.clone(), proof.clone(), vk.clone(), pvk.clone());

    let (range_pk, range_vk) = RangeProofPK::<Bn254>::setup(32);    

    let mut io_types = vec![PublicIOType::Hidden; client_state.inputs.len()];
    io_types[0] = PublicIOType::Revealed;
    io_types[1] = PublicIOType::Committed;

    let showing = client_state.show_groth16(&io_types);
    showing.verify(&vk, &pvk, &io_types, &vec![inputs[0]]);

    println!(
        "Committed to input: {}",
        client_state.committed_input_openings[0].m
    );

    let now = std::time::Instant::now();
    let show_range =
        client_state.show_range(&client_state.committed_input_openings[0], 32, &range_pk);        
    println!("Time taken for range proof: {:?}", now.elapsed());

    let now = std::time::Instant::now();
    let mut io_locations_map = BTreeMap::default();
    io_locations_map.insert(String::from("reserved_value"), 0 as usize);    // part of the Groth16 system
    io_locations_map.insert(String::from("revealed_value"), 1 as usize);
    io_locations_map.insert(String::from("committed_value"), 2 as usize);
    let io_locations = IOLocations{public_io_locations: io_locations_map.clone()};

    show_range.verify(
        &client_state.committed_input_openings[0].c,
        32,
        &range_vk,
        &io_locations,
        &client_state.pvk,
        "committed_value",
    );

    println!(
        "Time taken for range proof verification: {:?}",
        now.elapsed()
    );
}
