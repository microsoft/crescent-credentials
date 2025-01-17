// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_ff::PrimeField;
use ark_groth16::Groth16;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_std::{rand::SeedableRng, UniformRand, Zero};
use crescent::groth16rand::{ClientState, ShowGroth16};
use crescent::structs::PublicIOType;

const NUM_CONSTRAINTS: usize = (1 << 10) - 100;
const NUM_VARIABLES: usize = (1 << 10) - 100;
const NUM_INPUTS: usize = 10;

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

pub fn show_bench(c: &mut Criterion) {
    let rng = &mut ark_std::rand::rngs::StdRng::seed_from_u64(0u64);
    let circuit: DummyCircuit<ark_ff::Fp<ark_ff::MontBackend<ark_bn254::FrConfig, 4>, 4>> =
        DummyCircuit::<Fr> {
            a: Some(<Fr>::rand(rng)),
            b: Some(<Fr>::rand(rng)),
            num_variables: NUM_VARIABLES,
            num_constraints: NUM_CONSTRAINTS,
            num_inputs: NUM_INPUTS,
        };

    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, rng).unwrap();
    let mut public_inputs = Vec::new();
    public_inputs.push(circuit.a.unwrap() * circuit.b.unwrap());
    for _ in 0..circuit.num_inputs - 1 {
        public_inputs.push(circuit.a.unwrap());
    }

    let proof =
        Groth16::<Bn254>::create_proof_with_reduction(circuit.clone(), &pk, Fr::zero(), Fr::zero())
            .unwrap();
    let pvk = Groth16::<Bn254>::process_vk(&vk).unwrap();
    assert!(Groth16::<Bn254>::verify_with_processed_vk(&pvk, &public_inputs, &proof).unwrap());

    c.bench_function("Groth16 Verify", |b| {
        b.iter(|| {
            Groth16::<Bn254>::verify_with_processed_vk(
                black_box(&pvk),
                black_box(&public_inputs),
                black_box(&proof),
            )
            .unwrap()
        })
    });

    let mut client_state = ClientState::<Bn254>::new(
        public_inputs.clone(),
        proof.clone(),
        vk.clone(),
        pvk.clone(),
    );

    let io_types = vec![PublicIOType::Hidden; client_state.inputs.len()];
    let pm = "some presentation message".as_bytes();

    let showing = client_state.show_groth16(Some(pm), &io_types);
    c.bench_function(&format!("Show with {} hidden inputs", NUM_INPUTS), |b| {
        b.iter(|| {
            client_state.show_groth16(Some(pm), &io_types);
        })
    });

    showing.verify(&vk, &pvk, Some(pm), &io_types, &vec![]);
    c.bench_function(&format!("Verify with {} hidden inputs", NUM_INPUTS), |b| {
        b.iter(|| {
            ShowGroth16::<Bn254>::verify(
                black_box(&showing),
                black_box(&vk),
                black_box(&pvk),
                Some(pm), 
                &io_types,
                &vec![],
            );
        })
    });
}


criterion_group!{
    name = benches;
    // This can be any expression that returns a `Criterion` object.
    config = Criterion::default().significance_level(0.1).sample_size(10000).measurement_time(Duration::from_secs(40)).warm_up_time(Duration::from_secs(10));
    //sampling_mode(SamplingMode::Linear);
    targets = show_bench
}

criterion_main!(benches);
