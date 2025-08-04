// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::{
    dlog::{DLogPoK, PedersenOpening},
    utils::add_to_transcript,
};
use ark_ec::pairing::Pairing;
use ark_ff::{BigInteger, Field, PrimeField};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Polynomial,
    Radix2EvaluationDomain,
};
use ark_poly_commit::{
    kzg10::{Commitment, Powers, Randomness, KZG10},
    PCRandomness,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{One, Zero};
use merlin::Transcript;
use rand::thread_rng;


#[derive(Clone, Debug, CanonicalDeserialize, CanonicalSerialize, PartialEq)]
pub struct RangeProofPK<'b, E: Pairing> {
    pub powers: Powers<'b, E>,
}

impl<E: Pairing> RangeProofPK<'_, E> {
    pub fn setup(n: usize) -> (Self, RangeProofVK<E>) {
        let mut rng = thread_rng();
        let params = ark_poly_commit::kzg10::KZG10::<E, DensePolynomial<E::ScalarField>>::setup(
            4 * n,
            true,
            &mut rng,
        )
        .expect("Setup failed");
        let powers_of_g = params.powers_of_g.to_vec();
        let powers_of_gamma_g: Vec<E::G1Affine> =
            (0..=4 * n).map(|i| params.powers_of_gamma_g[&i]).collect();

        let com_f_basis: [E::G1; 4] = [
            powers_of_gamma_g[0].into(),
            powers_of_gamma_g[1].into(),
            powers_of_gamma_g[2].into(),
            powers_of_g[0].into(),
        ];

        let powers = ark_poly_commit::kzg10::Powers::<E> {
            powers_of_g: ark_std::borrow::Cow::Owned(powers_of_g),
            powers_of_gamma_g: ark_std::borrow::Cow::Owned(powers_of_gamma_g),
        };

        let kzg_vk = ark_poly_commit::kzg10::VerifierKey::<E> {
            g: params.powers_of_g[0],
            gamma_g: params.powers_of_gamma_g[&0],
            h: params.h,
            beta_h: params.beta_h,
            prepared_h: params.prepared_h.clone(),
            prepared_beta_h: params.prepared_beta_h.clone(),
        };

        (
            RangeProofPK { powers },
            RangeProofVK {
                kzg_vk,
                com_f_basis,
            },
        )
    }
 
}

#[derive(Clone, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct RangeProofVK<E: Pairing> {
    pub kzg_vk: ark_poly_commit::kzg10::VerifierKey<E>,
    pub com_f_basis: [E::G1; 4],
}

/// A range proofthat a value is in [0,2^n). Following the notation in https://hackmd.io/@dabo/B1U4kx8XI
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, Default)]
pub struct RangeProof<E: Pairing> {
    pub com_f: ark_poly_commit::kzg10::Commitment<E>,
    pub com_g: ark_poly_commit::kzg10::Commitment<E>,
    pub eval_g: E::ScalarField,
    pub proof_g: ark_poly_commit::kzg10::Proof<E>,
    pub eval_gw: E::ScalarField,
    pub proof_gw: ark_poly_commit::kzg10::Proof<E>,
    pub com_q: ark_poly_commit::kzg10::Commitment<E>,
    pub eval_w_hat: E::ScalarField,
    pub proof_w_hat: ark_poly_commit::kzg10::Proof<E>,
    pub dleq_proof: DLogPoK<E::G1>,
}

impl<E: Pairing> RangeProof<E> {
    pub fn default() -> Self {
        Self {
            com_f: ark_poly_commit::kzg10::Commitment::default(),
            com_g: ark_poly_commit::kzg10::Commitment::default(),
            eval_g: E::ScalarField::zero(),
            proof_g: ark_poly_commit::kzg10::Proof::default(),
            eval_gw: E::ScalarField::zero(),
            proof_gw: ark_poly_commit::kzg10::Proof::default(),
            com_q: ark_poly_commit::kzg10::Commitment::default(),
            eval_w_hat: E::ScalarField::zero(),
            proof_w_hat: ark_poly_commit::kzg10::Proof::default(),
            dleq_proof: DLogPoK::default(),
        }
    }
    /// Proves that the value in the pedersen opening is in the range [0, 2^n).
    /// See https://hackmd.io/@dabo/B1U4kx8XI and 
    /// https://decentralizedthoughts.github.io/2020-03-03-range-proofs-from-polynomial-commitments-reexplained/
    /// for a more detailed description.
    pub fn prove_n_bits(ped_open: &PedersenOpening<E::G1>, n: usize, powers: &Powers<E>) -> Self {
        // prove that
        // 1. f(1) = g(1)
        // 2. g(w^{n-1}) \in {0,1}
        // 3. g(X) = 2g(Xw) \in {0,1} for all x in H \ {w^{n-1}}

        // To do so we compute
        // w1 = (g-f)*(X^n - 1)/(X-1)
        // w2 = g(1-g)*(X^n - 1)/(X - w^{n-1})
        // w3 = (g - 2gw)*(1 - g + 2gw)*(X-w^{n-1})
        // q = (w1 + c*w2 + c^2*w3)/(X^n - 1); where c is a fiat shamir challenge
        // and show that w = w1 + c*w2 + c^2*w3 - q*(X^n - 1) is the zero polynomial

        // we can simplify the above polynomials and instead compute the lower degree polynomials
        // q1 = (g-f)/(X-1)
        // q2 = g(1-g)/(X - w^{n-1})
        // q3 = (g - 2gw)*(1 - g + 2gw)*(X-w^{n-1})/(X^n - 1)

        // to ensure zk, we blind g as g = g + (X^n - 1)*(rand_poly(deg=2))

        // Finally we link com_f to ped_open via a dleq proof

        assert!(powers.powers_of_g.len() >= n + 2, "Not enough powers of g");
        assert!(n.is_power_of_two(), "n must be a power of two");

        let mut rng = thread_rng();

        let elem = ped_open.m;

        // bit decomposition of elem
        let elem_bits = elem
            .into_bigint()
            .to_bits_le()
            .iter()
            .map(|x| {
                if *x {
                    E::ScalarField::one()
                } else {
                    E::ScalarField::zero()
                }
            })
            .take(n)
            .collect::<Vec<_>>();

        let domain = Radix2EvaluationDomain::<E::ScalarField>::new(n).unwrap();

        let f = DensePolynomial::<E::ScalarField>::from_coefficients_vec(vec![elem; 1]);

        let mut g_evals = vec![E::ScalarField::zero(); n];
        g_evals[n - 1] = elem_bits[n - 1];
        for i in (0..=n - 2).rev() {
            g_evals[i] = g_evals[i + 1].double() + elem_bits[i];
        }
        let g = DensePolynomial::from_coefficients_vec(domain.ifft(&g_evals));

        let blinding_poly =
            DensePolynomial::<E::ScalarField>::rand(2, &mut rng).mul_by_vanishing_poly(domain);

        let g_blinded = &g + &blinding_poly;

        let mut gw_blinded = g_blinded.clone();
        let domain_elements = domain.elements().collect::<Vec<E::ScalarField>>();
        for i in 0..n {
            gw_blinded.coeffs[i] *= domain_elements[i];
        }
        for i in n..n + 3 {
            gw_blinded.coeffs[i] *= domain_elements[i - n];
        }

        // q1 = (g-f)/(X-1)
        let q1 = &(&g_blinded - &f)
            / &(DensePolynomial::from_coefficients_vec(vec![
                -E::ScalarField::one(),
                E::ScalarField::one(),
            ]));

        // q2 = g(1-g)/(X - w^{n-1})
        let one = DensePolynomial::from_coefficients_vec(vec![E::ScalarField::one()]);
        let q2 = &(&g_blinded * &(&one - &g_blinded))
            / &(DensePolynomial::from_coefficients_vec(vec![
                -domain.element(n - 1),
                E::ScalarField::one(),
            ]));

        // q3 = (g - 2gw)*(1 - g + 2gw)*(X-w^{n-1})/(X^n - 1)
        let mut gw2 = gw_blinded.clone();
        gw2.coeffs
            .iter_mut()
            .for_each(|x| *x *= E::ScalarField::from(2u8));

        let g_2gw = &g_blinded - &gw2;
        let mut w3 = &g_2gw * &(&one - &g_2gw);
        w3 = &w3
            * &DensePolynomial::from_coefficients_vec(vec![
                -domain.element(n - 1),
                E::ScalarField::one(),
            ]);
        let (q3, _rem3) = w3.divide_by_vanishing_poly(domain).unwrap();

        debug_assert!(_rem3.is_zero());

        // create a commitment to f
        let (com_f, rand_f) = KZG10::commit(powers, &f, Some(1), Some(&mut rng)).unwrap(); // Opened once

        let mut com_f_basis = powers
            .powers_of_gamma_g
            .iter()
            .take(3)
            .map(|&x| x.into())
            .collect::<Vec<E::G1>>();
        com_f_basis.push(powers.powers_of_g[0].into());

        let mut com_f_scalars = rand_f
            .blinding_polynomial
            .coeffs.to_vec();
        com_f_scalars.push(elem);

        // Link com_f to ped_open via a DLEQ proof
        let dleq_proof = DLogPoK::<E::G1>::prove(
            None, // TODO: should we add a presentation message here? (use the c from the dlog proof?)
            &[ped_open.c, com_f.0.into()],
            &[
                ped_open
                    .bases
                    .iter()
                    .map(|&x| x.into())
                    .collect::<Vec<E::G1>>(),
                com_f_basis.clone(),
            ],
            &[vec![ped_open.m, ped_open.r], com_f_scalars],
            Some(vec![(0, 3)]),
        );

        // create a commitment to g
        let (com_g, rand_g) = KZG10::commit(powers, &g_blinded, Some(2), Some(&mut rng)).unwrap(); // Opened twice

        let mut ts = Transcript::new(&[0u8]);
        add_to_transcript(&mut ts, b"com_f", &com_f);
        add_to_transcript(&mut ts, b"com_g", &com_g);

        // get the challenge
        let mut c_bytes = [0u8; 31];
        ts.challenge_bytes(&[0u8], &mut c_bytes);
        let c = E::ScalarField::from_random_bytes(&c_bytes).unwrap();
        let c_sq = c.square();

        let mut q2_c = q2.clone();
        q2_c.coeffs.iter_mut().for_each(|x| *x *= c);

        let mut q3_c_sq = q3.clone();
        q3_c_sq.coeffs.iter_mut().for_each(|x| *x *= c_sq);

        let q = &(&q1 + &q2_c) + &q3_c_sq;

        let (com_q, rand_q) = KZG10::commit(powers, &q, Some(1), Some(&mut rng)).unwrap(); // Opened once

        add_to_transcript(&mut ts, b"com_q", &com_q);
        // get another challenge
        let mut rho_bytes = [0u8; 31];
        ts.challenge_bytes(&[0u8], &mut rho_bytes);
        let rho = E::ScalarField::from_random_bytes(&rho_bytes).unwrap();

        // open com_g at rho and rho*w
        let eval_g = g_blinded.evaluate(&rho);
        let proof_g =
            KZG10::<E, DensePolynomial<E::ScalarField>>::open(powers, &g_blinded, rho, &rand_g)
                .unwrap();

        let eval_gw = g_blinded.evaluate(&(rho * domain.element(1)));
        let proof_gw = KZG10::<E, DensePolynomial<E::ScalarField>>::open(
            powers,
            &g_blinded,
            rho * domain.element(1),
            &rand_g,
        )
        .unwrap();

        // Compute w_hat = f.(rho^n - 1)/(rho - 1) + q.(rho^n - 1)
        let q_coeff = rho.pow([n as u64]) - E::ScalarField::one();
        let f_coeff = q_coeff / (rho - E::ScalarField::one());

        let mut f_term = f.clone();
        f_term.coeffs.iter_mut().for_each(|x| *x *= f_coeff);

        let mut q_term = q.clone();
        q_term.coeffs.iter_mut().for_each(|x| *x *= q_coeff);

        let w_hat = &f_term + &q_term;

        let mut rand_f_term = rand_f.clone();
        rand_f_term
            .blinding_polynomial
            .coeffs
            .iter_mut()
            .for_each(|x| *x *= f_coeff);

        let mut rand_q_term = rand_q.clone();
        rand_q_term
            .blinding_polynomial
            .coeffs
            .iter_mut()
            .for_each(|x| *x *= q_coeff);

        let mut rand_w_hat = Randomness::empty();
        rand_w_hat.blinding_polynomial =
            rand_f_term.blinding_polynomial + rand_q_term.blinding_polynomial;

        // open com_w_hat at rho
        let eval_w_hat = w_hat.evaluate(&rho);
        let proof_w_hat =
            KZG10::<E, DensePolynomial<E::ScalarField>>::open(powers, &w_hat, rho, &rand_w_hat)
                .unwrap();

        RangeProof {
            com_f,
            com_g,
            com_q,
            eval_g,
            eval_gw,
            proof_g,
            proof_gw,
            eval_w_hat,
            proof_w_hat,
            dleq_proof,
        }
    }

    /// Verify that the value represented by `elem` is in the range [0, 2^n).
    pub fn verify_n_bits(
        &self,
        ped_com: &E::G1,
        bases: &[E::G1; 2],
        n: usize,
        vk: &RangeProofVK<E>,
    ) -> bool {
        let domain = Radix2EvaluationDomain::<E::ScalarField>::new(n).unwrap();

        // rederive the challenges
        let mut ts = Transcript::new(&[0u8]);
        add_to_transcript(&mut ts, b"com_f", &self.com_f);
        add_to_transcript(&mut ts, b"com_g", &self.com_g);

        // get the challenge
        let mut c_bytes = [0u8; 31];
        ts.challenge_bytes(&[0u8], &mut c_bytes);
        let c = E::ScalarField::from_random_bytes(&c_bytes).unwrap();

        add_to_transcript(&mut ts, b"com_q", &self.com_q);

        // get another challenge
        let mut rho_bytes = [0u8; 31];
        ts.challenge_bytes(&[0u8], &mut rho_bytes);
        let rho = E::ScalarField::from_random_bytes(&rho_bytes).unwrap();

        // verify the openings
        let q_coeff = rho.pow([n as u64]) - E::ScalarField::one();
        let f_coeff = q_coeff / (rho - E::ScalarField::one());
        let com_w_hat: Commitment<E> = Commitment((self.com_f.0 * f_coeff + self.com_q.0 * q_coeff).into());

        let rng = &mut thread_rng();
        let ret = KZG10::<E, DensePolynomial<E::ScalarField>>::batch_check(
            &vk.kzg_vk,
            &[self.com_g, self.com_g, com_w_hat],
            &[rho, rho * domain.element(1), rho],
            &[self.eval_g, self.eval_gw, self.eval_w_hat],
            &[self.proof_g, self.proof_gw, self.proof_w_hat],
            rng,
        );
        match ret{
            Ok(ret) => if !ret {
                println!("Error verifying range proof, batch_check failed ");
                return false;
            },
            Err(ret) => {
                println!("Error verifying range proof, batch_check failed with error: {ret:?} ");
                return false;
            }
        }

        // check that w1 + tau*w2 + t^2 * w3 - q * (X^n - 1) = 0
        // note: we don't have an opening of com_q. This will be accounted for in eval_w_hat
        let partial_eval_w1 = (self.eval_g) * (rho.pow([n as u64]) - E::ScalarField::one())
            / (rho - E::ScalarField::one());

        let eval_w2 = self.eval_g
            * (E::ScalarField::one() - self.eval_g)
            * (rho.pow([n as u64]) - E::ScalarField::one())
            / (rho - domain.element(n - 1));

        let eval_w3 = (self.eval_g - self.eval_gw.double())
            * (E::ScalarField::one() - self.eval_g + self.eval_gw.double())
            * (rho - domain.element(n - 1));

        let eval_w = partial_eval_w1 + c * eval_w2 + c * c * eval_w3 - self.eval_w_hat;

        if !eval_w.is_zero() {
            println!("Range proof failed to verify, eval_w is not zero");
            return false;
        }

        
        
        self
            .dleq_proof
            .verify(
                None, // TODO: should we add a presentation message here?
                &[bases.to_vec(), vk.com_f_basis.to_vec(),],
                &[*ped_com, self.com_f.0.into()],
                Some(vec![(0, 3)]),
            )
    }
}


#[cfg(test)]
mod tests {
    use ark_crypto_primitives::snark::SNARK;
    use ark_ff::PrimeField;
    use ark_groth16::Groth16;
    use ark_relations::{
        lc,
        r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
    };
    use ark_std::{rand::SeedableRng, UniformRand, Zero};
    use crate::{groth16rand::ClientState, rangeproof::RangeProofPK, 
        structs::{IOLocations, PublicIOType}, CrescentPairing, CrescentFr};
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
        fn clone(&self) -> Self { *self }
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
        let circuit: DummyCircuit<CrescentFr> =
            DummyCircuit::<CrescentFr> {
                a: Some(CrescentFr::from(7u32)),
                b: Some(<CrescentFr>::rand(rng)),
                num_variables: NUM_VARIABLES,
                num_constraints: NUM_CONSTRAINTS,
                num_inputs: NUM_INPUTS,
            };
    
        let (pk, vk) = Groth16::<CrescentPairing>::circuit_specific_setup(circuit, rng).unwrap();
        let mut inputs = Vec::new();
        inputs.push(circuit.a.unwrap() * circuit.b.unwrap());
        for _ in 0..circuit.num_inputs - 1 {
            inputs.push(circuit.a.unwrap());
        }
    
        let proof =
            Groth16::<CrescentPairing>::create_proof_with_reduction(circuit, &pk, CrescentFr::zero(), CrescentFr::zero())
                .unwrap();
        let pvk = Groth16::<CrescentPairing>::process_vk(&vk).unwrap();
        assert!(Groth16::<CrescentPairing>::verify_with_processed_vk(&pvk, &inputs, &proof).unwrap());
    
        let mut client_state =
            ClientState::<CrescentPairing>::new(inputs.clone(), None, proof.clone(), vk.clone(), pvk.clone(), "empty configuration string".to_string());
    
        let (range_pk, range_vk) = RangeProofPK::<CrescentPairing>::setup(32);    
    
        let mut io_types = vec![PublicIOType::Hidden; client_state.inputs.len()];
        io_types[0] = PublicIOType::Revealed;
        io_types[1] = PublicIOType::Committed;
    
        let pm = "some presentation message".as_bytes();
        let showing = client_state.show_groth16(Some(pm), &io_types);
        showing.verify(&vk, &pvk, Some(pm), &io_types, &[inputs[0]]);
    
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
        io_locations_map.insert(String::from("reserved_value"), 0_usize);    // part of the Groth16 system
        io_locations_map.insert(String::from("revealed_value"), 1_usize);
        io_locations_map.insert(String::from("committed_value"), 2_usize);
        let io_locations = IOLocations{public_io_locations: io_locations_map.clone()};
    
        let res = show_range.verify(
            &client_state.committed_input_openings[0].c,
            32,
            &range_vk,
            &io_locations,
            &client_state.pvk,
            "committed_value",
        );
        assert!(res);
    
        println!(
            "Time taken for range proof verification: {:?}",
            now.elapsed()
        );
    }
}