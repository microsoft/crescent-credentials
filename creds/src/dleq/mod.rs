use crate::utils::biguint_to_scalar;
use crate::utils::hash_to_curve_vartime;
use ark_ec::CurveGroup;
use ark_ec::Group;
use ark_ec::VariableBaseMSM;
use ark_ff::Field;
use ark_relations::r1cs::Result as R1CSResult;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{add_to_trace, end_timer, rand::thread_rng, start_timer, UniformRand};
use merlin::Transcript;
use num_bigint::BigUint;
use num_traits::Num;

use crate::utils::add_to_transcript;
use crate::utils::random_vec;

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct DLEQ<G: Group> {
    pub c: G::ScalarField,
    pub s: Vec<Vec<G::ScalarField>>,
}

impl<G: Group> DLEQ<G> {
    /// Given two commitments y1, y2 over vectors bases -- base1 and base2
    /// proves knowledge of the representations of y1 and y2
    /// and proves that one of the values in one vector is equal to the value in the other vector
    pub fn prove(y: &Vec<G>, bases: &Vec<Vec<G>>, scalars: &Vec<Vec<G::ScalarField>>) -> Self {
        assert_eq!(y.len(), bases.len());
        assert_eq!(bases.len(), scalars.len());
        let mut rng = thread_rng();

        let mut k = Vec::new();
        let mut r = Vec::new();

        let mut ts: Transcript = Transcript::new(&[0u8]);

        for i in 0..y.len() {
            // pok of the representation of y

            let mut ki = G::zero();
            let mut ri = Vec::new();
            for j in 0..bases[i].len() {
                // TODO: (perf) faster to use MSMs (See https://docs.rs/crate/ark-ec/latest, and prove_for_spartan)
                ri.push(G::ScalarField::rand(&mut rng));
                ki += bases[i][j] * ri[j];
            }
            k.push(ki);
            r.push(ri);

            // add the bases, k and y to the transcript
            add_to_transcript(&mut ts, b"num_bases", &bases[i].len());
            for j in 0..bases[i].len() {
                add_to_transcript(&mut ts, b"base", &bases[i][j]);
            }
            add_to_transcript(&mut ts, b"k", &k[i]);
            add_to_transcript(&mut ts, b"y", &y[i]);
        }

        // get the challenge
        let mut c_bytes = [0u8; 31];
        ts.challenge_bytes(&[0u8], &mut c_bytes);
        let c = G::ScalarField::from_random_bytes(&c_bytes).unwrap();

        let mut s = Vec::new();
        for i in 0..y.len() {
            // compute the responses
            let mut si = Vec::new();
            for j in 0..r[i].len() {
                si.push(r[i][j] - c * scalars[i][j]);
            }
            s.push(si);
        }

        DLogPoK {
            c,
            s,
            extra_values: None,
        }
    }

    pub fn verify(&self, bases: &Vec<Vec<G>>, y: &Vec<G>) -> R1CSResult<bool> {
        // compute the challenge
        // serialize and hash the bases, k and y
        let dl_verify_timer = start_timer!(|| "DlogPoK verify");
        let mut ts: Transcript = Transcript::new(&[0u8]);

        let mut recomputed_k = Vec::new();
        for i in 0..y.len() {
            assert_eq!(bases[i].len(), self.s[i].len(), "i: {}", i);
            let mut recomputed_ki = G::zero();
            for j in 0..bases[i].len() {
                recomputed_ki += bases[i][j] * self.s[i][j];
            }
            recomputed_ki += y[i] * self.c;
            recomputed_k.push(recomputed_ki);

            add_to_transcript(&mut ts, b"num_bases", &bases[i].len());
            for j in 0..bases[i].len() {
                add_to_transcript(&mut ts, b"base", &bases[i][j]);
            }
            add_to_transcript(&mut ts, b"k", &recomputed_ki);
            add_to_transcript(&mut ts, b"y", &y[i]);
        }

        // get the challenge
        let mut c_bytes = [0u8; 31];
        ts.challenge_bytes(&[0u8], &mut c_bytes);
        let c = G::ScalarField::from_random_bytes(&c_bytes).unwrap();

        end_timer!(dl_verify_timer);

        // check the challenge matches
        Ok(c == self.c)
    }
}
