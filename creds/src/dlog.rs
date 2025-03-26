// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::utils::hash_to_curve_vartime;
use crate::utils::msm_select;
use ark_ec::CurveGroup;
use ark_ec::Group;
use ark_ec::VariableBaseMSM;
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{end_timer, rand::thread_rng, start_timer, UniformRand};
use merlin::Transcript;

use crate::utils::add_to_transcript;

#[derive(Clone, Debug, Default, CanonicalSerialize, CanonicalDeserialize)]
pub struct DLogPoK<G: Group> {
    pub c: G::ScalarField,
    pub s: Vec<Vec<G::ScalarField>>,
}

// helper struct to store a commitment c = g1^m * g2^r
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PedersenOpening<G: CurveGroup> {
    pub bases: Vec<G::Affine>,
    pub m: G::ScalarField,
    pub r: G::ScalarField,
    pub c: G,
}

impl<G: Group> DLogPoK<G> {
    /// Proves knowledge of the representations of y1, y2, ... y_n
    /// in their respective bases -- bases[1], bases[2], ... bases[n]
    ///     y[i] = \prod_{i=0}^n bases[i]^scalars[i]
    /// Optionally, the context is bound to the proof.
    /// Optionally, when n=2, specify a set of positions to prove equality of scalars across the different statements.
    /// For each pair (i,j) in eq_pos, the proof ensures that scalars[0][i] == scalars[1][j]. 
    /// TODO (perf): shrink the proof size by compressing the responses since they're the same for all the equal positions
    pub fn prove(
        context: Option<&[u8]>,
        y: &[G],
        bases: &[Vec<G>],
        scalars: &[Vec<G::ScalarField>],
        eq_pos: Option<Vec<(usize, usize)>>,
    ) -> Self
    where
        G: CurveGroup + VariableBaseMSM,
    {
        assert_eq!(y.len(), bases.len());
        assert_eq!(bases.len(), scalars.len());
        let mut rng = thread_rng();

        let mut k = Vec::new();
        let mut r = Vec::new();

        let mut ts: Transcript = Transcript::new(&[0u8]);
        let context = context.unwrap_or(b"");
        add_to_transcript(&mut ts, b"context string", &context);

        for i in 0..y.len() {
            let mut ri = Vec::new();
            for _ in 0..bases[i].len() {
                ri.push(G::ScalarField::rand(&mut rng));
            }

            r.push(ri);
        }

        if eq_pos.is_some() {
            assert!(y.len() == 2);

            for (i,j) in eq_pos.unwrap().iter() {
                r[1][*j] = r[0][*i];
            }
        }

        for i in 0..y.len() {
            // add the bases, k and y to the transcript
            add_to_transcript(&mut ts, b"num_bases", &bases[i].len());
            for j in 0..bases[i].len() {
                add_to_transcript(&mut ts, b"base", &bases[i][j]);
            }

            let mut scalars = vec![];
            for j in 0..bases[i].len() {
                scalars.push(r[i][j]);
            }
            let bases_affine : Vec<G::Affine> = bases[i].iter().map(|x| x.into_affine()).collect();
            let ki = msm_select::<G>(&bases_affine, &scalars);

            k.push(ki);
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
        }
    }

    pub fn verify(
        &self,
        context: Option<&[u8]>,
        bases: &[Vec<G>],
        y: &[G],
        eq_pos: Option<Vec<(usize, usize)>>,
    ) -> bool
    where
        G: CurveGroup + VariableBaseMSM,    
    {
        // compute the challenge
        // serialize and hash the bases, k and y
        let dl_verify_timer = start_timer!(|| format!("DlogPoK verify y.len = {}", y.len()));
        let mut ts: Transcript = Transcript::new(&[0u8]);
        let context = context.unwrap_or(b"");
        add_to_transcript(&mut ts, b"context string", &context);

        let mut recomputed_k = Vec::new();
        for i in 0..y.len() {
            assert_eq!(bases[i].len(), self.s[i].len(), "i: {}", i);
            let mut bases_affine : Vec<G::Affine> = bases[i].iter().map(|x| x.into_affine()).collect();
            bases_affine.push(y[i].into_affine());
            let mut scalars = vec![];
            for j in 0..bases[i].len() {
                scalars.push(self.s[i][j]);
            }
            scalars.push(self.c);
            let recomputed_ki = msm_select::<G>(&bases_affine, &scalars);
            recomputed_k.push(recomputed_ki);

            add_to_transcript(&mut ts, b"num_bases", &bases[i].len());
            for j in 0..bases[i].len() {
                add_to_transcript(&mut ts, b"base", &bases[i][j]);
            }
            add_to_transcript(&mut ts, b"k", &recomputed_ki);
            add_to_transcript(&mut ts, b"y", &y[i]);
        }

        if eq_pos.is_some() {
            assert!(y.len() == 2);

            for (i,j) in eq_pos.unwrap().iter() {
                if self.s[0][*i] != self.s[1][*j] {
                    println!("DLogPoK verification failed: eq_pos mismatch");
                    return false;
                }
            }
        }        

        // get the challenge
        let mut c_bytes = [0u8; 31];
        ts.challenge_bytes(&[0u8], &mut c_bytes);
        let c = G::ScalarField::from_random_bytes(&c_bytes).unwrap();

        end_timer!(dl_verify_timer);

        // check the challenge matches
        c == self.c
    }

    // Computes Pedersen commitments
    pub fn pedersen_commit(
        m: &G::ScalarField,
        bases: &[<G as CurveGroup>::Affine],
    ) -> PedersenOpening<G>
    where
        G: CurveGroup + VariableBaseMSM,
    {
        assert!(bases.len() == 2);
        let mut rng = thread_rng();
        let r = G::ScalarField::rand(&mut rng);
        let scalars = vec![*m, r];
        let c = msm_select::<G>(bases, &scalars);
        PedersenOpening {
            bases: bases.to_vec(),
            m: *m,
            r,
            c,
        }
    }
    pub fn derive_pedersen_bases() -> Vec<G::Affine>
    where
        G: CurveGroup,
    {
        // Generate g1, g2.
        let mut bases_g: Vec<G::Affine> = Vec::new();
        for i in 1..3 {
            bases_g.push(hash_to_curve_vartime::<G>(&format!(
                "Pedersen commitment base {}",
                i
            )));
        }
        bases_g
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Bn254;
    use ark_ec::pairing::Pairing;
    use ark_std::{test_rng, Zero};

    type G1 = <Bn254 as Pairing>::G1;
    type G1A = <Bn254 as Pairing>::G1Affine;
    type F = <Bn254 as Pairing>::ScalarField;

    #[test]
    fn test_dlog_pok_base() {
        let num_terms = 10;
        let rng = &mut test_rng();
        let mut bases = vec![G1::zero(); num_terms];
        let mut scalars = vec![F::zero(); num_terms];
        let mut y = G1::zero();
        for i in 0..bases.len() {
            bases[i] = G1::rand(rng);
            scalars[i] = F::rand(rng);
            y += bases[i] * scalars[i];
        }

        let context = "some context data to bind to the proof".as_bytes();

        let pok = DLogPoK::<G1>::prove(
            Some(context),
            &[y, y],
            &[bases.clone(), bases.clone()],
            &[scalars.clone(), scalars.clone()],
            None
        );

        // verify with the wrong bases
        let wrong_bases = vec![G1::zero(); num_terms];
        let wrong_bases_result = pok.verify(
            Some(context),
            &[wrong_bases.clone(), wrong_bases.clone()],
            &[y, y],
            None
        );
        assert!(!wrong_bases_result, "Verification should fail with the wrong bases");

        // verify with the wrong context
        let wrong_context = "wrong context data".as_bytes();
        let wrong_context_result = pok.verify(
            Some(wrong_context),
            &[bases.clone(), bases.clone()],
            &[y, y],
            None
        );
        assert!(!wrong_context_result, "Verification should fail with the wrong context data");

        // successful verification
        let result = pok.verify(
            Some(context),
            &[bases.clone(), bases.clone()],
            &[y, y],
            None
        );

        assert!(result);
    }

    #[test]
    fn test_dleq() {
        let num_terms = 10;
        let rng = &mut test_rng();
        let mut bases : Vec<G1A> = vec![];
        let mut scalars1 = vec![F::zero(); num_terms];
        let mut scalars2 = vec![F::zero(); num_terms];
        for i in 0..num_terms {
            bases.push(G1::rand(rng).into());
            scalars1[i] = F::rand(rng);
            scalars2[i] = F::rand(rng);
        }

        // Equal scalars vectors, expect success
        let eq_pos = vec![(0,0)];
        assert!(run_dleq_test(&bases, &bases, &scalars1, &scalars1, &eq_pos));
        let eq_pos = vec![(0,0), (1,1)];
        assert!(run_dleq_test(&bases, &bases, &scalars1, &scalars1, &eq_pos));        
        let eq_pos = vec![(2,2), (1,1), (num_terms-1, num_terms-1)];
        assert!(run_dleq_test(&bases, &bases, &scalars1, &scalars1, &eq_pos)); 
        
        // Equal scalars in different positions, expect success
        let mut scalars_rev = scalars1.clone();
        scalars_rev.reverse();
        let eq_pos = vec![(0,num_terms-1)];
        assert!(run_dleq_test(&bases, &bases, &scalars1, &scalars_rev, &eq_pos));
        let eq_pos = vec![(3,num_terms-4), (0,num_terms-1)];
        assert!(run_dleq_test(&bases, &bases, &scalars1, &scalars_rev, &eq_pos));

        // Mix of matching and mismatching, expect failure
        let eq_pos = vec![(2,2), (1,3), (num_terms-1, num_terms-1)];
        assert!(!run_dleq_test(&bases, &bases, &scalars1, &scalars1, &eq_pos)); 

        // All different scalars, no equal positions, expect failure
        let eq_pos = vec![(0,0)];
        assert!(!run_dleq_test(&bases, &bases, &scalars1, &scalars2, &eq_pos));
        
    }    

    fn run_dleq_test(bases1 : &Vec<G1A>, bases2 : &Vec<G1A>, scalars1: &Vec<F>, scalars2:  &Vec<F>, eq_pos: &[(usize, usize)]) -> bool
    {
        let y1 = msm_select(bases1, scalars1);
        let y2 = msm_select(bases2, scalars2);
        let bases1_proj : Vec<G1> = bases1.iter().map(|x| (*x).into()).collect();
        let bases2_proj : Vec<G1> = bases2.iter().map(|x| (*x).into()).collect();
        
        let pok = DLogPoK::<G1>::prove(
            None,
            &[y1, y2],
            &[bases1_proj.clone(), bases2_proj.clone()],
            &[scalars1.clone(), scalars2.clone()],
            Some(eq_pos.to_vec())
        );

        pok.verify(
            None,
            &[bases1_proj, bases2_proj],
            &[y1, y2],
            Some(eq_pos.to_vec())
        )
    }
}
