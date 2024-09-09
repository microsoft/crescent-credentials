use crate::utils::biguint_to_scalar;
use crate::utils::hash_to_curve_vartime;
use crate::utils::msm_select;
use ark_ec::CurveGroup;
use ark_ec::Group;
use ark_ec::VariableBaseMSM;
use ark_ff::Field;
use ark_relations::r1cs::Result as R1CSResult;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{end_timer, rand::thread_rng, start_timer, UniformRand};
use merlin::Transcript;
use num_bigint::BigUint;
use num_traits::Num;

use crate::utils::add_to_transcript;

#[derive(Clone, Debug, Default, CanonicalSerialize, CanonicalDeserialize)]
pub struct DLogPoK<G: Group> {
    pub c: G::ScalarField,
    pub s: Vec<Vec<G::ScalarField>>,
    pub extra_values: Option<ExtraProofValues<G>>,
}

// When we prove knowledge of ecdsa signatures using an external prover, the DLogPoK will have more values
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ExtraProofValues<G: Group> {
    pub l_prime: G,
    pub z: G,
    pub s_any: G::ScalarField,
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
    /// proves knowledge of the representations of y1, y2, ... y_n
    /// in their respective bases -- bases[1], bases[2], ... bases[n]
    /// optionally, specify a set of positions to assert equality of in the form {(i1,j1), (i2,j2), ...}
    /// TODO: shrink the proof size by compressing the responses since they're the same for all the equal positions
    pub fn prove(
        y: &Vec<G>,
        bases: &Vec<Vec<G>>,
        scalars: &Vec<Vec<G::ScalarField>>,
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

        for i in 0..y.len() {
            let mut ri = Vec::new();
            for _ in 0..bases[i].len() {
                ri.push(G::ScalarField::rand(&mut rng));
            }

            r.push(ri);
        }

        // if eq_pos is some change the randomness of those positions to be the same
        if eq_pos.is_some() {
            let eq_pos = eq_pos.unwrap();
            let common_r = r[eq_pos[0].0][eq_pos[0].1];

            eq_pos.iter().for_each(|(i, j)| {
                r[*i][*j] = common_r;
            });
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
            extra_values: None,
        }
    }

    pub fn verify(
        &self,
        bases: &Vec<Vec<G>>,
        y: &Vec<G>,
        eq_pos: Option<Vec<(usize, usize)>>,
    ) -> R1CSResult<bool> 
    where
        G: CurveGroup + VariableBaseMSM,    
    {
        // compute the challenge
        // serialize and hash the bases, k and y
        let dl_verify_timer = start_timer!(|| format!("DlogPoK verify y.len = {}", y.len()));
        let mut ts: Transcript = Transcript::new(&[0u8]);

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
            let eq_pos = eq_pos.unwrap();
            eq_pos.iter().for_each(|(i, j)| {
                assert_eq!(self.s[*i][*j], self.s[eq_pos[0].0][eq_pos[0].1]);
            });
        }

        // get the challenge
        let mut c_bytes = [0u8; 31];
        ts.challenge_bytes(&[0u8], &mut c_bytes);
        let c = G::ScalarField::from_random_bytes(&c_bytes).unwrap();

        end_timer!(dl_verify_timer);

        // check the challenge matches
        Ok(c == self.c)
    }

    // Computes Pedersen commitments for the ecdsa sigma protocol
    // Since we need Z before we can compute the commitment, this is a separate function
    pub fn pedersen_commit(
        m: &G::ScalarField,
        bases: &Vec<<G as CurveGroup>::Affine>,
    ) -> PedersenOpening<G>
    where
        G: CurveGroup + VariableBaseMSM,
    {
        assert!(bases.len() == 2);
        let mut rng = thread_rng();
        let r = G::ScalarField::rand(&mut rng);
        let scalars = vec![m.clone(), r];
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
                "ECDSA sigma proof base {}",
                i
            )));
        }
        bases_g
    }

    // (NIZK Adapter version 2)
    // TODO: This proof needs better documentation
    // The IOs contain x such that d = r*x + H(x, k), where r is a challenge derived as described below
    // Since the field size is 254 bits and h = SHA-256(signed data) is 256-bits,
    // h is split in two: h= x||b, where x is 248 bits and b is 8 bits.
    // The input to the ECDSA sub-prover is a commitment to the digest value x, and the orchestration layer above proves that
    // x is also an IO of the Groth16 proof.
    // Let mask = H(x,k) (H is Poseidon, defined over the Groth16 field)
    // We need to commit to mask, and recompute c in the exponent to prove it's well-formed
    // As a sigma protocol, we have:
    // g1, g2:  bases for Pedersen commitments
    // Z = g1^mask * g2^r_m     // Pedersen commitment to mask (computed in sub-prover)
    // L' = g1^x * g2^r_L       // Pedersen commitment to x, (input to sub-prover)
    // Prove knowledge of representation of L'
    // L'^r * Z = g1^d * g2^any
    //  equivalently: g2^any = (L'^r * Z)/g1^d
    // (`any` is unconstrained, but honest prover uses any = r_L*r + r_m )
    // The challenge is computed r = Hash(binding commitments to x and mask) = Hash(L', Z)
    // Note that we don't need to prove knowledge of the opening of Z, since mask is allowed to be anything.
    pub fn prove_for_ecdsa(
        //y: &G,
        // bases: &Vec<G>,
        // scalars: &Vec<G::ScalarField>,
        mask_commitment: &PedersenOpening<G>,
        digest_pedersen: &PedersenOpening<G>,
        digest_commitment: &G::ScalarField,
        commitment_challenge: &String,
        //hpos: usize,
    ) -> Self
    where
        G: CurveGroup,
    {
        let mut rng = thread_rng();
        let dl_proof_timer = start_timer!(|| "DLogPok Prove with external ECDSA proof");

        // Note that Z = mask_commitment, L' = digest_pedersen

        // Prove knowledge of representations, compute commitment step of Sigma protocol
        // For g2^any = (L'^r * Z)/g1^c, compute g2_any2 = g2^r_any
        let r_any = G::ScalarField::rand(&mut rng);
        let g2_any2 = mask_commitment.bases[1] * r_any;

        // Compute the challenge c = H(pedersen_bases, g3_any2, l_prime, Z, commitment_challenge, digest_commitment)

        let mut ts: Transcript = Transcript::new(b"DLogPok with external ECDSA proof");
        add_to_transcript(&mut ts, b"num_pedersen_bases", &mask_commitment.bases.len());
        for pedersen_base in &mask_commitment.bases {
            add_to_transcript(&mut ts, b"pedersen_base", pedersen_base);
        }

        add_to_transcript(&mut ts, b"g3_any2", &g2_any2);
        add_to_transcript(&mut ts, b"digest_pedersen", &digest_pedersen.c);
        add_to_transcript(&mut ts, b"mask_commitment", &mask_commitment.c);
        let com_chal_scalar = biguint_to_scalar::<G::ScalarField>(
            &BigUint::from_str_radix(&commitment_challenge, 16).unwrap(),
        );
        add_to_transcript(&mut ts, b"commitment_challenge", &com_chal_scalar);
        add_to_transcript(&mut ts, b"digest_commitment", digest_commitment);

        let mut c_bytes = [0u8; 31];
        ts.challenge_bytes(&[0u8], &mut c_bytes);
        let c = G::ScalarField::from_random_bytes(&c_bytes).unwrap();

        // Compute responses
        // For g2^any
        let any = digest_pedersen.r * com_chal_scalar + mask_commitment.r;
        let s_any = r_any - c * any;

        end_timer!(dl_proof_timer);

        let extra_values = ExtraProofValues {
            l_prime: digest_pedersen.c, // TODO: is this already communicated to the verifier?
            z: mask_commitment.c,
            s_any,
        };

        DLogPoK {
            c,
            s: vec![Vec::new()], // TODO: This was holding the responses for the proof of com_l, which is no longer needed. Could pack s_any in here
            extra_values: Some(extra_values),
        }
    }

    pub fn verify_for_ecdsa(
        &self,
        pedersen_bases: &Vec<G>,
        digest_commitment: &G::ScalarField,
        commitment_challenge: &String,
    ) -> R1CSResult<bool>
    where
        G: CurveGroup,
    {
        let dl_verify_timer = start_timer!(|| "DLogPok Verify with external ECDSA proof");
        assert!(self.extra_values.is_some());
        let extra_values = self.extra_values.clone().unwrap();

        // For L'^r * Z = g1^d * g2^any, recompute g2_any2 = g2^r_any using L' and Z
        let com_chal_scalar = biguint_to_scalar::<G::ScalarField>(
            &BigUint::from_str_radix(&commitment_challenge, 16).unwrap(),
        );
        let lhs = (extra_values.l_prime * com_chal_scalar + extra_values.z)
            - pedersen_bases[0] * digest_commitment;
        let mut recomputed_g2_any2 = pedersen_bases[1] * extra_values.s_any;
        recomputed_g2_any2 += lhs * self.c;

        // Recompute challenge and check it matches

        let mut ts: Transcript = Transcript::new(b"DLogPok with external ECDSA proof");
        add_to_transcript(&mut ts, b"num_pedersen_bases", &pedersen_bases.len());
        for base in pedersen_bases {
            add_to_transcript(&mut ts, b"pedersen_base", base);
        }
        add_to_transcript(&mut ts, b"g3_any2", &recomputed_g2_any2);
        add_to_transcript(&mut ts, b"digest_pedersen", &extra_values.l_prime);
        add_to_transcript(&mut ts, b"mask_commitment", &extra_values.z);
        add_to_transcript(&mut ts, b"commitment_challenge", &com_chal_scalar);
        add_to_transcript(&mut ts, b"digest_commitment", digest_commitment);

        let mut c_bytes = [0u8; 31];
        ts.challenge_bytes(&[0u8], &mut c_bytes);
        let c = G::ScalarField::from_random_bytes(&c_bytes).unwrap();

        end_timer!(dl_verify_timer);

        Ok(c == self.c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Bn254;
    use ark_ec::{pairing::Pairing, AffineRepr};
    use ark_ff::PrimeField;
    use ark_std::{test_rng, Zero};
    use num_bigint::{BigUint, RandBigInt};
    use num_traits::Num;
    use spartan_ecdsa::{ECDSAParams, ECDSAProof, NamedCurve};

    type G1 = <Bn254 as Pairing>::G1;
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
        let pok = DLogPoK::<G1>::prove(
            &vec![y.clone(), y.clone()],
            &vec![bases.clone(), bases.clone()],
            &vec![scalars.clone(), scalars.clone()],
            Some(vec![(0, 1), (1, 1)]),
        );

        let result = pok.verify(
            &vec![bases.clone(), bases.clone()],
            &vec![y.clone(), y.clone()],
            Some(vec![(0, 1), (1, 1)]),
        );
        assert!(result.is_ok());
        assert!(result.unwrap() == true);
    }

    #[test]
    fn test_dlog_pok_for_ecdsa() {
        let rng = &mut test_rng();

        let h = BigUint::from_str_radix(
            "115792089237316195423570985008687907853269984665640564039457584007913129639680",
            10,
        )
        .unwrap(); // 256-bit, 248 ones followed by 8 zeros
        let b = 0u8;
        let x = BigUint::from_str_radix(
            "452312848583266388373324160190187140051835877600158453279131187530910662655",
            10,
        )
        .unwrap(); // 248 ones
        let h_hexstr = h.to_str_radix(16);

        assert_eq!(h, &x * 256u32 + b);

        let params = ECDSAParams::new(NamedCurve::Secp256k1, NamedCurve::Bn254);
        let commitment_opening = ECDSAProof::commit_digest_part1(&params, &h_hexstr);

        let commitment_challenge = rng.gen_biguint(248).to_str_radix(16);
        let (digest_commitment, commitment_opening) =
            ECDSAProof::commit_digest_part2(&params, commitment_opening, &commitment_challenge);

        let mask = biguint_to_scalar(&BigUint::from_bytes_le(&ECDSAProof::get_mask(
            &commitment_opening,
        )));
        let bases = DLogPoK::<G1>::derive_pedersen_bases();
        let mask_commitment = DLogPoK::pedersen_commit(&mask, &bases);
        let x_scalar = F::from_be_bytes_mod_order(&x.to_bytes_be());
        let x_commitment = DLogPoK::pedersen_commit(&x_scalar, &bases);

        let digest_commitment = biguint_to_scalar::<F>(&BigUint::from_bytes_le(&digest_commitment));
        let pok = DLogPoK::<G1>::prove_for_ecdsa(
            &mask_commitment,
            &x_commitment,
            &digest_commitment,
            &commitment_challenge,
        );

        let bases_proj = bases.iter().map(|x| x.into_group()).collect();

        let result = pok.verify_for_ecdsa(&bases_proj, &digest_commitment, &commitment_challenge);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);
    }
}
