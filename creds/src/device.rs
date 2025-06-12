#![allow(non_snake_case)]
use ark_ec::{CurveGroup, Group, VariableBaseMSM};
use ark_ff::PrimeField;
use ark_std::UniformRand;
use num_bigint::BigUint;
use rand::thread_rng;
use sha2::{Digest, Sha256};

use crate::dlog::{DLogPoK, PedersenOpening};
use ecdsa_pop::{ECDSAProof, ECDSAProofCircuit};
use crate::utils::scalar_to_biguint;
use ark_serialize::CanonicalSerialize;
use ark_serialize::CanonicalDeserialize;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::ecdsa::signature::hazmat::PrehashSigner;

const CONTEXT_E : &[u8] = "computing challenge for linking proof".as_bytes();
const CONTEXT_PI0 : &[u8] = "creating sigma proof pi0 for linking proof".as_bytes();
const CONTEXT_PI1 : &[u8] = "creating sigma proof pi1 for linking proof".as_bytes();

pub struct ECDSASig {
    pub r: BigUint, 
    pub s: BigUint, 
    pub digest: Vec<u8>
}
pub struct TestDevice {
    keypair : SigningKey,
    public_key : VerifyingKey
}

impl ECDSASig {
    pub fn new_from_bytes(digest: &[u8], sig_bytes: &[u8]) -> Self {
        assert!(sig_bytes.len() == 64);
        let (r_bytes, s_bytes) = sig_bytes.split_at(32);
        let r = BigUint::from_bytes_be(r_bytes);
        let s = BigUint::from_bytes_be(s_bytes);

        ECDSASig{ r, s, digest : digest.to_vec()}
    }
}

impl TestDevice {
    pub fn new_with_keygen() -> Self {
        let mut rng = thread_rng();
        let keypair = SigningKey::random(&mut rng);
        let public_key = *keypair.verifying_key();
        Self {keypair, public_key}
    }
    pub fn new_from_file(secret_key_file : &str) -> Self {
        let secret_key_pem  = std::fs::read_to_string(secret_key_file).unwrap();
        Self::new_from_pem(&secret_key_pem)
    }
    pub fn new_from_pem(secret_key_pem : &str) -> Self {
        let secret_key = secret_key_pem.parse::<p256::SecretKey>().unwrap();
        let keypair = SigningKey::from_bytes(&secret_key.to_bytes()).unwrap();
        let public_key = *keypair.verifying_key();
        
        Self{keypair, public_key}
    }
    pub fn sign(&self, digest : &[u8]) -> Vec<u8> {
        let sig : Signature = match self.keypair.sign_prehash(digest) {
            Ok(s) => s, 
            Err(_) => { panic!("failed to create ecdsa signature"); }
        };
        sig.to_bytes().to_vec()
    }
    pub fn get_public_key(&self) -> (BigUint, BigUint) {
        let pk_bytes = self.public_key.to_sec1_bytes(); 
        assert!(pk_bytes[0] == 0x04);// make sure it's uncompressed
        let pk_bytes = &pk_bytes[1..];
        assert!(pk_bytes.len() == 64);
        let (pk_x, pk_y) = pk_bytes.split_at(32);
        let pk_x = BigUint::from_bytes_be(pk_x);
        let pk_y = BigUint::from_bytes_be(pk_y);
        
        (pk_x, pk_y)
    }
}    



#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct DeviceProof<G : Group> {
    r_x: BigUint,
    r_y: BigUint,
    digest: Vec<u8>,
    com1: G,    // Prover-computed version of com1 with the same bases as com0
    comz: G,
    h_Q : Vec<u8>,
    m : G::ScalarField,
    pi0 : DLogPoK<G>, 
    pi1 : DLogPoK<G>, 
    pi2 : Vec<u8>
}

impl<G: Group> DeviceProof<G> {

    pub fn prove(com0 : &PedersenOpening<G>, com1: &PedersenOpening<G>, sig: &ECDSASig, pubkey_x: &BigUint, pubkey_y: &BigUint) 
    -> DeviceProof<G>
        where 
            G: CurveGroup + VariableBaseMSM, 
            G::ScalarField : PrimeField, 
    {
        let mut rng = thread_rng();
        let z = G::ScalarField::rand(&mut rng);
        let comz = DLogPoK::<G>::pedersen_commit(&z, &com0.bases);
        
        let q0 : BigUint = com0.m.into();
        let q1 : BigUint = com1.m.into();
        let z  : BigUint = comz.m.into();

        let params = ecdsa_pop::ECDSAParams::new(ecdsa_pop::NamedCurve::Secp256r1, ecdsa_pop::NamedCurve::Bn254);
        let h_Q = ECDSAProofCircuit::compute_hQ(&params, &q0, &q1, &z);

        // com1 and com0 have different bases, so we have to re-create com1 with the same bases as com0 (and prove it's correct)
        let com1_orig = com1;
        let com1 = DLogPoK::<G>::pedersen_commit(&com1_orig.m, &com0.bases);
        // Compute \pi_0: proof that com1 and com1_orig commit to the same message, 
        //  {(m, r0, r1) : com1_orig = G1^m H1^r1  AND  com1 = G0^m H0^r0}
        let bases1 = vec![com1_orig.bases[0].into(), com1_orig.bases[1].into()];
        let bases2 = vec![com0.bases[0].into(), com0.bases[1].into()];
        let scalars1 = vec![com1_orig.m, com1_orig.r];
        let scalars2 = vec![com1.m, com1.r];
        let pi0 = DLogPoK::prove(Some(CONTEXT_PI0), &[com1_orig.c, com1.c], &[bases1, bases2], &[scalars1, scalars2], Some(vec![(0,0)]));

        let mut sha2 = Sha256::new();
        sha2.update(CONTEXT_E);
        sha2.update(pi0.c.to_string());
        sha2.update(com0.c.to_string());
        sha2.update(com1.c.to_string());
        sha2.update(comz.c.to_string());
        sha2.update(&h_Q);
        let digest = sha2.finalize();
        let e1_bytes = &digest[0..16];
        let e2_bytes = &digest[16..32];

        // Compute    m = q0 + q1*e1 + z*e2 (mod q)
        //  and     C_m = C0 + e1 * C1 + e2 * Cz
        let e1 = G::ScalarField::from_le_bytes_mod_order(e1_bytes);
        let e2 = G::ScalarField::from_le_bytes_mod_order(e2_bytes);
        let q0 = com0.m;
        let q1 = com1.m;
        let z = comz.m;
        let m = q0 + q1*e1 + z*e2;
        let c = (com0.c + (com1.c * e1) + (comz.c * e2)).into_affine();
        let r =  com0.r + com1.r*e1     + comz.r*e2;
        let comm = PedersenOpening::<G>{bases: com0.bases.clone(), m, r, c: c.into()};

        // Compute \pi_1 proof that  { (r, z, t) : Cm/G^m == H^r (for any r)  AND C_z = G^z * H^t }
        // (note that m is public here)
        let g = com0.bases[0].into();
        let h = com0.bases[1].into();
        let lhs1 = comm.c.into() + (g * (-m));
        assert!(lhs1 == h * r);
        let bases1 : Vec<G> = vec![h];
        let scalars1 = vec![r];
        let lhs2 = comz.c;
        let bases2 : Vec<G> = vec![g, h];
        let scalars2 = vec![z, comz.r];
        let pi1 = DLogPoK::prove(Some(CONTEXT_PI1), &[lhs1, lhs2], &[bases1, bases2], &[scalars1, scalars2], None);

        // Call the snark part
        let (r_x, r_y, pi2) = ECDSAProof::prove(&params, pubkey_x, pubkey_y, &sig.r, &sig.s, &sig.digest, &h_Q, &scalar_to_biguint(&m), e1_bytes, e2_bytes, &scalar_to_biguint(&z), false);

        DeviceProof { r_x, r_y, digest: sig.digest.clone(), com1: com1.c, comz: comz.c, h_Q, m, pi0, pi1, pi2 }     
    }

    pub fn verify(proof: &DeviceProof<G>, com0: &G::Affine, com1: &G::Affine, bases: &[G::Affine], bases_com1: &[G::Affine]) -> bool
        where 
            G: CurveGroup + VariableBaseMSM, 
            G::ScalarField : PrimeField, 
     {
        // Check pi0, proof that com1 commits to the same value as com1_orig
        //  {(m, r0, r1) : com1_orig = G1^m H1^r1  AND  com1 = G0^m H0^r0}
        let bases1 = vec![bases_com1[0].into(), bases_com1[1].into()];
        let bases2 = vec![bases[0].into(), bases[1].into()];
        let pi0_valid = DLogPoK::verify(&proof.pi0, Some(CONTEXT_PI0), &[bases1, bases2], &[(*com1).into(), proof.com1], Some(vec![(0,0)]));
        if !pi0_valid {
            println!("Failed to verify device proof, proof.pi0 did not verify");
            return false;
        }
        let com1 = proof.com1;

        // Re-compute e1, e2
        let mut sha2 = Sha256::new();
        sha2.update(CONTEXT_E);
        sha2.update(proof.pi0.c.to_string());
        sha2.update(com0.to_string());
        sha2.update(com1.to_string());
        sha2.update(proof.comz.to_string());
        sha2.update(&proof.h_Q);
        let e_digest = sha2.finalize();
        let e1_bytes = &e_digest[0..16];
        let e2_bytes = &e_digest[16..32];

        // Recompute comm, commitment to m
        let e1 = G::ScalarField::from_le_bytes_mod_order(e1_bytes);
        let e2 = G::ScalarField::from_le_bytes_mod_order(e2_bytes);        
        let comm = (*com0 + (com1 * e1) + (proof.comz * e2)).into_affine();

        // Verify sigma proof pi1, { (r, z, t) : Cm/G^m == H^r (for any r)  AND C_z = G^z * H^t }
        let g = bases[0].into();
        let h = bases[1].into();
        let lhs1 = comm.into() + (g * (-proof.m));
        let bases1 : Vec<G> = vec![h];
        let lhs2 = proof.comz;
        let bases2 : Vec<G> = vec![g, h];
        let pi1_valid = proof.pi1.verify(Some(CONTEXT_PI1), &[bases1, bases2], &[lhs1, lhs2], None);

        if !pi1_valid {
            println!("Failed to verify device proof, proof.pi1 did not verify");
            return false;
        }

        let params = ecdsa_pop::ECDSAParams::new(ecdsa_pop::NamedCurve::Secp256r1, ecdsa_pop::NamedCurve::Bn254);
        let pi2_valid = ECDSAProof::verify(&params, &proof.r_x, &proof.r_y, &proof.digest, &proof.h_Q, &scalar_to_biguint(&proof.m), e1_bytes, e2_bytes, &proof.pi2);

        if !pi2_valid {
            println!("Failed to verify device proof, proof.pi2 did not verify");
            return false;
        }        

        true
    }

}


#[cfg(test)]
mod tests {
    use crate::utils::biguint_to_scalar;

    use super::*;
    use ark_bn254::Bn254;
    use ark_ec::pairing::Pairing;
    use ark_std::{end_timer, start_timer};
    use num_traits::Num;
    use ecdsa_pop::ECDSAProof; 

    type G1 = <Bn254 as Pairing>::G1;
    //type G1Affine = <Bn254 as Pairing>::G1Affine;
    type F = <Bn254 as Pairing>::ScalarField;    

    // converts a hex-encoded string into a BigUint
    pub fn hex_to_big(hex: &str) -> BigUint {    
        BigUint::from_str_radix(hex, 16).unwrap()
    }  

    fn create_mock_commitments(q_x : &BigUint) -> (PedersenOpening<G1>, PedersenOpening<G1>) 
    {
        // Mock up the commitment inputs to the device proof
        let (q0, q1) = ECDSAProof::split_public_key_x(q_x);
        let q0 = biguint_to_scalar::<F>(&q0);
        let q1 = biguint_to_scalar::<F>(&q1);

        let bases = DLogPoK::<G1>::derive_pedersen_bases();
        let com0 = DLogPoK::<G1>::pedersen_commit(&q0, &bases);

        // In the show protocol, com1 has a different base value g
        let bases1 = vec![(bases[0] * F::from(7)).into(), bases[1]];
        let com1 = DLogPoK::<G1>::pedersen_commit(&q1, &bases1);

        (com0, com1)
    }

    #[test]
    fn test_device_proof() {
        // test from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P256_SHA256.pdf        
        let q_x = hex_to_big("B7E08AFDFE94BAD3F1DC8C734798BA1C62B3A0AD1E9EA2A38201CD0889BC7A19");
        let q_y = hex_to_big("3603F747959DBF7A4BB226E41928729063ADC7AE43529E61B563BBC606CC5E09");
        let digest = hex::decode("A41A41A12A799548211C410C65D8133AFDE34D28BDD542E4B680CF2899C8A8C4").unwrap();
        let r = hex_to_big("2B42F576D07F4165FF65D1F3B1500F81E44C316F1F0B3EF57325B69ACA46104F");
        let s = hex_to_big("DC42C2122D6392CD3E3A993A89502A8198C1886FE69D262C4B329BDB6B63FAF1");        

        let sig = ECDSASig{ r: r.clone(), s : s.clone(), digest : digest.clone() };
        let (com0, com1) = create_mock_commitments(&q_x);
        let proof = DeviceProof::prove(&com0, &com1, &sig, &q_x, &q_y);
        let valid = DeviceProof::verify(&proof, &com0.c.into(), &com1.c.into(), &com0.bases, &com1.bases);
        assert!(valid); 

        println!("\nTest with bad signature, expect proof generation to fail");
        let sig = ECDSASig{ r: r.clone()-BigUint::from(1u32), s: s.clone(), digest: digest.clone() };
        let (com0, com1) = create_mock_commitments(&q_x);
        let result = std::panic::catch_unwind(|| 
            DeviceProof::prove(&com0, &com1, &sig, &q_x, &q_y)
        );
        assert!(result.is_err());        

        println!("\nTest with bad signature, expect proof verification to fail");
        let sig = ECDSASig{ r: r.clone(), s : s.clone(), digest : digest.clone() };
        let (com0, com1) = create_mock_commitments(&q_x);
        let mut proof = DeviceProof::prove(&com0, &com1, &sig, &q_x, &q_y);
        proof.digest[0] ^= 0x01;
        let valid = DeviceProof::verify(&proof, &com0.c.into(), &com1.c.into(), &com0.bases, &com1.bases);
        assert!(!valid);        

        println!("\nTest with bad ECDSA proof, expect proof verification to fail");
        let sig = ECDSASig{ r: r.clone(), s : s.clone(), digest : digest.clone() };
        let (com0, com1) = create_mock_commitments(&q_x);
        let mut proof = DeviceProof::prove(&com0, &com1, &sig, &q_x, &q_y);
        proof.pi2[100] ^= 0x01;
        let valid = DeviceProof::verify(&proof, &com0.c.into(), &com1.c.into(), &com0.bases, &com1.bases);
        assert!(!valid);          
    }

    #[test]
    fn test_mock_device_proof() {
        let nonce: [u8; 32] = rand::random();
        let digest = Sha256::digest(nonce);
        let device = TestDevice::new_with_keygen();
        let sig_bytes = device.sign(&digest);
        let sig = ECDSASig::new_from_bytes(&digest, &sig_bytes);
        let (q_x, q_y) = device.get_public_key();
        let (com0, com1) = create_mock_commitments(&q_x);
        let t = start_timer!(||"DeviceProof::prove");
        let proof = DeviceProof::prove(&com0, &com1, &sig, &q_x, &q_y);
        end_timer!(t);
        let t = start_timer!(||"DeviceProof::verify");
        let valid = DeviceProof::verify(&proof, &com0.c.into(), &com1.c.into(), &com0.bases, &com1.bases);
        end_timer!(t);
        assert!(valid); 
    }

}
