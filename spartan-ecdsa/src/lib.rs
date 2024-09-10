//! This library implements `Spartan`-compatible circuits proving knowledge of ECDSA signatures
//! The circuits are fed to `Spartan` zkSNARK by expressing them in Rust with `bellpepper` library.
#![deny(
  warnings,
  unused,
  future_incompatible,
  nonstandard_style,
  rust_2018_idioms,
  missing_docs
)]
#![allow(non_snake_case)]
#![forbid(unsafe_code)]



mod ecc;
mod ecdsa;
mod errors;
mod utils;
mod poseidon;
mod nonnative;
/// Commtiment type for ECDSA hashes
pub mod commitment;

use crate::errors::ECDSAError;
use crate::{ecc::AllocatedPoint, ecdsa::Signature, commitment::CommitmentGadget};
use bellpepper_core::num::AllocatedNum;
use bellpepper_core::{Circuit, ConstraintSystem, SynthesisError};
use commitment::{Commitment, CommitmentOpening};
use ff::PrimeField;
use halo2curves::secp256k1::Fp as Scalar;
use nonnative::bignat::BigNat;
use num_bigint::{BigUint, ToBigInt};
use num_traits::Num;
use poseidon::PoseidonConstantsCircuit;
use spartan2::{ProverKey, VerifierKey, SNARK};
use ff::Field;
use ark_std::{end_timer, start_timer};
use utils::biguint_to_scalar;

/// converts a vector of 32 u8s in big-endian format into a Scalar
fn be_bytes_to_ff(be_bytes: &[u8]) -> Scalar {
  assert_eq!(be_bytes.len(), 32);
  let le_bytes = be_bytes.iter().rev().copied().collect::<Vec<u8>>();
  let mut arr = [0; 32];
  arr.copy_from_slice(&le_bytes[0..32]);
  Scalar::from_repr(arr).unwrap()
}

/// converts a hex-encoded string into a Scalar
fn hex_to_ff(hex: &str) -> Scalar {
  let v = hex::decode(hex).unwrap().to_vec();
  be_bytes_to_ff(&v)
}

///////////////////////////////////////////////

/// An enum to select the elliptic curve used with ECDSA
#[derive(Clone, PartialEq)]
pub enum NamedCurve {
  /// The "bitcoin curve"  https://w3c-ccg.github.io/lds-ecdsa-secp256k1-2019/
  Secp256k1,
  /// The BN254 curve used by Ethereum and others https://neuromancer.sk/std/bn/bn254 
  Bn254,    
  /// Pairing-friendly curve with 128-bit security https://neuromancer.sk/std/bls/BLS12-381 
  Bls12381
}

/// Holds public parameters for the circuit
#[derive(Clone)]
pub struct ECDSAParams {
  /// Enum that indicates which curve we have, by name
  pub curve: NamedCurve,
  /// x-coord of group generator point
  pub g_x: Scalar, 
  /// y-coord of group generator point
  pub g_y: Scalar,
  /// Poseidon constants
  pub constants: PoseidonConstantsCircuit<Scalar>,
  /// Prime defining the field used for the commitment scheme (treated as non-native)
  pub commit_prime: BigUint
}

impl ECDSAParams {
  /// constructs public parameters using hex-encoded strings
  /// `ecdsa_curve`: curve where the ECDSA signature was created
  /// `commitment_curve`: curve used by the proof system that created the commitment to the digest
  pub fn new(ecdsa_curve: NamedCurve, commitment_curve: NamedCurve) -> Self {
    match ecdsa_curve {
      NamedCurve::Secp256k1 => {
        let g_x = hex_to_ff("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
        let g_y = hex_to_ff("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
        let constants = Commitment::create_constants();
        let commit_prime = match commitment_curve {
          NamedCurve::Bn254 => {
              BigUint::from_str_radix("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", 16).unwrap()
          }
          NamedCurve::Bls12381 => {
              BigUint::from_str_radix("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16).unwrap()
          }
          _ => {
            panic!("Unsupported commitment curve");
          }
        };
// // TODO: Ensure Commitment::NUM_HASH_BITS less than commit_prime's bitlength        
        Self { curve:ecdsa_curve, g_x, g_y, constants, commit_prime}
      }
      _ => {
        panic!("Unsupported ECDSA curve");
      }
    }
  }
}


/// Holds the prover's inputs to the ECDSA proof circuit
#[derive(Clone)]
pub struct ECDSACircuitProverInputs {
  // hash of message to be signed, known only to prover
  digest: Scalar,
  // signature as (r, s_inv), know only to prover
  r: Scalar,
  s_inv: Scalar,
  //pk in uncompressed form (x,y), will be an output of the circuit
  pk_x: Scalar,
  pk_y: Scalar  
}

impl ECDSACircuitProverInputs {

  /// constructs prover inputs to the ECDSA proof circuit
  // Input h, r, s as hex strings.
  pub fn new(digest: &str, r: &str, s: &str, pk_x : &str, pk_y : &str) -> Result<Self, ECDSAError> {

    let digest_scalar = hex_to_ff(&digest);
    let r_scalar = hex_to_ff(r);
    let s_inv_scalar = {
      // modulus of secp256k1's base field
      let p = BigUint::parse_bytes(
        b"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",  // TODO: use params instead of hardcoding
        16,
      )
      .unwrap();
      let two = BigUint::parse_bytes(b"2", 10).unwrap();
      //let s_biguint = BigUint::from_bytes_be(&s_bytes);
      let s_biguint = BigUint::from_str_radix(s, 16).unwrap();
      let s_inv = s_biguint.modpow(&(&p - two), &p);
      let s_inv_bytes = s_inv.to_bytes_be();
      be_bytes_to_ff(s_inv_bytes.as_slice())
    };

    Ok(Self { digest: digest_scalar, r: r_scalar, s_inv: s_inv_scalar, pk_x: hex_to_ff(pk_x), pk_y: hex_to_ff(pk_y)})
  }

}

/// Holds opening information about the commitment to the digest
#[derive(Clone)]
pub struct CommitmentInputs{
  /// Poseidon constants
  pub constants: PoseidonConstantsCircuit<Scalar>,
  /// Opening of the commitment the prover knows
  pub opening: Option<CommitmentOpening>,
  /// r is a challenge used to form the commitment
  pub r: Option<BigUint>,
  /// p is a fixed prime defining the field that the commitment is computed over
  pub p: BigUint,
}

/// Holds the ECDSA proof circuit
#[derive(Clone)]
pub struct ECDSAProofCircuit {
  params: ECDSAParams,
  prover_inputs: Option<ECDSACircuitProverInputs>,  
  commitment_inputs: Option<CommitmentInputs> 
}

impl ECDSAProofCircuit {
  /// constructs the selective disclosure circuit
  pub fn new(params: &ECDSAParams, prover_inputs: Option<ECDSACircuitProverInputs>, commitment_inputs: Option<CommitmentInputs>) -> Result<Self, ECDSAError> {

    Ok(Self { params: params.clone(),  prover_inputs : prover_inputs.clone(), commitment_inputs: commitment_inputs.clone() })
  }
  
}

impl Circuit<Scalar> for ECDSAProofCircuit {

  fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {

    let limb_width = Commitment::<Scalar>::LIMB_WIDTH;
    let n_limbs = Commitment::<Scalar>::N_LIMBS;

      let unwrap_to_results = |opening: &Option<CommitmentOpening>, cinputs: &CommitmentInputs| {
        if opening.is_some() {
          assert!(opening.as_ref().unwrap().c.is_some());
          let opening = opening.as_ref().unwrap();
          (
            Ok(opening.c.as_ref().unwrap().to_bigint().unwrap()), 
            Ok(biguint_to_scalar::<Scalar>(&opening.k)),
            Ok(biguint_to_scalar::<Scalar>(&opening.x)),
            Some(opening.b), 
            Ok(cinputs.r.clone().unwrap().to_bigint().unwrap()), 
            Ok(biguint_to_scalar(&opening.c.as_ref().unwrap())),
            Ok(biguint_to_scalar(&cinputs.r.clone().unwrap())),
          )
        }
        else {
          (
            Err(SynthesisError::AssignmentMissing), 
            Err(SynthesisError::AssignmentMissing), 
            Err(SynthesisError::AssignmentMissing), 
            None, 
            Err(SynthesisError::AssignmentMissing),
            Err(SynthesisError::AssignmentMissing),
            Err(SynthesisError::AssignmentMissing)
          )
        }
      };
      

    // If the digest is committed, first reconstruct it, otherwise allocate provided digest
    let h = {
      if self.commitment_inputs.is_some() {
        let cinputs = self.commitment_inputs.unwrap();
                
        let (c_res, k_res, x_res, b_opt, r_res, c_res2, r_res2) = unwrap_to_results(&cinputs.opening, &cinputs);
        let c = BigNat::alloc_from_nat(&mut cs.namespace(||"c"), ||c_res, limb_width, n_limbs)?;
        let r = BigNat::alloc_from_nat(&mut cs.namespace(||"r"), ||r_res, limb_width, n_limbs)?;
        let p = BigNat::alloc_from_nat(&mut cs.namespace(||"p"), ||Ok(cinputs.p.to_bigint().unwrap()), limb_width, n_limbs)?;

        let k  = AllocatedNum::alloc(&mut cs.namespace(||"k"),  || k_res)?;
        let x = AllocatedNum::alloc(&mut cs.namespace(||"x"), || x_res)?;

        // The commitment values c, r are public IOs
        // TODO: BUG we cheat for now and just allocate them as scalars, rather than the BigNat limbs; 
        // we know they'll fit in scalars.
        let c_alloc = AllocatedNum::alloc(&mut cs.namespace(||"c alloc"), ||c_res2)?;
        let r_alloc = AllocatedNum::alloc(&mut cs.namespace(||"r alloc"), ||r_res2)?;
        c_alloc.inputize(cs.namespace(||"c input"))?;
        r_alloc.inputize(cs.namespace(||"r input"))?;

        CommitmentGadget::build_digest(cs.namespace(||"build digest"), &cinputs.constants, &c, &r, &p, cinputs.p.bits() as usize, &k, &x, b_opt)?
      }
      else {
        AllocatedNum::<Scalar>::alloc(cs.namespace(||"h"), ||{
          if self.prover_inputs.is_some() {
            let pi = self.prover_inputs.clone().unwrap();
            Ok(pi.digest)
          } else {
            Err(SynthesisError::AssignmentMissing)
          }
        })?
      }
    };

    // allocate and make pk and g as public IO
    let g = AllocatedPoint::alloc(
      cs.namespace(|| "g"),
      Some((self.params.g_x, self.params.g_y, false)),
    )?;
    let pk_to_alloc = if self.prover_inputs.is_some() {
      let pi = self.prover_inputs.clone().unwrap();
      Some((pi.pk_x, pi.pk_y, false))
    } else {
      None
    };
    let pk = AllocatedPoint::alloc(
      cs.namespace(|| "pk"),
      pk_to_alloc
    )?;
    g.inputize(cs.namespace(|| "g input"))?;
    pk.inputize(cs.namespace(|| "pk input"))?;

    // allocate provided signature
    let sig_opt_scalar = if self.prover_inputs.is_some() {
      let pi = self.prover_inputs.clone().unwrap();
      Some((pi.r, pi.s_inv))
    } else {
      None
    };
    let sig = Signature::alloc(cs.namespace(|| "sig"), sig_opt_scalar)?;

    // verify the signature using the digest that was output by the hashing step
    sig.verify(cs.namespace(|| "verify"), &g, &pk, &h).unwrap();

    Ok(())
  }
}

macro_rules! define_SNARK_types {
  () => {
      type G = spartan2::provider::secp_secq::secq256k1::Point;
      type EE = spartan2::provider::hyrax_pc::HyraxEvaluationEngine<G>;
      type S = spartan2::spartan::snark::RelaxedR1CSSNARK<G, EE>;
  };
}

/// Public API for creating ECDSA proofs. The inputs are hex strings and the outputs are serialized opaque values.
/// This API assumes the digest is provided by an external commitment.
/// It's possible to have the prover supply the digest directly, but there is no equivalent high-level API for it.
pub struct ECDSAProof;

impl ECDSAProof {

  /// Run setup, return the prover key and verifier key (public parameters for the system).
  /// `p` is a prime associated to the commitment scheme.
  pub fn setup(params : &ECDSAParams) -> (Vec<u8>, Vec<u8>) {

    assert!(params.curve == NamedCurve::Secp256k1); // We only support one curve right now  
    define_SNARK_types!();
    
    // produce keys
    let commitment_public_inputs = CommitmentInputs{ constants: params.constants.clone(), opening: None, r: None, p: params.commit_prime.clone()};
    let circuit = ECDSAProofCircuit::new(params,  None, Some(commitment_public_inputs)).unwrap();    
    let timer_setup = start_timer!(|| "ECDSA SNARK::setup");
    let (pk, vk) = SNARK::<G, S, _>::setup(circuit.clone()).unwrap();
    end_timer!(timer_setup);

    let serialize_timer = start_timer!(|| "ECDSA serializing SNARK prover and verifier keys");
    let pk_bytes = bincode::serialize(&pk).unwrap();    
    let vk_bytes = bincode::serialize(&vk).unwrap();    
    end_timer!(serialize_timer);

    (pk_bytes, vk_bytes)
  }

  /// First phase of committing to a hash digest; input is in hex, returns the partial commitment opening
  pub fn commit_digest_part1(params : &ECDSAParams, digest: &str) -> Vec<u8> {
    let h = BigUint::from_str_radix(&digest, 16).unwrap();

    let com_opening = Commitment::commit_digest_part1(&params.constants, &h, &params.commit_prime);
    let commitment_opening_bytes = bincode::serialize(&com_opening).unwrap();

    commitment_opening_bytes
  }    

  /// Second phase of committing to a hash digest; given the challenge, returns the commitment and opening
  pub fn commit_digest_part2(params: &ECDSAParams, opening: Vec<u8>, challenge: &str) -> (Vec<u8>, Vec<u8>) {

    let com_opening : CommitmentOpening = bincode::deserialize(&opening).unwrap();
    let challenge = BigUint::from_str_radix(&challenge, 16).unwrap();
    let new_opening = Commitment::<Scalar>::commit_digest_part2(&com_opening, &challenge, &params.commit_prime);
    let commitment_bytes = new_opening.c.as_ref().unwrap().to_bytes_le();
    let commitment_opening_bytes = bincode::serialize(&new_opening).unwrap();
    
    (commitment_bytes, commitment_opening_bytes)
  }      

  /// Create a proof of an ECDSA signature
  pub fn prove(params : &ECDSAParams, prover_key: &Vec<u8>, digest: &str, pk_x : &str, pk_y : &str, r: &str, s: &str, challenge: &str, commitment_opening : &Vec<u8>) -> Vec<u8> {

    assert!(params.curve == NamedCurve::Secp256k1); // We only support one curve right now  
    define_SNARK_types!();

    let pk : ProverKey<G,S> = bincode::deserialize(&prover_key).unwrap();
    let com_opening : CommitmentOpening = bincode::deserialize(&commitment_opening).unwrap();
    let prover_inputs = ECDSACircuitProverInputs::new(digest, r, s, pk_x, pk_y).unwrap();
    let challenge_int = BigUint::from_str_radix(challenge, 16).unwrap();
    let commitment_prover_inputs = CommitmentInputs{ constants: params.constants.clone(), opening: Some(com_opening), r: Some(challenge_int), p: params.commit_prime.clone()};
    let prover_circuit = ECDSAProofCircuit::new(&params, Some(prover_inputs), Some(commitment_prover_inputs)).unwrap();    
    let timer_prove = start_timer!(|| "SNARK::witness-gen+prove");
    let res = SNARK::prove(&pk, prover_circuit);
    assert!(res.is_ok());
    let proof = res.unwrap();
    end_timer!(timer_prove);

    let proof_bytes = bincode::serialize(&proof).unwrap();
    
    proof_bytes
  }

  /// Extract the mask value from the (opaque) commitment opening
  pub fn get_mask(commitment_opening : &Vec<u8>) -> Vec<u8> {
    let opening : CommitmentOpening = bincode::deserialize(&commitment_opening).unwrap();
    
    opening.mask.to_bytes_le()
  }

  /// Verify the proof
  pub fn verify(params : &ECDSAParams, verifier_key : &Vec<u8>,  pk_x : &str, pk_y : &str, proof : &Vec<u8>, challenge: &str, commitment: &Vec<u8> ) -> bool {

    assert!(params.curve == NamedCurve::Secp256k1); // We only support one curve right now  
    define_SNARK_types!();
    let vk : VerifierKey<G,S> = bincode::deserialize(&verifier_key).unwrap();   
    let c = BigUint::from_bytes_le(&commitment);
    let challenge_int = BigUint::from_str_radix(challenge, 16).unwrap();
    let proof : SNARK<G, S, ECDSAProofCircuit> = bincode::deserialize(&proof).unwrap();   
    let io = vec![biguint_to_scalar(&c), biguint_to_scalar(&challenge_int), params.g_x, params.g_y, Scalar::ZERO, hex_to_ff(pk_x), hex_to_ff(pk_y), Scalar::ZERO];    
    let timer_verify = start_timer!(|| "ECDSA SNARK::verify");
    let res = proof.verify(&vk, &io);
    end_timer!(timer_verify);  
    res.is_ok()
  }

  /// Run setup, return the prover key and verifier key (public parameters for the system).
  pub fn setup_nocommit(params : &ECDSAParams) -> (Vec<u8>, Vec<u8>) {

    assert!(params.curve == NamedCurve::Secp256k1); // We only support one curve right now  
    define_SNARK_types!();
    
    // produce keys
    let circuit = ECDSAProofCircuit::new(params,  None, None).unwrap();    
    let timer_setup = start_timer!(|| "ECDSA SNARK::setup");
    let (pk, vk) = SNARK::<G, S, _>::setup(circuit.clone()).unwrap();
    end_timer!(timer_setup);

    let serialize_timer = start_timer!(|| "ECDSA serializing SNARK prover and verifier keys");
    let pk_bytes = bincode::serialize(&pk).unwrap();    
    let vk_bytes = bincode::serialize(&vk).unwrap();    
    end_timer!(serialize_timer);

    (pk_bytes, vk_bytes)
  }

  /// Create a proof of an ECDSA signature
  pub fn prove_nocommit(params : &ECDSAParams, prover_key: &Vec<u8>, digest: &str, pk_x : &str, pk_y : &str, r: &str, s: &str) -> Vec<u8> {

    assert!(params.curve == NamedCurve::Secp256k1); // We only support one curve right now  
    define_SNARK_types!();

    let pk : ProverKey<G,S> = bincode::deserialize(&prover_key).unwrap();   
    let prover_inputs = ECDSACircuitProverInputs::new(digest, r, s, pk_x, pk_y).unwrap();   
    let circuit_prover = ECDSAProofCircuit::new(&params, Some(prover_inputs), None).unwrap();     
    let timer_prove = start_timer!(|| "ECDSA SNARK::witness-gen+prove");  // TODO (perf): Is it possible to run witness generation once and cache the results? perhaps not when the hash digest is committed (the commitment changes)
    let res = SNARK::prove(&pk, circuit_prover);
    assert!(res.is_ok());
    let proof = res.unwrap();
    end_timer!(timer_prove);

    let proof_bytes = bincode::serialize(&proof).unwrap();
    
    proof_bytes
  }

  /// Verify the proof
  pub fn verify_nocommit(params : &ECDSAParams, verifier_key : &Vec<u8>,  pk_x : &str, pk_y : &str, proof : &Vec<u8>) -> bool {

    assert!(params.curve == NamedCurve::Secp256k1); // We only support one curve right now  
    define_SNARK_types!();
    let vk : VerifierKey<G,S> = bincode::deserialize(&verifier_key).unwrap();   
    let proof : SNARK<G, S, ECDSAProofCircuit> = bincode::deserialize(&proof).unwrap();        
    let io = vec![params.g_x, params.g_y, Scalar::ZERO, hex_to_ff(pk_x), hex_to_ff(pk_y), Scalar::ZERO];    
    let timer_verify = start_timer!(|| "ECDSA SNARK::verify");
    let res = proof.verify(&vk, &io);
    end_timer!(timer_verify);  
    res.is_ok()
  }

}



#[cfg(test)]
mod tests {
  use super::*;
  use ark_std::{end_timer, start_timer};
  use bellpepper_core::{test_cs::TestConstraintSystem, Comparable};
  use ff::Field;
  use num_format::{Locale, ToFormattedString};
  use spartan2::{ProverKey, VerifierKey, SNARK};
  use std::{fs, path::Path};
  use crate::commitment::Commitment;
  use num_bigint::RandBigInt;

  // cargo test --release --features print-trace test_ecdsa_proof -- --nocapture
  #[test]
  fn test_ecdsa_proof() {

    println!("Running first test");
    let digest = "3F891FDA3704F0368DAB65FA81EBE616F4AA2A0854995DA4DC0B59D2CADBD64F";
    let pk_x = "3AF1E1EFA4D1E1AD5CB9E3967E98E901DAFCD37C44CF0BFB6C216997F5EE51DF";
    let pk_y = "E4ACAC3E6F139E0C7DB2BD736824F51392BDA176965A1C59EB9C3C5FF9E85D7A";
    let r = "A5C7B7756D34D8AAF6AA68F0B71644F0BEF90D8BFD126CE951B6060498345089";
    //let s_inv = "D6E6D8E2B519D1955CF6452E05CB89143EA752A222D38F3492B7B51B83625700";
    let s = "BC9644F1625AF13841E589FD00653AE8C763309184EA0DE481E8F06709E5D1CB";
    test_ecdsa_proof_with(digest, pk_x, pk_y, r, s);

    println!("\nRunning second test");
    let digest = "AE1AB30CE075F12CADB7F66ED3C8FC0B0B203AC206F381C6E2BDC1498402BCEA";
    let pk_x = "BB8552F9F4B5EA4159EBFE9A42F8CC5B209E8CEDD3A2D0E36F1B7DB39FB45693";
    let pk_y = "B4169332E1F00C8A10AA18806235295D2596F00D13EA2921B5A20C89ACEBC822";
    let r = "C6FBBDB372303F3B65CBFCF16FF7FC4DBF6ACD921E40C93DB8207A860DB41850";
    //let s_inv = "B02D639CB9D6143C6363E5A716C0761DF817B116D1853CE528A03D64E08846B6";
    let s = "0C61995E52329CBC955A8B7891F461D8C5D1DD965E353BDF5214A1BAC9284AB2";
    test_ecdsa_proof_with(digest, pk_x, pk_y, r, s);

  }

  fn test_ecdsa_proof_with(digest: &str, pk_x: &str, pk_y: &str, r: &str, s: &str) {

    let params = ECDSAParams::new(NamedCurve::Secp256k1, NamedCurve::Bn254);
    let circuit_verifier = ECDSAProofCircuit::new(&params,  None, None).unwrap();
    let io = vec![params.g_x, params.g_y, Scalar::ZERO, hex_to_ff(pk_x), hex_to_ff(pk_y), Scalar::ZERO];

    type G = spartan2::provider::secp_secq::secq256k1::Point;
    type EE = spartan2::provider::hyrax_pc::HyraxEvaluationEngine<G>;
    type S = spartan2::spartan::snark::RelaxedR1CSSNARK<G, EE>;

    // produce keys
    let timer_setup = start_timer!(|| "SNARK::setup");
    let (pk, vk) = SNARK::<G, S, _>::setup(circuit_verifier.clone()).unwrap();
    end_timer!(timer_setup);

    let ser = bincode::serialize(&pk).unwrap();
    println!("Prover key is {} bytes (uncompressed)", ser.len().to_formatted_string(&Locale::en));    
    let ser = bincode::serialize(&pk).unwrap();
    println!("Verifier key is {} bytes (uncompressed)", ser.len().to_formatted_string(&Locale::en));    

    // produce a SNARK
    let prover_inputs = ECDSACircuitProverInputs::new(digest, r, s, pk_x, pk_y).unwrap();   
    let circuit_prover = ECDSAProofCircuit::new(&params, Some(prover_inputs), None).unwrap();     
    let timer_prove = start_timer!(|| "SNARK::witness-gen+prove");
    let res = SNARK::prove(&pk, circuit_prover);
    assert!(res.is_ok());
    let snark = res.unwrap();
    end_timer!(timer_prove);

    let ser = bincode::serialize(&snark).unwrap();
    println!("Proof is {} bytes (uncompressed)", ser.len().to_formatted_string(&Locale::en));

    // verify the SNARK
    let timer_verify = start_timer!(|| "SNARK::verify");
    let res = snark.verify(&vk, &io);
    assert!(res.is_ok());
    end_timer!(timer_verify);    
  }

  #[test]
  fn test_ecdsa_cs() {
    
    let digest = "3F891FDA3704F0368DAB65FA81EBE616F4AA2A0854995DA4DC0B59D2CADBD64F";
    let pk_x = "3AF1E1EFA4D1E1AD5CB9E3967E98E901DAFCD37C44CF0BFB6C216997F5EE51DF";
    let pk_y = "E4ACAC3E6F139E0C7DB2BD736824F51392BDA176965A1C59EB9C3C5FF9E85D7A";
    let r = "A5C7B7756D34D8AAF6AA68F0B71644F0BEF90D8BFD126CE951B6060498345089";
    //let s_inv = "D6E6D8E2B519D1955CF6452E05CB89143EA752A222D38F3492B7B51B83625700";
    let s = "BC9644F1625AF13841E589FD00653AE8C763309184EA0DE481E8F06709E5D1CB";

    let inputs = ECDSACircuitProverInputs::new(digest, r, s, pk_x, pk_y).unwrap();
    let params = ECDSAParams::new(NamedCurve::Secp256k1, NamedCurve::Bn254);
    let circuit = ECDSAProofCircuit::new(&params, Some(inputs), None).unwrap();

    // test constraint system
    let mut cs = TestConstraintSystem::<Scalar>::new();
    circuit
      .synthesize(&mut cs.namespace(|| "build_test_vec"))
      .unwrap();

    println!(
      "test_ecdsa_cs: ECDSA circuit has {} constraints and {} aux values",
      cs.num_constraints().to_formatted_string(&Locale::en),
      cs.aux().len().to_formatted_string(&Locale::en)
    );

    assert!(cs.is_satisfied());
    assert_eq!(cs.num_constraints(), 8033);
  }

  pub fn serialize_into_file<T: serde::Serialize>(path: &Path, obj: T) {
    let timer = start_timer!(|| "Bincode serializing");
    let ser = bincode::serialize(&obj).unwrap();
    end_timer!(timer);
    let timer = start_timer!(|| "Writing file");
    fs::write(path, ser).expect("Failed to write file");
    end_timer!(timer);
  }

  pub fn deserialize_from_file<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let timer = start_timer!(|| "Reading file");
    let de = fs::read(path).expect("Could not read file");
    end_timer!(timer);
    let timer = start_timer!(|| "Bincode deserializing");
    let ret = bincode::deserialize(de.as_slice()).expect("Could not deserialize the object");
    end_timer!(timer);
    ret
  }

  #[test]
  fn test_serialization() {

    type G = spartan2::provider::secp_secq::secq256k1::Point;
    type EE = spartan2::provider::hyrax_pc::HyraxEvaluationEngine<G>;
    type S = spartan2::spartan::snark::RelaxedR1CSSNARK<G, EE>;    

    let digest = "AE1AB30CE075F12CADB7F66ED3C8FC0B0B203AC206F381C6E2BDC1498402BCEA";
    let pk_x = "BB8552F9F4B5EA4159EBFE9A42F8CC5B209E8CEDD3A2D0E36F1B7DB39FB45693";
    let pk_y = "B4169332E1F00C8A10AA18806235295D2596F00D13EA2921B5A20C89ACEBC822";
    let r = "C6FBBDB372303F3B65CBFCF16FF7FC4DBF6ACD921E40C93DB8207A860DB41850";
    let s = "C61995E52329CBC955A8B7891F461D8C5D1DD965E353BDF5214A1BAC9284AB2";

    //let public_inputs = ECDSACircuitPublicInputs::new(pk_x, pk_y).unwrap();
    let params = ECDSAParams::new(NamedCurve::Secp256k1, NamedCurve::Bn254);
    let circuit = ECDSAProofCircuit::new(&params, None, None).unwrap();
    let io = vec![params.g_x, params.g_y, Scalar::ZERO, hex_to_ff(pk_x), hex_to_ff(pk_y), Scalar::ZERO];
    
    // produce keys
    let timer_setup = start_timer!(|| "SNARK::setup");
    let (pk, vk) = SNARK::<G, S, _>::setup(circuit.clone()).unwrap();
    end_timer!(timer_setup);
    println!();

    // Serialize
    let timer = start_timer!(|| "Serializing prover key into a file");
    serialize_into_file(Path::new("pk.bin"), &pk);
    end_timer!(timer);
    println!();
    let timer = start_timer!(|| "Serializing verifier key into a file");
    serialize_into_file(Path::new("vk.bin"), &vk);
    end_timer!(timer);
    println!();

    // Deserialize prover key
    let timer = start_timer!(|| "Deserializing prover key from a file");
    let _ = deserialize_from_file::<ProverKey<G, S>>(Path::new("pk.bin"));
    end_timer!(timer);
    println!();

    // produce a SNARK
    let prover_inputs = ECDSACircuitProverInputs::new(digest, r, s, pk_x, pk_y).unwrap();    
    let prover_circuit = ECDSAProofCircuit::new(&params, Some(prover_inputs), None).unwrap();
    let timer_prove = start_timer!(|| "SNARK::witness-gen+prove");
    let res = SNARK::prove(&pk, prover_circuit);
    assert!(res.is_ok());
    let snark = res.unwrap();
    end_timer!(timer_prove);
    println!();

    // deserialize verifier key
    let timer = start_timer!(|| "Deserializing verifier key from a file");
    let _ = deserialize_from_file::<VerifierKey<G, S>>(Path::new("vk.bin"));
    end_timer!(timer);
    println!();

    // verify the SNARK
    let timer_verify = start_timer!(|| "SNARK::verify");
    let res = snark.verify(&vk, &io);
    assert!(res.is_ok());
    end_timer!(timer_verify);
  }

  #[test]
  fn test_ecdsa_committed_digest_proof() {
    
    let pk_x = "3AF1E1EFA4D1E1AD5CB9E3967E98E901DAFCD37C44CF0BFB6C216997F5EE51DF";
    let pk_y = "E4ACAC3E6F139E0C7DB2BD736824F51392BDA176965A1C59EB9C3C5FF9E85D7A";
    
    // The prover starts with all these values:
    let digest = "3F891FDA3704F0368DAB65FA81EBE616F4AA2A0854995DA4DC0B59D2CADBD64F";
    let r = "A5C7B7756D34D8AAF6AA68F0B71644F0BEF90D8BFD126CE951B6060498345089";
    let s = "BC9644F1625AF13841E589FD00653AE8C763309184EA0DE481E8F06709E5D1CB";

    // First they create a commitment to the digest
    let mut rng = rand::thread_rng();
    let constants = Commitment::create_constants();
    let params = ECDSAParams::new(NamedCurve::Secp256k1, NamedCurve::Bn254);    
    let h = BigUint::from_str_radix(digest, 16).unwrap();
    let timer_commit = start_timer!(||"Commit to digest");
    let opening = Commitment::commit_digest_part1(&constants, &h, &params.commit_prime);
    let challenge = rng.gen_biguint(Commitment::<Scalar>::CHALLENGE_BITLEN as u64); // The challenge would be input to the prover as part of the first proof    
    let opening = Commitment::<Scalar>::commit_digest_part2(&opening, &challenge, &params.commit_prime);
    end_timer!(timer_commit);

    // Then we set-up the proof as in the non-committed case, but include the commitment public inputs
    let commitment_public_inputs = CommitmentInputs{ constants: constants.clone(), opening: None, r: None, p: params.commit_prime.clone()};
    let circuit = ECDSAProofCircuit::new(&params, None, Some(commitment_public_inputs)).unwrap();

    type G = spartan2::provider::secp_secq::secq256k1::Point;
    type EE = spartan2::provider::hyrax_pc::HyraxEvaluationEngine<G>;
    type S = spartan2::spartan::snark::RelaxedR1CSSNARK<G, EE>;

    // produce keys
    let timer_setup = start_timer!(|| "SNARK::setup");
    let (pk, vk) = SNARK::<G, S, _>::setup(circuit.clone()).unwrap();
    end_timer!(timer_setup);

    let ser = bincode::serialize(&pk).unwrap();
    println!("Prover key is {} bytes (uncompressed)", ser.len().to_formatted_string(&Locale::en));    
    let ser = bincode::serialize(&pk).unwrap();
    println!("Verifier key is {} bytes (uncompressed)", ser.len().to_formatted_string(&Locale::en));    

    // produce a SNARK
    let prover_inputs = ECDSACircuitProverInputs::new(digest, r, s, pk_x, pk_y).unwrap();
    let commitment_prover_inputs = CommitmentInputs{ constants, opening: Some(opening.clone()), r: Some(challenge.clone()), p: params.commit_prime.clone()};
    let prover_circuit = ECDSAProofCircuit::new(&params, Some(prover_inputs), Some(commitment_prover_inputs)).unwrap();    
    let timer_prove = start_timer!(|| "SNARK::witness-gen+prove");
    let res = SNARK::prove(&pk, prover_circuit);
    assert!(res.is_ok());
    let snark = res.unwrap();
    end_timer!(timer_prove);

    let ser = bincode::serialize(&snark).unwrap();
    println!("Proof is {} bytes (uncompressed)", ser.len().to_formatted_string(&Locale::en));

    // verify the SNARK
    let io = vec![biguint_to_scalar(&opening.c.as_ref().unwrap()), biguint_to_scalar(&challenge) , params.g_x, params.g_y, Scalar::ZERO, hex_to_ff(pk_x), hex_to_ff(pk_y), Scalar::ZERO];    
    let timer_verify = start_timer!(|| "SNARK::verify");
    let res = snark.verify(&vk, &io);
    assert_eq!(res, Ok(()));
    end_timer!(timer_verify); 

  }

  #[test]
  fn test_ecdsa_committed_digest_cs() {
    
    // The prover starts with all these values:
    let digest = "3F891FDA3704F0368DAB65FA81EBE616F4AA2A0854995DA4DC0B59D2CADBD64F";
    let pk_x = "3AF1E1EFA4D1E1AD5CB9E3967E98E901DAFCD37C44CF0BFB6C216997F5EE51DF";
    let pk_y = "E4ACAC3E6F139E0C7DB2BD736824F51392BDA176965A1C59EB9C3C5FF9E85D7A";
    let r = "A5C7B7756D34D8AAF6AA68F0B71644F0BEF90D8BFD126CE951B6060498345089";
    let s = "BC9644F1625AF13841E589FD00653AE8C763309184EA0DE481E8F06709E5D1CB";
    
    // First they create a commitment to the digest
    let mut rng = rand::thread_rng();
    let constants = Commitment::create_constants();
    let params = ECDSAParams::new(NamedCurve::Secp256k1, NamedCurve::Bn254);    
    let timer_commit = start_timer!(||"Commit to digest");
    let h = BigUint::from_str_radix(digest, 16).unwrap();
    let opening = Commitment::commit_digest_part1(&constants, &h, &params.commit_prime);
    let challenge = rng.gen_biguint(Commitment::<Scalar>::CHALLENGE_BITLEN as u64); // The challenge would be input to the prover as part of the first proof    
    let opening = Commitment::<Scalar>::commit_digest_part2(&opening, &challenge, &params.commit_prime);
    end_timer!(timer_commit);

    // Then set-up the proof as in the non-committed case, but includes the commitment inputs
    let prover_inputs = ECDSACircuitProverInputs::new(digest, r, s, pk_x, pk_y).unwrap();
    let commitment_inputs = CommitmentInputs{ constants, opening: Some(opening), r: Some(challenge), p: params.commit_prime.clone()};
    let circuit = ECDSAProofCircuit::new(&params, Some(prover_inputs), Some(commitment_inputs)).unwrap();

    // test constraint system
    let mut cs = TestConstraintSystem::<Scalar>::new();
    circuit
      .synthesize(&mut cs.namespace(|| "build_test_vec"))
      .unwrap();

    println!(
      "test_ecdsa_committed_digest_cs: ECDSA circuit has {} constraints and {} aux values",
      cs.num_constraints().to_formatted_string(&Locale::en),
      cs.aux().len().to_formatted_string(&Locale::en)
    );

    assert!(cs.is_satisfied());
    assert_eq!(cs.num_constraints(), 10042);
    //println!("{}", cs.pretty_print());
  }  

  #[test]
  fn test_ecdsa_nocommit_public_api() {
    let pk_x = "3AF1E1EFA4D1E1AD5CB9E3967E98E901DAFCD37C44CF0BFB6C216997F5EE51DF";
    let pk_y = "E4ACAC3E6F139E0C7DB2BD736824F51392BDA176965A1C59EB9C3C5FF9E85D7A";
    let digest = "3F891FDA3704F0368DAB65FA81EBE616F4AA2A0854995DA4DC0B59D2CADBD64F";    
    let r = "A5C7B7756D34D8AAF6AA68F0B71644F0BEF90D8BFD126CE951B6060498345089";
    let s = "BC9644F1625AF13841E589FD00653AE8C763309184EA0DE481E8F06709E5D1CB";    
    
    let params = ECDSAParams::new(NamedCurve::Secp256k1, NamedCurve::Bn254);    // The 2nd curve is used for the commitment only, it's unused in this case
    let (pk, vk) = ECDSAProof::setup_nocommit(&params);
    let proof = ECDSAProof::prove_nocommit(&params, &pk, digest, pk_x, pk_y, r, s);
    assert!(ECDSAProof::verify_nocommit(&params, &vk, pk_x, pk_y, &proof));
  }

  #[test]
  fn test_ecdsa_public_api() {
    let pk_x = "3AF1E1EFA4D1E1AD5CB9E3967E98E901DAFCD37C44CF0BFB6C216997F5EE51DF";
    let pk_y = "E4ACAC3E6F139E0C7DB2BD736824F51392BDA176965A1C59EB9C3C5FF9E85D7A";
    
    // The prover starts with all these values:
    let digest = "3F891FDA3704F0368DAB65FA81EBE616F4AA2A0854995DA4DC0B59D2CADBD64F";
    let r = "A5C7B7756D34D8AAF6AA68F0B71644F0BEF90D8BFD126CE951B6060498345089";
    let s = "BC9644F1625AF13841E589FD00653AE8C763309184EA0DE481E8F06709E5D1CB";

    // First they create a commitment to the digest
    let params = ECDSAParams::new(NamedCurve::Secp256k1, NamedCurve::Bn254);
    let commitment_opening = ECDSAProof::commit_digest_part1(&params, &digest);
    let challenge = "00AAAA1FDA3704F0368DAB65FA81EBE616F4AA2A0854995DA4DC0B59D2CABBBB"; // The challenge would be input to the prover as part of the first proof
    let (commitment, commitment_opening) = ECDSAProof::commit_digest_part2(&params, commitment_opening, &challenge);
    let (pk, vk) = ECDSAProof::setup(&params);
    let proof = ECDSAProof::prove(&params, &pk, digest, pk_x, pk_y, r, s, &challenge, &commitment_opening);
    assert!(ECDSAProof::verify(&params, &vk, pk_x, pk_y, &proof, &challenge, &commitment));
  }    

}
