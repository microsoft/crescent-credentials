//! This library implements bellpepper circuits proving knowledge of ECDSA signatures and uses Spartan to prove them
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
mod utils;
mod poseidon;
mod emulated;

use std::io::Write;
use bellpepper_core::{num::AllocatedNum, test_cs::TestConstraintSystem, Circuit, ConstraintSystem, SynthesisError, Comparable};
use ff::Field;
use flate2::{write::ZlibDecoder, write::ZlibEncoder, Compression};
use halo2curves::{CurveAffine, group::Curve, secp256r1::Fp as P256Fp};
use merlin::Transcript;
use num_bigint::{BigInt, BigUint};
use num_format::{Locale, ToFormattedString};
use poseidon::{Poseidon, PoseidonConstantsCircuit};
use spartan_t256::{bellpepper::shape_cs::ShapeCS, bellpepper::solver::SatisfyingAssignment, Assignment, Instance, NIZK, NIZKGens};
use utils::enforce_equal;
use ark_std::{end_timer, start_timer};
use crate::emulated::util::allocated_num_to_emulated_fe;
use crate::poseidon::PoseidonCircuit;
use crate::utils::{hex_to_ff, hex_to_big, big_to_ff, ff_to_big};
use crate::ecc::AllocatedPoint;
use crate::emulated::field_element::{EmulatedFieldElement, EmulatedFieldParams, PseudoMersennePrime};

type Scalar = P256Fp;

// ECDSA proof when only the verification key must be secret
// Notation
//    Q: verification key
//    r, R: signature value, r = f(R) = R.x
//    s: other signature value
//    h: digest of message to be signed
// Define:
//    T = (1/r) * R
//    U = (-h/r) * G
// Verification equation:
//    T^s * U  = Q
// Circuit IO:
//   public inputs: T, U, hQ, m, (e1, e2) // (public inputs are computed by both prover and verifier from R, h, G)    
//   private inputs: q0, q1, z
// Circuit:
//   1. Check hQ = Poseidon(q0, q1, z)
//   2. Check m = q0 + q1*e1 + z*e2 (mod q)
//   3. Compute public key Q.x = q0 + 2^128 * q1
//
// This modified signing equation was also used here: https://github.com/personaelabs/spartan-ecdsa

// We must use halo2curves's implementation of P256 because the one produced by ff_derive
// in circ_fields has five 64-bit limbs to represent P256, and Poseidon only works with
// 32-byte fields
// This is a known issue in ff_derive https://github.com/zkcrypto/ff/issues/71


///////////////////////////////////////////////

/// An enum to select the elliptic curve used with ECDSA
#[derive(Clone, PartialEq, Debug)]
pub enum NamedCurve {
  /// NIST-P256
  Secp256r1,
  /// The BN254 curve used by Ethereum and others https://neuromancer.sk/std/bn/bn254
  Bn254,
}

/// Holds public parameters for the circuit
#[derive(Clone)]
pub struct ECDSAParams {
  /// Enum that indicates which curve the signature is on
  pub curve: NamedCurve,
  /// x-coord of group generator point
  pub g_x: Scalar,
  /// y-coord of group generator point
  pub g_y: Scalar,
  /// Poseidon constants
  pub constants: PoseidonConstantsCircuit<P256Fp>,
}

impl ECDSAParams {
  /// constructs public parameters 
  /// `ecdsa_curve`: curve where the ECDSA signature was created
  /// `commitment_curve`: curve used by the proof system that created the commitment to the digest
  /// Only secp256r1 and bn254 are currently supported
  pub fn new(ecdsa_curve: NamedCurve, commitment_curve: NamedCurve) -> Self {
    
    match commitment_curve {
        NamedCurve::Bn254 => {}
        _ => {
          panic!("Unsupported commitment curve");
        }
    }

    match ecdsa_curve {
      NamedCurve::Secp256r1 => {
        let g_x = hex_to_ff("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
        let g_y = hex_to_ff("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
        let constants = PoseidonConstantsCircuit::<P256Fp>::default();
        Self { curve:ecdsa_curve, g_x, g_y, constants}
      }
      _ => {
            panic!("Unsupported ECDSA curve");
      }
    }
  }
}

struct Bn254FrEmulatedParams; // TODO: Would be nice to move this into the ECDSAParams
impl EmulatedFieldParams for Bn254FrEmulatedParams {
    fn num_limbs() -> usize {
        16
    }

    fn bits_per_limb() -> usize {
        16
    }

    fn modulus() -> BigInt {
        BigInt::parse_bytes(
            b"30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001",
            //b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
            16,
        )
        .unwrap()
    }

    fn is_modulus_pseudo_mersenne() -> bool {
        false
    }

    fn pseudo_mersenne_params() -> Option<PseudoMersennePrime> {
            None
    }
}

// An internal type to represent an affine point
#[derive(Clone)]
struct Point<T> {
  x: T, 
  y: T
}

/// Holds the public inputs to the ECDSA proof circuit
#[derive(Clone)]
struct ECDSACircuitPublicInputs {
  T: Point<Scalar>,
  U: Point<Scalar>,
  hQ:  Scalar,
  m :  BigUint,
  e1:  BigUint,
  e2:  BigUint,
}

/// Holds the prover's inputs to the ECDSA proof circuit
#[derive(Clone)]
struct ECDSACircuitProverInputs {
  s: Scalar,
  q0: Scalar,
  q1: Scalar,
  z: Scalar,
}

impl ECDSACircuitProverInputs {
  pub fn new(s: &BigUint, q0: &BigUint, q1: &BigUint, z: &BigUint) -> Self {
    Self { s: big_to_ff(s), q0: big_to_ff(q0), q1: big_to_ff(q1), z: big_to_ff(z) }
  }
}

impl ECDSACircuitPublicInputs {

  fn compute_RTU(q: &Point<BigUint>, r: &BigUint, s: &BigUint, digest : &str, curve: &NamedCurve) -> (Point<BigUint>, Point<BigUint>, Point<BigUint>) {
    assert_eq!(*curve, NamedCurve::Secp256r1);

    type Fq = halo2curves::secp256r1::Fq;
    type Fp = halo2curves::secp256r1::Fp;
    let r = big_to_ff::<Fq>(r);
    let s = big_to_ff::<Fq>(s);
    let d = hex_to_ff::<Fq>(digest);
    let G = halo2curves::secp256r1::Secp256r1Affine::generator();
    let x = big_to_ff::<Fp>(&q.x); 
    let y = big_to_ff::<Fp>(&q.y);
    let Q = halo2curves::secp256r1::Secp256r1Affine::from_xy(x, y).unwrap();

    assert!(s!= Fq::ZERO);
    let s_inv = s.invert().unwrap();

    // Recover R as a point
    let u = d * s_inv;
    let v = r * s_inv;
    let R = G * u + Q * v;
    let R = R.to_affine();
    assert!(ff_to_big::<Fq>(&r) == ff_to_big::<Fp>(&R.x));  // Signature verifies

    // Compute T and U for the modified verification equation
    assert!(s!= Fq::ZERO);
    let r_inv = r.invert().unwrap();
    let u = -d * r_inv;
    let T = (R * r_inv).to_affine();
    let U = (G * u).to_affine();

    let pR = Point{x: ff_to_big(&R.x), y: ff_to_big(&R.y)};
    let pT = Point{x: ff_to_big(&T.x), y: ff_to_big(&T.y)};
    let pU = Point{x: ff_to_big(&U.x), y: ff_to_big(&U.y)};

    (pR, pT, pU)
  }

  fn compute_TU(R: &Point<BigUint>, digest : &str, curve: &NamedCurve) -> (Point<BigUint>, Point<BigUint>) {
    assert_eq!(*curve, NamedCurve::Secp256r1);
    
    type Fq = halo2curves::secp256r1::Fq;
    type Fp = halo2curves::secp256r1::Fp;
    let r = big_to_ff::<Fq>(&R.x);  // in Fq
    let Rx = big_to_ff::<Fp>(&R.x); // in Fp
    let Ry = big_to_ff::<Fp>(&R.y);
    let R = halo2curves::secp256r1::Secp256r1Affine::from_xy(Rx, Ry).unwrap();
    let d = hex_to_ff::<Fq>(digest);
    let G = halo2curves::secp256r1::Secp256r1Affine::generator();

    // Compute T and U for the modified verification equation
    assert!(r!= Fq::ZERO);
    let r_inv = r.invert().unwrap();
    let u = -d * r_inv;
    let T = (R * r_inv).to_affine();
    let U = (G * u).to_affine();

    let pT = Point{x: ff_to_big(&T.x), y: ff_to_big(&T.y)};
    let pU = Point{x: ff_to_big(&U.x), y: ff_to_big(&U.y)};

    (pT, pU)
  }  
  
  pub fn new(T: &Point<BigUint>, U: &Point<BigUint>, hQ: &[u8], m :BigUint, e1: BigUint, e2: BigUint) -> Self {
    Self{
      T: Point{x: big_to_ff(&T.x), y: big_to_ff(&T.y)},
      U: Point{x: big_to_ff(&U.x), y: big_to_ff(&U.y)},
      hQ: hex_to_ff(&hex::encode(hQ)),
      m, e1, e2
    }
  }

  fn _default() -> Self {
      Self{
      T: Point{ x: hex_to_ff("00"), y: hex_to_ff("00")},
      U: Point{ x: hex_to_ff("00"), y: hex_to_ff("00")},
      hQ: hex_to_ff("00"), m: hex_to_big("00"),
      e1: hex_to_big("00"), e2: hex_to_big("00"),
      }
}  
}


/// Holds the ECDSA proof circuit
#[derive(Clone)]
pub struct ECDSAProofCircuit {
  params: ECDSAParams,
  prover_inputs: Option<ECDSACircuitProverInputs>,
  public_inputs: ECDSACircuitPublicInputs,
}

impl ECDSAProofCircuit {
 
  /// constructs the selective disclosure circuit
  fn new(params: &ECDSAParams, prover_inputs: Option<ECDSACircuitProverInputs>, public_inputs: &ECDSACircuitPublicInputs) -> Self {

    Self { params: params.clone(),  prover_inputs : prover_inputs.clone(), public_inputs: public_inputs.clone() }
  }

  fn build_qx<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    q0:  &AllocatedNum<Scalar>,
    q1:  &AllocatedNum<Scalar>
    ) -> Result<AllocatedNum<Scalar>, SynthesisError>
  {
    let shift_to_alloc = hex_to_ff("0100000000000000000000000000000000");
    let shift = AllocatedNum::alloc(&mut cs.namespace(||"alloc 2^128"), ||Ok(shift_to_alloc))?;

    // Compute Qx
    let qx = AllocatedNum::<Scalar>::alloc(&mut cs.namespace(||"alloc Qx"), || {
      if q0.get_value().is_some() && q1.get_value().is_some() {
          let qx = q1.get_value().unwrap() * shift_to_alloc + q0.get_value().unwrap();
          Ok(qx)
      } else {
          Err(SynthesisError::AssignmentMissing)
      }
    })?;

      cs.enforce(
        || "Enforce qx = q1*shift + q0",
        |lc| lc + q1.get_variable(),
        |lc| lc + shift.get_variable(),
        |lc| lc + qx.get_variable() - q0.get_variable()
    );

    Ok(qx)
  }

  /// Compute the hash commitment H_Q = Poseidon(q0, q1, z)
  pub fn compute_hQ(params: &ECDSAParams, q0: &BigUint, q1: &BigUint, z: &BigUint) -> Vec<u8> {
    let NUM_ABSORBS = 3;
    let mut poseidon: Poseidon<P256Fp> = Poseidon::new(params.constants.clone(), NUM_ABSORBS);
    poseidon.absorb(big_to_ff(q0));
    poseidon.absorb(big_to_ff(q1));
    poseidon.absorb(big_to_ff(z));

    let hQ = poseidon.squeeze_field_element();    // H(q0, q1, z)

    let mut hQ = hQ.to_bytes();
    hQ.reverse();
    hQ.to_vec()
  }

  #[allow(dead_code)]
  fn print_efe(label: &str, e: &EmulatedFieldElement<Scalar, Bn254FrEmulatedParams>) {
     let mm = BigInt::try_from(e).unwrap();
     println!("{} = {}", label, mm.to_str_radix(16));
  }

  pub(crate) fn enforce_m_valid<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    q0:  &AllocatedNum<Scalar>,
    q1:  &AllocatedNum<Scalar>,
    e1:  &EmulatedFieldElement<Scalar, Bn254FrEmulatedParams>,
    e2:  &EmulatedFieldElement<Scalar, Bn254FrEmulatedParams>,
    z:   &AllocatedNum<Scalar>,
    m:   &EmulatedFieldElement<Scalar, Bn254FrEmulatedParams>,
    ) -> Result<(), SynthesisError>
  {
    // Check that m = q0 + q1*e1 + z*e2 (mod q)
    // using emulated arithmetic
    let q0 : EmulatedFieldElement<Scalar, Bn254FrEmulatedParams> = allocated_num_to_emulated_fe(&mut cs.namespace(||"convert q0"), q0)?;
    let q1 : EmulatedFieldElement<Scalar, Bn254FrEmulatedParams> = allocated_num_to_emulated_fe(&mut cs.namespace(||"convert q1"), q1)?;
    let z : EmulatedFieldElement<Scalar, Bn254FrEmulatedParams> = allocated_num_to_emulated_fe(&mut cs.namespace(||"convert z"), z)?;

    let tmp = e1.mul(&mut cs.namespace(||"e1*q1"), &q1)?;
    let tmp2 = e2.mul(&mut cs.namespace(||"e2*z"), &z)?;
    let tmp3 = tmp.add(&mut cs.namespace(||"tmp + tmp2"), &tmp2)?;
    let m_calc = q0.add(&mut cs.namespace(||"q0 + tmp3"), &tmp3)?;
  
    EmulatedFieldElement::<Scalar, Bn254FrEmulatedParams>::assert_is_equal(
        &mut cs.namespace(|| "check equality"),
        &m_calc,
        m,
    )?;
    
    Ok(())
  }

}

impl Circuit<Scalar> for ECDSAProofCircuit {

  fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {

    // allocate public IOs T, U, hQ, m, e1, e2, q
    let T = AllocatedPoint::alloc(
      cs.namespace(|| "T"),
      Some((self.public_inputs.T.x, self.public_inputs.T.y, false)),
    )?;
    let U = AllocatedPoint::alloc(
      cs.namespace(|| "U"),
      Some((self.public_inputs.U.x, self.public_inputs.U.y, false)),
    )?;
    let hQ = AllocatedNum::alloc(cs.namespace(||"hQ"), || Ok(self.public_inputs.hQ))?;
    T.inputize(cs.namespace(|| "T input"))?;
    U.inputize(cs.namespace(|| "U input"))?;
    hQ.inputize(cs.namespace(||"hQ input"))?;

    let m = EmulatedFieldElement::<Scalar, Bn254FrEmulatedParams>::from(&self.public_inputs.m.into())
    .allocate_field_element_unchecked(&mut cs.namespace(|| "m"))?;
    let e1 = EmulatedFieldElement::<Scalar, Bn254FrEmulatedParams>::from(&self.public_inputs.e1.into())
    .allocate_field_element_unchecked(&mut cs.namespace(|| "e1"))?;
    let e2 = EmulatedFieldElement::<Scalar, Bn254FrEmulatedParams>::from(&self.public_inputs.e2.into())
    .allocate_field_element_unchecked(&mut cs.namespace(|| "e2"))?;    

    // Allocate prover inputs (s, q0, q1, z)
    let to_alloc = if self.prover_inputs.is_some() {
      let pi = self.prover_inputs.clone().unwrap();
      (Ok(pi.s), Ok(pi.q0), Ok(pi.q1), Ok(pi.z))
    } else {
      (Err(SynthesisError::AssignmentMissing), Err(SynthesisError::AssignmentMissing), Err(SynthesisError::AssignmentMissing), Err(SynthesisError::AssignmentMissing))
    };
    let s  = AllocatedNum::alloc(cs.namespace(|| "s"), || to_alloc.0)?;
    let q0 = AllocatedNum::<P256Fp>::alloc(cs.namespace(|| "q0"), || to_alloc.1)?;
    let q1 = AllocatedNum::<P256Fp>::alloc(cs.namespace(|| "q1"), || to_alloc.2)?;
    let z  = AllocatedNum::<P256Fp>::alloc(cs.namespace(|| "z"), || to_alloc.3)?;

    // Check that hQ = Poseidon(q0, q1, z)
    let num_absorbs = 3;
    let mut poseidon: PoseidonCircuit<P256Fp> = PoseidonCircuit::new(self.params.constants.clone(), num_absorbs);
    poseidon.absorb(&q0);
    poseidon.absorb(&q1);
    poseidon.absorb(&z);
    let hQ_prime = poseidon.squeeze_field_element(&mut cs.namespace(||"squeeze"))?;

    enforce_equal(cs.namespace(||"ensure hQ == hQ_prime "), &hQ, &hQ_prime);

    // Check that m = q0 + q1*e1 + z*e2 (mod q)
    Self::enforce_m_valid(cs.namespace(||"check m"), &q0, &q1, &e1, &e2, &z, &m)?;

    // Create Qx = q0 + 2^128 * q1
    let Qx = Self::build_qx(cs.namespace(||"build Qx"), &q0, &q1)?;

    // Check ( T^s * U ).x  = Qx
    let sT = T.scalar_mul(cs.namespace(|| "s*T"), &s)?;
    let lhs = sT.add(cs.namespace(||"sT + U"), &U)?;
    enforce_equal(cs.namespace(||"lhs.x == Q.x"), &lhs.x, &Qx);

    Ok(())
  }
}

mod private_macros {
  /// Print an error message and return the boolean false
  #[macro_export]
  macro_rules! return_false {
    ($msg:expr) => {
      {
        println!("{}", $msg);
        return false;
      }
    };
  }
}

/// Top-level API for creating ECDSA proofs. The inputs and outputs are all standard types: BigUint and Vec<u8>.
pub struct ECDSAProof;

impl ECDSAProof {

  /// Split an ECDSA public key's x-coord into two parts. Restricted to keys 32-byte fields.
  pub fn split_public_key_x(qx: &BigUint) -> (BigUint, BigUint) {
    let mut Qx_bytes = qx.to_bytes_le();
    assert!(Qx_bytes.len() <=32 );
    while Qx_bytes.len() < 32 {
      Qx_bytes.push(0);
    }
    let (Qx_low_bytes, Qx_high_bytes) = Qx_bytes.split_at(16);
    let q0 = BigUint::from_bytes_le(Qx_low_bytes);
    let q1 = BigUint::from_bytes_le(Qx_high_bytes);

    (q0, q1)
  }

  // Run setup, return the prover key and verifier key (public parameters for the system).
  // For now prover and verifier always re-generate the public parameters themselves
  fn _setup(params : &ECDSAParams) -> NIZKGens {

    assert!(params.curve == NamedCurve::Secp256r1); // We only support one curve right now
    let public_inputs = ECDSACircuitPublicInputs::_default();
    let circuit_verifier = ECDSAProofCircuit::new(params,  None, &public_inputs);
    let t = start_timer!(|| "Getting R1CS Shape");
    let mut cs = ShapeCS::<Scalar>::new();
    let _ = circuit_verifier.synthesize(&mut cs.namespace(||"synthesize verifier"));
    let shape = cs.r1cs_shape();
    end_timer!(t);

    let t = start_timer!(|| "Producing NIZK public generators");
    let gens = NIZKGens::new(shape.num_cons, shape.num_vars, shape.num_io);
    end_timer!(t);

    gens
  }

  /// Create a proof of an ECDSA signature
  #[allow(clippy::too_many_arguments)]
  pub fn prove(params : &ECDSAParams, 
    qx: &BigUint, qy: &BigUint,                   // Signer's public key
    r: &BigUint, s: &BigUint, digest: &[u8],      // ECDSA signature on digest
    hQ: &[u8], m: &BigUint, e1: &[u8], e2: &[u8], // Adapter public values
    z: &BigUint,                                  // Adapter private values
    debug_checks: bool
  ) -> (BigUint, BigUint, Vec<u8>) {

    let q = Point{x: qx.clone(), y: qy.clone()};
    let digest_hex = hex::encode(digest);
    let (R, T, U) = ECDSACircuitPublicInputs::compute_RTU(&q, r, s, &digest_hex, &params.curve);

    let (q0, q1) = ECDSAProof::split_public_key_x(qx);

    let e1 = BigUint::from_bytes_le(e1);
    let e2 = BigUint::from_bytes_le(e2);
    let public_inputs = ECDSACircuitPublicInputs::new(&T, &U, hQ, m.clone(), e1, e2);
    let prover_inputs = ECDSACircuitProverInputs::new(s, &q0, &q1, z);
    
    let circuit_verifier = ECDSAProofCircuit::new(params,  None, &public_inputs);
    let t = start_timer!(|| "Getting R1CS Shape");
    let mut cs = ShapeCS::<Scalar>::new();
    let _ = circuit_verifier.synthesize(&mut cs.namespace(||"synthesize verifier"));
    let shape = cs.r1cs_shape();
    end_timer!(t);

    let t = start_timer!(|| "Calculate witness");
    let circuit_prover = ECDSAProofCircuit::new(params,  Some(prover_inputs), &public_inputs);
    let mut cs: SatisfyingAssignment<Scalar> = SatisfyingAssignment::new();
    let _ = circuit_prover.clone().synthesize(&mut cs.namespace(||"calculate witness"));
    let (inst, witness, inputs) = cs.r1cs_instance_and_witness(&shape);
    end_timer!(t);

    if debug_checks {
      // For debugging, we'll use the test constraint system. If there is a failure it'll tell us where
      let mut cs = TestConstraintSystem::<Scalar>::new();
      circuit_prover
        .synthesize(&mut cs.namespace(|| "build_test_vec"))
        .unwrap();

      println!(
        "prove: ECDSA circuit has {} constraints and {} aux values",
        cs.num_constraints().to_formatted_string(&Locale::en),
        cs.aux().len().to_formatted_string(&Locale::en)
      );

      let t = start_timer!(|| "Checking satisfiability (debugging only)");
      let is_sat = inst.is_sat(&witness, &inputs);
      assert!(is_sat.is_ok());
      assert!(is_sat.unwrap());
      end_timer!(t);
    }

    let t = start_timer!(|| "Producing NIZK public generators");
    let gens = NIZKGens::new(shape.num_cons, shape.num_vars, shape.num_io);
    end_timer!(t);

    let t = start_timer!(|| "Generate NIZK proof");
    let mut prover_transcript = Transcript::new(b"NIZK proof of ECDSA signature with committed public key");
    let proof = NIZK::prove(&inst, witness, &inputs, &gens, &mut prover_transcript);
    end_timer!(t);

    let proof_str = bincode::serialize(&proof).unwrap();
    println!("Proof length, serialized by bincode: {} ", proof_str.len());

    let t = start_timer!(|| "Compress proof");
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    bincode::serialize_into(&mut encoder, &proof).unwrap();
    let proof_encoded = encoder.finish().unwrap();
    end_timer!(t);

    let msg_proof_len = format!("NIZK::proof_compressed_len {:?}", proof_encoded.len());
    println!("{msg_proof_len}");

    (R.x, R.y, proof_encoded) // TODO: return errors too
  }

  /// Verify the proof
  #[allow(clippy::too_many_arguments)]
  pub fn verify(params : &ECDSAParams, Rx: &BigUint, Ry: &BigUint, digest : &[u8], hQ: &[u8], m: &BigUint, e1: &[u8], e2: &[u8], proof : &[u8]) -> bool {

    assert!(params.curve == NamedCurve::Secp256r1); // We only support one curve right now

    let R = Point{x: Rx.clone(), y: Ry.clone()};
    let (T, U) = ECDSACircuitPublicInputs::compute_TU(&R, &hex::encode(digest), &params.curve);
    
    let e1 = BigUint::from_bytes_le(e1);
    let e2 = BigUint::from_bytes_le(e2);
    let public_inputs = ECDSACircuitPublicInputs::new(&T, &U, hQ, m.clone(), e1, e2);
    
    let circuit_verifier = ECDSAProofCircuit::new(params,  None, &public_inputs);
    let t = start_timer!(|| "Getting R1CS Shape");
    let mut cs = ShapeCS::<Scalar>::new();
    let _ = circuit_verifier.synthesize(&mut cs.namespace(||"synthesize verifier"));
    let shape = cs.r1cs_shape();
    end_timer!(t);

    let t = start_timer!(||"Converting Shape to Instance");
    let inst = match Instance::new_from_shape(&shape) {
      Ok(i) => i,
      Err(_) => return_false!("Failed to create Instance")
    };
    end_timer!(t);    

    let t = start_timer!(|| "Producing NIZK public generators");
    let gens = NIZKGens::new(shape.num_cons, shape.num_vars, shape.num_io);
    end_timer!(t);    

    let t = start_timer!(|| "Decompress proof");
    let mut decoder = ZlibDecoder::new(Vec::new());
    match decoder.write_all(proof) {
      Ok(_) => {},
      Err(_) => return_false!("failed writing proof to ZlibDecoder")
    };
    let writer = match decoder.finish() {
      Ok(w) => w,
      Err(_) => return_false!("Failed decompressing proof")
    };
    let proof_decoded : NIZK = match bincode::deserialize(&writer) {
      Ok(p) => p,
      Err(_) => return_false!("Failed to deserialize proof")
    };
    end_timer!(t);

    let inputs = vec![public_inputs.T.x.to_bytes(), public_inputs.T.y.to_bytes(), Scalar::ZERO.to_bytes(), 
                      public_inputs.U.x.to_bytes(), public_inputs.U.y.to_bytes(), Scalar::ZERO.to_bytes(), 
                      public_inputs.hQ.to_bytes()];

    let inputs_assign = match Assignment::new(inputs.as_slice()) {
      Ok(i) => i,
      Err(_) => return_false!("Failed to create input Assignment")
    };

    let t = start_timer!(|| "Verify proof");
    let mut verifier_transcript = Transcript::new(b"NIZK proof of ECDSA signature with committed public key");
    let is_valid = proof_decoded.verify(&inst, &inputs_assign, &mut verifier_transcript, &gens).is_ok();
    end_timer!(t);

    is_valid
  }

}



#[cfg(test)]
mod tests {
  use super::*;
  use bellpepper_core::{test_cs::TestConstraintSystem, Comparable};
  use flate2::write::ZlibDecoder;
  use merlin::Transcript;
  use num_format::{Locale, ToFormattedString};
  use sha2::{Digest, Sha256};
  use spartan_t256::bellpepper::solver::SatisfyingAssignment;
  use spartan_t256::{NIZKGens, NIZK, bellpepper::shape_cs::ShapeCS};
  use std::io::Write;
  use ark_secp256r1::{Affine as GGA, Fr as Fr, Fq as Fp};
  use ark_ec::{AffineRepr, CurveGroup};
  use ark_bn254::{Fr as Bn254_Fr, G1Affine};
  use ark_ff::{BigInteger, PrimeField};
  use flate2::{write::ZlibEncoder, Compression};
  use ark_std::{rand::thread_rng, UniformRand, end_timer, start_timer};

  // For unit tests we compute the mock adapter values using arkworks Bn254 implementation so we need
  // some conversion helper functions 
  fn hex_to_ark<FF : ark_ff::PrimeField>(hex_int : &str) -> FF {
    let digits = (0..hex_int.len())
      .step_by(2)
      .map(|i| u8::from_str_radix(&hex_int[i..i + 2], 16).unwrap())
      .collect::<Vec<u8>>();
    let bu = BigUint::from_radix_be(digits.as_slice(), 256).unwrap();
    FF::from(bu)
  }
  fn ark_to_uint<FF: ark_ff::PrimeField>(u : &FF) -> BigUint {
    let u_big = u.into_bigint();
    BigUint::from_bytes_le(&u_big.to_bytes_le())
  }
  fn uint_to_ark<FF: ark_ff::PrimeField>(u : &BigUint) -> FF {
    let u_bytes = u.to_bytes_le();
    FF::from_le_bytes_mod_order(&u_bytes)
  }
  fn hex_to_point(x : &str, y: &str) -> GGA {
    let x = hex_to_ark::<Fp>(x);
    let y = hex_to_ark::<Fp>(y);
    GGA::new(x, y)
  }
  fn uint_to_point(x : &BigUint, y: &BigUint) -> GGA {
    let x = uint_to_ark::<Fp>(x);
    let y = uint_to_ark::<Fp>(y);
    GGA::new(x, y)
  }

  #[allow(non_snake_case)]
  fn check_keypair(Q: &Point<BigUint>, d: &BigUint) -> bool {
    let G = hex_to_point( "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
    let Q = uint_to_point(&Q.x, &Q.y);
    let d = uint_to_ark::<Fr>(d);

    G * d == Q
  }

  fn modified_ECDSA_ver(T: &Point<BigUint>, U: &Point<BigUint>, Q: &Point<BigUint>, s: &BigUint) -> bool {
    // Check that s*T + U = Q
    let T = uint_to_point(&T.x, &T.y);
    let U = uint_to_point(&U.x, &U.y);
    let Q = uint_to_point(&Q.x, &Q.y);
    let s = uint_to_ark::<Fr>(s);

    (T * s + U).into_affine() == Q
  }

  fn regular_ECDSA_ver(digest : &str, s: &BigUint, R_x : &BigUint, Q : &Point<BigUint>) -> bool{
    let z = hex_to_ark::<Fr>(digest);
    let s = uint_to_ark::<Fr>(s);
    let u1 = z/s;
    let r = uint_to_ark::<Fr>(R_x);
    let u2 = r/s;
    let G = hex_to_point( "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
    let Q = uint_to_point(&Q.x, &Q.y);
    let Rprime = G * u1 + Q * u2;
    let Rprime = Rprime.into_affine();

    Rprime.x == uint_to_ark::<Fp>(R_x)
  }

  // cargo test --release --features print-trace test_ecdsa_proof -- --nocapture
  #[test]
  fn test_ecdsa_proof() {

    // A test vector from from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P256_SHA256.pdf
    let digest ="A41A41A12A799548211C410C65D8133AFDE34D28BDD542E4B680CF2899C8A8C4";
    let R_x = hex_to_big("2B42F576D07F4165FF65D1F3B1500F81E44C316F1F0B3EF57325B69ACA46104F");
    let R_y = hex_to_big("3CE76603264661EA2F602DF7B4510BBC9ED939233C553EA5F42FB3F1338174B5");
    let s = hex_to_big("DC42C2122D6392CD3E3A993A89502A8198C1886FE69D262C4B329BDB6B63FAF1");
    let R = Point{x: R_x.clone(), y: R_y};
    let (T, U) = ECDSACircuitPublicInputs::compute_TU(&R, digest, &NamedCurve::Secp256r1);

    let Q_x = hex_to_big("B7E08AFDFE94BAD3F1DC8C734798BA1C62B3A0AD1E9EA2A38201CD0889BC7A19");
    let Q_y = hex_to_big("3603F747959DBF7A4BB226E41928729063ADC7AE43529E61B563BBC606CC5E09");
    let Q = Point{x: Q_x, y: Q_y};
    let d = hex_to_big("C477F9F65C22CCE20657FAA5B2D1D8122336F851A508A1ED04E479C34985BF96");

    assert!(check_keypair(&Q, &d));

    assert!(regular_ECDSA_ver(digest, &s, &R_x, &Q));

    assert!(modified_ECDSA_ver(&T, &U, &Q, &s));

    test_ecdsa_proof_with_committed_pk(&Q, &T, &U, &s);
  }

  struct PedCom {
    C: G1Affine,
    _m: Bn254_Fr,
    r: Bn254_Fr
  }

  fn commit(m : &BigUint, G: &G1Affine, H: &G1Affine) -> PedCom {
    let mut rng = thread_rng();
    let m = Bn254_Fr::from_bigint(ark_ff::BigInt::try_from(m.clone()).unwrap()).unwrap();
    let r = Bn254_Fr::rand(&mut rng);
    let C = ((*G * m) + (*H * r)).into_affine();

    PedCom{C, _m: m, r}
  }

 
  fn compute_mock_adapter_values(Qx: &BigUint) -> (BigUint, BigUint, Vec<u8>, BigUint, BigUint, BigUint,  BigUint) {
    let params = ECDSAParams::new(NamedCurve::Secp256r1, NamedCurve::Bn254);
    let mut rng = thread_rng();
    // Public key Q will be provided as two Pedersen commitments to the high and low
    // bytes of Q.x
    let (q0, q1) = ECDSAProof::split_public_key_x(Qx);
   
    // Setup some commitment bases G and H (just placeholders; the real values defined in Crescent)
    let G = G1Affine::generator();
    let H = (G * Bn254_Fr::from_bigint(ark_ff::BigInt::from(1234u64)).unwrap()).into_affine();

    let z = Bn254_Fr::rand(&mut rng);
    let C0 = commit(&q0, &G, &H);
    let C1 = commit(&q1, &G, &H);
    let Cz = commit(&z.into(), &G, &H);

    // Use Poseidon on T-256's scalar field (P256 basefield) to hash (q0, q1, z)
    let hQ = ECDSAProofCircuit::compute_hQ(&params, &q0, &q1, &ark_to_uint(&z));

    let mut sha2 = Sha256::new();
    sha2.update("Compute challenge to combine commitments C0, C1, Cz");
    sha2.update(C0.C.to_string());
    sha2.update(C1.C.to_string());
    sha2.update(Cz.C.to_string());
    sha2.update(&hQ);
    let digest = sha2.finalize();
    let e1 = &digest[0..16];
    let e2 = &digest[16..32];

    // Compute    m = q0 + q1*e1 + z*e2 (mod q)
    //  and     C_m = C0 + e1 * C1 + e2 * Cz
    let e1 = Bn254_Fr::from_le_bytes_mod_order(e1);
    let e2 = Bn254_Fr::from_le_bytes_mod_order(e2);
    let q0a = uint_to_ark::<Bn254_Fr>(&q0);
    let q1a = uint_to_ark::<Bn254_Fr>(&q1);

    let m = q0a + q1a*e1 + z*e2;
    let C = (C0.C + (C1.C * e1) + (Cz.C * e2)).into_affine();
    let r = C0.r + C1.r*e1 + Cz.r*e2;
    let _Cm = PedCom{C, _m: m, r};

    (q0, q1, hQ, m.into(), e1.into(), e2.into(), z.into())
  }

  fn test_ecdsa_proof_with_committed_pk(Q: &Point<BigUint>, T: &Point<BigUint>, U: &Point<BigUint>, s: &BigUint) {

    let (q0, q1, hQ, m, e1, e2, z) = compute_mock_adapter_values(&Q.x);

    let params = ECDSAParams::new(NamedCurve::Secp256r1, NamedCurve::Bn254);    
    let public_inputs = ECDSACircuitPublicInputs::new(T, U, &hQ, m, e1, e2);
    let prover_inputs = ECDSACircuitProverInputs::new(s, &q0, &q1, &z);
    let circuit_verifier = ECDSAProofCircuit::new(&params,  None, &public_inputs);
    let circuit_prover = ECDSAProofCircuit::new(&params,  Some(prover_inputs), &public_inputs);

    // For debugging, we'll use the test constraint system. If there is a failure it'll tell us where
    let mut cs = TestConstraintSystem::<Scalar>::new();
    circuit_prover.clone()
      .synthesize(&mut cs.namespace(|| "build_test_vec"))
      .unwrap();

    println!(
      "test_ecdsa_cs: ECDSA circuit has {} constraints and {} aux values",
      cs.num_constraints().to_formatted_string(&Locale::en),
      cs.aux().len().to_formatted_string(&Locale::en)
    );

    assert!(cs.is_satisfied());

    let t = start_timer!(|| "Getting R1CS Shape");
    let mut cs = ShapeCS::<Scalar>::new();
    let _ = circuit_verifier.synthesize(&mut cs.namespace(||"synthesize verifier"));
    let shape = cs.r1cs_shape();
    end_timer!(t);

    let t = start_timer!(|| "Calculate witness");
    let mut cs: SatisfyingAssignment<Scalar> = SatisfyingAssignment::new();
    let _ = circuit_prover.synthesize(&mut cs.namespace(||"calculate witness"));

    let (inst, witness, inputs) = cs.r1cs_instance_and_witness(&shape);
    end_timer!(t);

    let t = start_timer!(|| "Checking satisfiability (debugging only)");
    let is_sat = inst.is_sat(&witness, &inputs);
    assert!(is_sat.is_ok());
    assert!(is_sat.unwrap());
    end_timer!(t);

    let t = start_timer!(|| "Producing NIZK public generators");
    let gens = NIZKGens::new(shape.num_cons, shape.num_vars, shape.num_io);
    end_timer!(t);

    let t = start_timer!(|| "Generate NIZK proof");
    let mut prover_transcript = Transcript::new(b"nizk_example");
    let proof = NIZK::prove(&inst, witness, &inputs, &gens, &mut prover_transcript);
    end_timer!(t);

    let proof_str = bincode::serialize(&proof).unwrap();
    println!("Proof length, serialized by bincode: {} ", proof_str.len());

    let t = start_timer!(|| "Compress proof");
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    bincode::serialize_into(&mut encoder, &proof).unwrap();
    let proof_encoded = encoder.finish().unwrap();
    end_timer!(t);

    let msg_proof_len = format!("NIZK::proof_compressed_len {:?}", proof_encoded.len());
    println!("{msg_proof_len}");

    let t = start_timer!(|| "Decompress proof");
    let mut decoder = ZlibDecoder::new(Vec::new());
    assert!(decoder.write_all(&proof_encoded).is_ok());
    let _proof_decoded : NIZK = bincode::deserialize(&decoder.finish().unwrap()).unwrap();
    end_timer!(t);

    let t = start_timer!(|| "Verify proof");
    let mut verifier_transcript = Transcript::new(b"nizk_example");
    assert!(proof
      .verify(&inst, &inputs, &mut verifier_transcript, &gens)
      .is_ok());
    end_timer!(t);

  }


  #[test]
  fn test_ecdsa_public_api() {

    // test from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P256_SHA256.pdf
    let digest = hex::decode("A41A41A12A799548211C410C65D8133AFDE34D28BDD542E4B680CF2899C8A8C4").unwrap();
    let r = hex_to_big("2B42F576D07F4165FF65D1F3B1500F81E44C316F1F0B3EF57325B69ACA46104F");
    let s = hex_to_big("DC42C2122D6392CD3E3A993A89502A8198C1886FE69D262C4B329BDB6B63FAF1");
    let Q_x = hex_to_big("B7E08AFDFE94BAD3F1DC8C734798BA1C62B3A0AD1E9EA2A38201CD0889BC7A19");
    let Q_y = hex_to_big("3603F747959DBF7A4BB226E41928729063ADC7AE43529E61B563BBC606CC5E09");

    let (_q0, _q1, hQ, m, e1, e2, z) = compute_mock_adapter_values(&Q_x);
    let e1 = e1.to_bytes_le();
    let e2 = e2.to_bytes_le();

    let params = ECDSAParams::new(NamedCurve::Secp256r1, NamedCurve::Bn254);
    
    let t = start_timer!(||"ECDSAProof::prove");
    let (Rx, Ry, proof) = ECDSAProof::prove(&params, &Q_x, &Q_y, &r, &s, &digest, &hQ, &m, &e1, &e2, &z, true);
    end_timer!(t);

    let t = start_timer!(||"ECDSAProof::verify");
    let valid = ECDSAProof::verify(&params, &Rx, &Ry, &digest, &hQ, &m, &e1, &e2, &proof);
    end_timer!(t);

    assert!(valid);
  }


}
