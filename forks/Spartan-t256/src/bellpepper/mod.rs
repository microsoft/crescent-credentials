//! Support for generating R1CS from [Bellperson].
//!
//! [Bellperson]: https://github.com/filecoin-project/bellperson
//! 
//! This code is adapted from [Spartan2] https://github.com/Microsoft/Spartan2

pub mod r1cs;
pub mod shape_cs;
pub mod solver;
pub mod test_shape_cs;

#[cfg(test)]
mod tests {
  use crate::{
    bellpepper::{
      shape_cs::ShapeCS,
      solver::SatisfyingAssignment,
    }, NIZKGens, NIZK
  };
  use bellpepper_core::{boolean::AllocatedBit, num::AllocatedNum, ConstraintSystem, LinearCombination, SynthesisError};
  use ff::{PrimeField, PrimeFieldBits};
  use itertools::Itertools;
  use flate2::{write::ZlibEncoder, Compression};
  use merlin::Transcript;
  use rand::random;

  type F = circ_fields::ff_field::f_t256::Ft;

  fn synthesize_alloc_bit<Fr: PrimeField, CS: ConstraintSystem<Fr>>(
    cs: &mut CS,
  ) -> Result<(), SynthesisError> {
    // get two bits as input and check that they are indeed bits
    let a = AllocatedNum::alloc(cs.namespace(|| "a"), || Ok(Fr::ONE))?;
    let _ = a.inputize(cs.namespace(|| "a is input"));
    cs.enforce(
      || "check a is 0 or 1",
      |lc| lc + CS::one() - a.get_variable(),
      |lc| lc + a.get_variable(),
      |lc| lc,
    );
    let b = AllocatedNum::alloc(cs.namespace(|| "b"), || Ok(Fr::ONE))?;
    let _ = b.inputize(cs.namespace(|| "b is input"));
    cs.enforce(
      || "check b is 0 or 1",
      |lc| lc + CS::one() - b.get_variable(),
      |lc| lc + b.get_variable(),
      |lc| lc,
    );

    Ok(())
  }

  #[test]
  fn test_alloc_bit()
  {
    type F = circ_fields::ff_field::f_t256::Ft;
    // First create the shape
    let mut cs = ShapeCS::<F>::new();
    let _ = synthesize_alloc_bit(&mut cs);
    let shape = cs.r1cs_shape();

    // Now get the assignment
    let mut cs: SatisfyingAssignment<F> = SatisfyingAssignment::new();
    let _ = synthesize_alloc_bit(&mut cs);

    let (inst, witness, inputs) = cs.r1cs_instance_and_witness(&shape);

    let is_sat = inst.is_sat(&witness, &inputs);
    assert!(is_sat.is_ok());
    assert_eq!(is_sat.unwrap(), true);
  }

  // A sample gadget for testing
  /// Gets as input the little endian representation of a number and spits out
  /// the number
  fn le_bits_to_num<F, CS>(
    mut cs: CS,
    bits: &[AllocatedBit],
  ) -> Result<AllocatedNum<F>, SynthesisError>
  where
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
  {
    // We loop over the input bits and construct the constraint
    // and the field element that corresponds to the result
    let mut lc = LinearCombination::zero();
    let mut coeff = F::ONE;
    let mut fe = Some(F::ZERO);
    for bit in bits.iter() {
      lc = lc + (coeff, bit.get_variable());
      fe = bit.get_value().map(|val| {
        if val {
          fe.unwrap() + coeff
        } else {
          fe.unwrap()
        }
      });
      coeff = coeff.double();
    }
    let num = AllocatedNum::alloc(cs.namespace(|| "Field element"), || {
      fe.ok_or(SynthesisError::AssignmentMissing)
    })?;
    lc = lc - num.get_variable();
    cs.enforce(|| "compute number from bits", |lc| lc, |lc| lc, |_| lc);
    Ok(num)
  }

  fn synthesize_bits_to_num<F: PrimeField + PrimeFieldBits, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    bits_le : &Vec<bool>
  ) -> Result<Option<F>, SynthesisError> {

    let mut alloc_bits : Vec<AllocatedBit> = vec![];
    for (i, b) in  bits_le.iter().enumerate() {
       alloc_bits.push(
        AllocatedBit::alloc(
        &mut cs.namespace(|| format!("alloc x[{}] = {}",i,b)), 
        Some(b.clone()))?
      );
    }
    let alloc_num = le_bits_to_num(&mut cs.namespace(||"let_bits_to_num(x)"), &alloc_bits)?;

    Ok(alloc_num.get_value())
  }  

  #[test]
  fn test_bits_to_num() {
    let x = random::<u64>();
    let x_bits_le : Vec<bool> = (0..64).map(|i| ((x>>i) & 1) != 0 ).collect_vec();

    // First create the shape
    let mut cs = ShapeCS::<F>::new();
    let _ = synthesize_bits_to_num(&mut cs, &x_bits_le);
    let shape = cs.r1cs_shape();

    // Now get the assignment
    let mut cs: SatisfyingAssignment<F> = SatisfyingAssignment::new();
    let num = synthesize_bits_to_num(&mut cs, &x_bits_le);

    assert_eq!(num.unwrap().unwrap(), F::from(x));

    let (inst, witness, inputs) = cs.r1cs_instance_and_witness(&shape);

    let is_sat = inst.is_sat(&witness, &inputs);
    assert!(is_sat.is_ok());
    assert_eq!(is_sat.unwrap(), true);

  }

  #[test]
  fn test_bellpepper_circuit_with_nizk() {
    let x = random::<u64>();
    let x_bits_le : Vec<bool> = (0..64).map(|i| ((x>>i) & 1) != 0 ).collect_vec();

    // First create the shape
    let mut cs = ShapeCS::<F>::new();
    let _ = synthesize_bits_to_num(&mut cs, &x_bits_le);
    let shape = cs.r1cs_shape();

    // Now get the assignment
    let mut cs: SatisfyingAssignment<F> = SatisfyingAssignment::new();
    let num = synthesize_bits_to_num(&mut cs, &x_bits_le);

    assert_eq!(num.unwrap().unwrap(), F::from(x));

    let (inst, witness, inputs) = cs.r1cs_instance_and_witness(&shape);

    let is_sat = inst.is_sat(&witness, &inputs);
    assert!(is_sat.is_ok());
    assert_eq!(is_sat.unwrap(), true);

    // produce public generators
    let gens = NIZKGens::new(shape.num_cons, shape.num_vars, shape.num_io);

    // produce a proof of satisfiability
    let mut prover_transcript = Transcript::new(b"nizk_example");
    let proof = NIZK::prove(&inst, witness, &inputs, &gens, &mut prover_transcript);

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    bincode::serialize_into(&mut encoder, &proof).unwrap();
    let proof_encoded = encoder.finish().unwrap();
    let msg_proof_len = format!("NIZK::proof_compressed_len {:?}", proof_encoded.len());
    println!("{}", msg_proof_len);

    // verify the proof of satisfiability
    let mut verifier_transcript = Transcript::new(b"nizk_example");
    assert!(proof
      .verify(&inst, &inputs, &mut verifier_transcript, &gens)
      .is_ok());

  }

}