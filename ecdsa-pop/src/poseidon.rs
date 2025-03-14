//! Poseidon Constants and Poseidon hash function
//! This file is adapted from the Nova implementation
//! https://github.com/microsoft/Nova/blob/79de586b1e61caabbc7ad1854d6dec41f56313d7/src/provider/poseidon.rs#L1
use bellpepper_core::{
  boolean::{AllocatedBit, Boolean},
  num::AllocatedNum,
  ConstraintSystem, SynthesisError,
};
//use core::marker::PhantomData;
use ff::{PrimeField, PrimeFieldBits};
use generic_array::typenum::U2;
use neptune::{
  circuit2::Elt,
  poseidon::PoseidonConstants,
  sponge::{
    api::{IOPattern, SpongeAPI, SpongeOp},
    circuit::SpongeCircuit,
    vanilla::{Mode::Simplex, Sponge, SpongeTrait},
  },
  Strength,
};
use serde::{Deserialize, Serialize};

use crate::utils::le_bits_to_num;

/// All Poseidon constants
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct PoseidonConstantsCircuit<Scalar: PrimeField>(PoseidonConstants<Scalar, U2>);

impl<Scalar: PrimeField> Default for PoseidonConstantsCircuit<Scalar> {
  /// Generate Poseidon constants
  fn default() -> Self {
    Self(Sponge::<Scalar, U2>::api_constants(Strength::Standard))
  }
}

/// A Poseidon-based sponge to use outside circuits
#[derive(Serialize, Deserialize)]
pub struct Poseidon<Scalar>
where
  Scalar: PrimeField,
{
  // Internal State
  state: Vec<Scalar>,
  constants: PoseidonConstantsCircuit<Scalar>,
  num_absorbs: usize,
  squeezed: bool,
}

impl<Scalar>  Poseidon<Scalar> 
where
  Scalar: PrimeField + PrimeFieldBits + Serialize + for<'de> Deserialize<'de>,
{
  pub fn new(constants: PoseidonConstantsCircuit<Scalar>, num_absorbs: usize) -> Self {
    Self {
      state: Vec::new(),
      constants,
      num_absorbs,
      squeezed: false,
    }
  }

  /// Absorb a new number into the state of the sponge
  pub fn absorb(&mut self, e: Scalar) {
    assert!(!self.squeezed, "Cannot absorb after squeezing");
    self.state.push(e);
  }

  #[allow(dead_code)]
  /// Compute a digest by hashing the current state
  pub fn squeeze(&mut self, num_bits: usize) -> Scalar {
    // check if we have squeezed already
    assert!(!self.squeezed, "Cannot squeeze again after squeezing");
    self.squeezed = true;

    let mut sponge = Sponge::new_with_constants(&self.constants.0, Simplex);
    let acc = &mut ();
    let parameter = IOPattern(vec![
      SpongeOp::Absorb(self.num_absorbs as u32),
      SpongeOp::Squeeze(1u32),
    ]);

    sponge.start(parameter, None, acc);
    assert_eq!(self.num_absorbs, self.state.len());
    SpongeAPI::absorb(&mut sponge, self.num_absorbs as u32, &self.state, acc);
    let hash = SpongeAPI::squeeze(&mut sponge, 1, acc);
    sponge.finish(acc).unwrap();

    // Only return `num_bits`
    let bits = hash[0].to_le_bits();
    let mut res = Scalar::ZERO;
    let mut coeff = Scalar::ONE;
    for bit in bits[0..num_bits].into_iter() {
      if *bit {
        res += coeff;
      }
      coeff += coeff;
    }
    res
  }

  /// Compute a digest that is one field element long
  pub fn squeeze_field_element(&mut self) -> Scalar {
    // check if we have squeezed already
    assert!(!self.squeezed, "Cannot squeeze again after squeezing");
    self.squeezed = true;

    let mut sponge = Sponge::new_with_constants(&self.constants.0, Simplex);
    let acc = &mut ();
    let parameter = IOPattern(vec![
      SpongeOp::Absorb(self.num_absorbs as u32),
      SpongeOp::Squeeze(1u32),
    ]);

    sponge.start(parameter, None, acc);
    assert_eq!(self.num_absorbs, self.state.len());
    SpongeAPI::absorb(&mut sponge, self.num_absorbs as u32, &self.state, acc);
    let hash = SpongeAPI::squeeze(&mut sponge, 1, acc);
    sponge.finish(acc).unwrap();

    hash[0]
  }

}

/// A Poseidon-based sponge gadget to use inside the verifier circuit.
#[derive(Serialize, Deserialize)]
pub struct PoseidonCircuit<Scalar: PrimeField> {
  // Internal state
  state: Vec<AllocatedNum<Scalar>>,
  constants: PoseidonConstantsCircuit<Scalar>,
  num_absorbs: usize,
  squeezed: bool,
}

impl<Scalar> PoseidonCircuit<Scalar>
where
  Scalar: PrimeField + PrimeFieldBits + Serialize + for<'de> Deserialize<'de>,
{
  /// Initialize the internal state and set the poseidon constants
  pub fn new(constants: PoseidonConstantsCircuit<Scalar>, num_absorbs: usize) -> Self {
    Self {
      state: Vec::new(),
      constants,
      num_absorbs,
      squeezed: false,
    }
  }

  /// Absorb a new scalar into the state of the sponge
  pub fn absorb(&mut self, e: &AllocatedNum<Scalar>) {
    assert!(!self.squeezed, "Cannot absorb after squeezing");
    self.state.push(e.clone());
  }

  /// Compute a digest by hashing the current state
  #[allow(dead_code)]
  pub fn squeeze_to_bits<CS: ConstraintSystem<Scalar>>(
    &mut self,
    mut cs: CS,
    num_bits: usize,
  ) -> Result<Vec<AllocatedBit>, SynthesisError> {
    let mut ns = cs.namespace(|| "ns");
    let hash = self.squeeze_field_element(ns.namespace(||"Squeeze a field element"))?;
    // return the hash as a vector of bits, truncated
    Ok(
      hash
        .to_bits_le(ns.namespace(|| "poseidon hash to boolean"))?
        .iter()
        .map(|boolean| match boolean {
          Boolean::Is(ref x) => x.clone(),
          _ => panic!("Wrong type of input. We should have never reached there"),
        })
        .collect::<Vec<AllocatedBit>>()[..num_bits]
        .into(),
    )
  }
    /// Compute a digest by hashing the current state
    #[allow(dead_code)]
    pub fn squeeze<CS: ConstraintSystem<Scalar>>(
      &mut self,
      mut cs: CS, 
      num_bits: usize,      
    ) -> Result<AllocatedNum<Scalar>, SynthesisError> {

      let hash_bits = Self::squeeze_to_bits(self, cs.namespace(||"squeeze to bits"), num_bits)?;
      
      // convert hash bits to allocated scalar and return
      le_bits_to_num(&mut cs.namespace(||"Convert hash bits to num"), &hash_bits)
    }

    /// Compute a digest by hashing the current state
    pub fn squeeze_field_element<CS: ConstraintSystem<Scalar>>(
      &mut self,
      mut cs: CS,   
    ) -> Result<AllocatedNum<Scalar>, SynthesisError> {

      // check if we have squeezed already
      assert!(!self.squeezed, "Cannot squeeze again after squeezing");
      self.squeezed = true;
      let parameter = IOPattern(vec![
        SpongeOp::Absorb(self.num_absorbs as u32),
        SpongeOp::Squeeze(1u32),
      ]);
      let mut ns = cs.namespace(|| "ns");

      let hash = {
        let mut sponge = SpongeCircuit::new_with_constants(&self.constants.0, Simplex);
        let acc = &mut ns;
        assert_eq!(self.num_absorbs, self.state.len());

        sponge.start(parameter, None, acc);
        neptune::sponge::api::SpongeAPI::absorb(
          &mut sponge,
          self.num_absorbs as u32,
          &(0..self.state.len())
            .map(|i| Elt::Allocated(self.state[i].clone()))
            .collect::<Vec<Elt<Scalar>>>(),
          acc,
        );

        let output = neptune::sponge::api::SpongeAPI::squeeze(&mut sponge, 1, acc);
        sponge.finish(acc).unwrap();
        output
      };

      let hash = Elt::ensure_allocated(&hash[0], &mut ns.namespace(|| "ensure allocated"), true)?;

      Ok(hash)
    }    

}

#[cfg(test)]
mod tests {
  use super::*;
  use ark_std::{end_timer, start_timer};
use bellpepper_core::LinearCombination;
  use bellpepper_core::test_cs::TestConstraintSystem;
  use halo2curves::secp256r1::Fp as Scalar;
  use generic_array::typenum::U2 as A;
  use ff::Field;
   
  const NUM_HASH_BITS: usize = 248;

  // helper function 
  pub fn le_bits_to_num<Scalar, CS>(
    mut cs: CS,
    bits: &[AllocatedBit],
  ) -> Result<AllocatedNum<Scalar>, SynthesisError>
  where
    Scalar: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<Scalar>,
  {
    // We loop over the input bits and construct the constraint
    // and the field element that corresponds to the result
    let mut lc = LinearCombination::zero();
    let mut coeff = Scalar::ONE;
    let mut fe = Some(Scalar::ZERO);
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


  #[test]
  fn test_poseidon_sponge()
  {
    // Check that the number computed inside the circuit is equal to the number computed outside the circuit
    //let mut csprng: OsRng = OsRng;
    let constants = PoseidonConstantsCircuit::<Scalar>::default();
    let num_absorbs = 2;
    let mut ro: Poseidon<Scalar> = Poseidon::new(constants.clone(), num_absorbs);
    let mut ro_gadget: PoseidonCircuit<Scalar> =
      PoseidonCircuit::new(constants, num_absorbs);
    let mut cs = TestConstraintSystem::<Scalar>::new();
    for i in 0..num_absorbs {
      let num = Scalar::from(i as u64);
      ro.absorb(num);
      let num_gadget = AllocatedNum::alloc(cs.namespace(|| format!("data {i}")), || Ok(num)).unwrap();
      num_gadget
        .inputize(&mut cs.namespace(|| format!("input {i}")))
        .unwrap();
      ro_gadget.absorb(&num_gadget);
    }
    let num = ro.squeeze(NUM_HASH_BITS);
    let num2_bits = ro_gadget.squeeze_to_bits(&mut cs, NUM_HASH_BITS).unwrap();
    let num2 = le_bits_to_num(&mut cs, &num2_bits).unwrap();
    assert_eq!(num , num2.get_value().unwrap());
    assert!(cs.is_satisfied());
    assert_eq!(cs.num_constraints(), 498)
  }

  #[test]
  fn test_poseidon_direct() {
    // In this test we compare the speed of directly calling Poseidon from Neptune vs using the sponge wrapper
    // They're about the same speed
    let arity = 2; 
    let preimage1 = vec![<Scalar as Field>::ONE; arity];    
    let preimage2 = vec![<Scalar as Field>::ONE; arity];
    let constants_timer = start_timer!(||"Generating Poseidon Constants");
    let consts = neptune::poseidon::PoseidonConstants::<Scalar, A>::new();
    end_timer!(constants_timer);
    let poseidon_timer = start_timer!(||"Poseidon Hashing (neptune)");
    let _hash1 = neptune::poseidon::Poseidon::new_with_preimage(&preimage1, &consts).hash();
    let _hash2 = neptune::poseidon::Poseidon::new_with_preimage(&preimage2, &consts).hash();
    end_timer!(poseidon_timer);

    let consts = PoseidonConstantsCircuit::<Scalar>::default();
    let poseidon_timer = start_timer!(||"Poseidon Hashing (sponge)");
    let mut poseidon: Poseidon<Scalar> = Poseidon::new(consts.clone(), 2);
    poseidon.absorb(preimage1[0]);
    poseidon.absorb(preimage1[1]);
    let _hash1 = poseidon.squeeze(248);
    let mut poseidon: Poseidon<Scalar> = Poseidon::new(consts.clone(), 2);
    poseidon.absorb(preimage2[0]);
    poseidon.absorb(preimage2[1]);
    let _hash2 = poseidon.squeeze(248);    
    end_timer!(poseidon_timer);
  }

}
