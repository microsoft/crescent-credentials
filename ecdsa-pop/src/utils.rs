#![allow(unused)]

//! This module implements various low-level gadgets
use bellpepper::gadgets::Assignment;
use bellpepper_core::{
  boolean::{AllocatedBit, Boolean},
  num::AllocatedNum,
  ConstraintSystem, LinearCombination, SynthesisError,
};
use ff::{PrimeField, PrimeFieldBits};
use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::Num;

/// Gets as input the little indian representation of a number and spits out
/// the number
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

/// Allocate a variable that is set to zero
pub fn alloc_zero<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
) -> Result<AllocatedNum<F>, SynthesisError> {
  let zero = AllocatedNum::alloc(cs.namespace(|| "alloc"), || Ok(F::ZERO))?;
  cs.enforce(
    || "check zero is valid",
    |lc| lc,
    |lc| lc,
    |lc| lc + zero.get_variable(),
  );
  Ok(zero)
}

/// Allocate a variable that is set to one
pub fn alloc_one<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
) -> Result<AllocatedNum<F>, SynthesisError> {
  let one = AllocatedNum::alloc(cs.namespace(|| "alloc"), || Ok(F::ONE))?;
  cs.enforce(
    || "check one is valid",
    |lc| lc + CS::one(),
    |lc| lc + CS::one(),
    |lc| lc + one.get_variable(),
  );

  Ok(one)
}

/// Check that two numbers are equal and return a bit
pub fn alloc_num_equals<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  b: &AllocatedNum<F>,
) -> Result<AllocatedBit, SynthesisError> {
  // Allocate and constrain `r`: result boolean bit.
  // It equals `true` if `a` equals `b`, `false` otherwise
  let r_value = match (a.get_value(), b.get_value()) {
    (Some(a), Some(b)) => Some(a == b),
    _ => None,
  };

  let r = AllocatedBit::alloc(cs.namespace(|| "r"), r_value)?;

  // Allocate t s.t. t=1 if z1 == z2 else 1/(z1 - z2)

  let t = AllocatedNum::alloc(cs.namespace(|| "t"), || {
    Ok(if *a.get_value().get()? == *b.get_value().get()? {
      F::ONE
    } else {
      (*a.get_value().get()? - *b.get_value().get()?)
        .invert()
        .unwrap()
    })
  })?;

  cs.enforce(
    || "t*(a - b) = 1 - r",
    |lc| lc + t.get_variable(),
    |lc| lc + a.get_variable() - b.get_variable(),
    |lc| lc + CS::one() - r.get_variable(),
  );

  cs.enforce(
    || "r*(a - b) = 0",
    |lc| lc + r.get_variable(),
    |lc| lc + a.get_variable() - b.get_variable(),
    |lc| lc,
  );

  Ok(r)
}

pub fn enforce_equal<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  a: &AllocatedNum<F>, 
  b: &AllocatedNum<F>
) {
      cs.enforce(
        || "check a == b",
        |lc| lc + a.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + b.get_variable(),
      );
}

/// If condition return a otherwise b
pub fn conditionally_select<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  b: &AllocatedNum<F>,
  condition: &Boolean,
) -> Result<AllocatedNum<F>, SynthesisError> {
  let c = AllocatedNum::alloc(cs.namespace(|| "conditional select result"), || {
    if *condition.get_value().get()? {
      Ok(*a.get_value().get()?)
    } else {
      Ok(*b.get_value().get()?)
    }
  })?;

  // a * condition + b*(1-condition) = c ->
  // a * condition - b*condition = c - b
  cs.enforce(
    || "conditional select constraint",
    |lc| lc + a.get_variable() - b.get_variable(),
    |_| condition.lc(CS::one(), F::ONE),
    |lc| lc + c.get_variable() - b.get_variable(),
  );

  Ok(c)
}

/// If condition return a otherwise b
pub fn conditionally_select_vec<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  a: &[AllocatedNum<F>],
  b: &[AllocatedNum<F>],
  condition: &Boolean,
) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
  a.iter()
    .zip(b.iter())
    .enumerate()
    .map(|(i, (a, b))| {
      conditionally_select(cs.namespace(|| format!("select_{i}")), a, b, condition)
    })
    .collect::<Result<Vec<AllocatedNum<F>>, SynthesisError>>()
}

/// Same as the above but Condition is an `AllocatedNum` that needs to be
/// 0 or 1. 1 => True, 0 => False
pub fn conditionally_select2<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  b: &AllocatedNum<F>,
  condition: &AllocatedNum<F>,
) -> Result<AllocatedNum<F>, SynthesisError> {
  let c = AllocatedNum::alloc(cs.namespace(|| "conditional select result"), || {
    if *condition.get_value().get()? == F::ONE {
      Ok(*a.get_value().get()?)
    } else {
      Ok(*b.get_value().get()?)
    }
  })?;

  // a * condition + b*(1-condition) = c ->
  // a * condition - b*condition = c - b
  cs.enforce(
    || "conditional select constraint",
    |lc| lc + a.get_variable() - b.get_variable(),
    |lc| lc + condition.get_variable(),
    |lc| lc + c.get_variable() - b.get_variable(),
  );

  Ok(c)
}

/// If condition set to 0 otherwise a. Condition is an allocated num
pub fn select_zero_or_num2<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  condition: &AllocatedNum<F>,
) -> Result<AllocatedNum<F>, SynthesisError> {
  let c = AllocatedNum::alloc(cs.namespace(|| "conditional select result"), || {
    if *condition.get_value().get()? == F::ONE {
      Ok(F::ZERO)
    } else {
      Ok(*a.get_value().get()?)
    }
  })?;

  // a * (1 - condition) = c
  cs.enforce(
    || "conditional select constraint",
    |lc| lc + a.get_variable(),
    |lc| lc + CS::one() - condition.get_variable(),
    |lc| lc + c.get_variable(),
  );

  Ok(c)
}

/// If condition set to a otherwise 0. Condition is an allocated num
pub fn select_num_or_zero2<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  condition: &AllocatedNum<F>,
) -> Result<AllocatedNum<F>, SynthesisError> {
  let c = AllocatedNum::alloc(cs.namespace(|| "conditional select result"), || {
    if *condition.get_value().get()? == F::ONE {
      Ok(*a.get_value().get()?)
    } else {
      Ok(F::ZERO)
    }
  })?;

  cs.enforce(
    || "conditional select constraint",
    |lc| lc + a.get_variable(),
    |lc| lc + condition.get_variable(),
    |lc| lc + c.get_variable(),
  );

  Ok(c)
}

/// If condition set to a otherwise 0
pub fn select_num_or_zero<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  condition: &Boolean,
) -> Result<AllocatedNum<F>, SynthesisError> {
  let c = AllocatedNum::alloc(cs.namespace(|| "conditional select result"), || {
    if *condition.get_value().get()? {
      Ok(*a.get_value().get()?)
    } else {
      Ok(F::ZERO)
    }
  })?;

  cs.enforce(
    || "conditional select constraint",
    |lc| lc + a.get_variable(),
    |_| condition.lc(CS::one(), F::ONE),
    |lc| lc + c.get_variable(),
  );

  Ok(c)
}

/// If condition set to 1 otherwise a
pub fn select_one_or_num2<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  condition: &AllocatedNum<F>,
) -> Result<AllocatedNum<F>, SynthesisError> {
  let c = AllocatedNum::alloc(cs.namespace(|| "conditional select result"), || {
    if *condition.get_value().get()? == F::ONE {
      Ok(F::ONE)
    } else {
      Ok(*a.get_value().get()?)
    }
  })?;

  cs.enforce(
    || "conditional select constraint",
    |lc| lc + CS::one() - a.get_variable(),
    |lc| lc + condition.get_variable(),
    |lc| lc + c.get_variable() - a.get_variable(),
  );
  Ok(c)
}

/// If condition set to 1 otherwise a - b
pub fn select_one_or_diff2<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  b: &AllocatedNum<F>,
  condition: &AllocatedNum<F>,
) -> Result<AllocatedNum<F>, SynthesisError> {
  let c = AllocatedNum::alloc(cs.namespace(|| "conditional select result"), || {
    if *condition.get_value().get()? == F::ONE {
      Ok(F::ONE)
    } else {
      Ok(*a.get_value().get()? - *b.get_value().get()?)
    }
  })?;

  cs.enforce(
    || "conditional select constraint",
    |lc| lc + CS::one() - a.get_variable() + b.get_variable(),
    |lc| lc + condition.get_variable(),
    |lc| lc + c.get_variable() - a.get_variable() + b.get_variable(),
  );
  Ok(c)
}

/// If condition set to a otherwise 1 for boolean conditions
pub fn select_num_or_one<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  condition: &Boolean,
) -> Result<AllocatedNum<F>, SynthesisError> {
  let c = AllocatedNum::alloc(cs.namespace(|| "conditional select result"), || {
    if *condition.get_value().get()? {
      Ok(*a.get_value().get()?)
    } else {
      Ok(F::ONE)
    }
  })?;

  cs.enforce(
    || "conditional select constraint",
    |lc| lc + a.get_variable() - CS::one(),
    |_| condition.lc(CS::one(), F::ONE),
    |lc| lc + c.get_variable() - CS::one(),
  );

  Ok(c)
}

/// Check that two numbers are equal and return result as field element in {0,1}
pub fn alloc_num_equals_constant<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  b: u64,
) -> Result<AllocatedNum<F>, SynthesisError> {
  // Convert b to AllocatedNum
  let b_scalar = F::from_u128(b as u128);
  let b_allocated = AllocatedNum::alloc(cs.namespace(|| "b"), || Ok(b_scalar))?;

  // Allocate and constrain `r`: a bit encoding the comparison result, as a scalar.
  // It equals 1 if `a` equals `b`, 0 otherwise
  let r = AllocatedNum::alloc(cs.namespace(|| "r"), || {
    if a.get_value().is_some() {
      if a.get_value().unwrap() == b_scalar {
        Ok(F::ONE)
      } else {
        Ok(F::ZERO)
      }
    } else {
      Err(SynthesisError::AssignmentMissing)
    }
  })?;
  cs.enforce(
    || "r is a bit",
    |lc| lc + r.get_variable(),
    |lc| lc + CS::one() - r.get_variable(),
    |lc| lc,
  );

  // Allocate t s.t. t=1 if z1 == z2 else 1/(z1 - z2)
  let t = AllocatedNum::alloc(cs.namespace(|| "t"), || {
    Ok(
      if *a.get_value().get()? == *b_allocated.get_value().get()? {
        F::ONE
      } else {
        (*a.get_value().get()? - *b_allocated.get_value().get()?)
          .invert()
          .unwrap()
      },
    )
  })?;

  cs.enforce(
    || "t*(a - b) = 1 - r",
    |lc| lc + t.get_variable(),
    |lc| lc + a.get_variable() - b_allocated.get_variable(),
    |lc| lc + CS::one() - r.get_variable(),
  );

  cs.enforce(
    || "r*(a - b) = 0",
    |lc| lc + r.get_variable(),
    |lc| lc + a.get_variable() - b_allocated.get_variable(),
    |lc| lc,
  );

  Ok(r)
}

// Computes a*b + c
pub fn mul_add<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  b: &AllocatedNum<F>,
  c: &AllocatedNum<F>,
) -> Result<AllocatedNum<F>, SynthesisError> {
  let r = AllocatedNum::alloc(cs.namespace(|| "a*b + c"), {
    || {
      if a.get_value().is_some() {
        Ok(a.get_value().unwrap() * b.get_value().unwrap() + c.get_value().unwrap())
      } else {
        Err(SynthesisError::AssignmentMissing)
      }
    }
  })?;

  // Constrain: r = ab + c  as  r - c = a * b
  cs.enforce(
    || "multiplication constraint",
    |lc| lc + a.get_variable(),
    |lc| lc + b.get_variable(),
    |lc| lc + r.get_variable() - c.get_variable(),
  );

  Ok(r)
}

pub fn scalar_to_biguint<Scalar: PrimeField>(x : &Scalar) -> BigUint {
  BigUint::from_bytes_le(x.to_repr().as_ref())
}
pub fn scalar_to_bigint<Scalar: PrimeField>(x : &Scalar) -> BigInt {
  scalar_to_biguint(x).to_bigint().unwrap()
}

pub fn biguint_to_scalar<Scalar:PrimeField>(x : &BigUint) -> Scalar {
  Scalar::from_str_vartime(&x.to_str_radix(10)).unwrap()
}

pub fn mod_inverse(a: &BigUint, p: &BigUint) -> BigUint {
  let two = BigUint::from(2u8);
  a.modpow(&(p - two), p)
}


/// converts a hex-encoded string into a Scalar
pub fn hex_to_ff<Scalar : PrimeField>(hex: &str) -> Scalar {
  let b = hex_to_big(hex);
  Scalar::from_str_vartime(&b.to_str_radix(10)).unwrap()
}

pub fn big_to_ff<FF: ff::PrimeField>(u : &BigUint) -> FF {
  FF::from_str_vartime(&u.to_str_radix(10)).unwrap()
}
pub fn ff_to_big<FF: ff::PrimeField>(i : &FF) -> BigUint {
  let repr = i.to_repr();
  let i_bytes : &[u8] = repr.as_ref();
  BigUint::from_bytes_le(i_bytes)
}
/// converts a hex-encoded string into a BigUint
pub fn hex_to_big(hex: &str) -> BigUint {
  let hex = if hex.len() % 2 != 0 {
    &format!("0{hex}")
  } else {
    hex
  };

  BigUint::from_str_radix(hex, 16).unwrap()
}

#[cfg(test)]
mod tests {
  use super::*;
  use ff::Field;
  use halo2curves::secp256r1::Fp as Scalar;
  use num_bigint::RandBigInt;
  use ark_std::rand::thread_rng;
  
  #[test]
  pub fn test_conversion_util() {
    let mut rng = thread_rng();
    let x_bigint = rng.gen_biguint(248);
    let x_scalar = biguint_to_scalar::<Scalar>(&x_bigint);
    let x_bigint2 = scalar_to_biguint::<Scalar>(&x_scalar);

    assert!(x_bigint == x_bigint2);

    let x_scalar = Scalar::random(rng);
    let x_bigint = scalar_to_biguint::<Scalar>(&x_scalar);
    let x_scalar2 = biguint_to_scalar::<Scalar>(&x_bigint);
    assert!(x_scalar2 == x_scalar2);
  }

}