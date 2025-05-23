//! This module implements various elliptic curve gadgets
#![allow(non_snake_case)]
use crate::utils::{
  alloc_num_equals, alloc_one, alloc_zero, conditionally_select, conditionally_select2,
  select_num_or_one, select_num_or_zero, select_num_or_zero2, select_one_or_diff2,
  select_one_or_num2, select_zero_or_num2,
};
use bellpepper::gadgets::Assignment;
use bellpepper_core::{
  boolean::{AllocatedBit, Boolean},
  num::AllocatedNum,
  ConstraintSystem, SynthesisError,
};
use ff::{PrimeField, PrimeFieldBits};

/// `AllocatedPoint` provides an elliptic curve abstraction inside a circuit.
#[derive(Clone)]
pub struct AllocatedPoint<Scalar>
where
  Scalar: PrimeField,
{
  pub(crate) x: AllocatedNum<Scalar>,
  pub(crate) y: AllocatedNum<Scalar>,
  pub(crate) is_infinity: AllocatedNum<Scalar>,
}

impl<Scalar> AllocatedPoint<Scalar>
where
  Scalar: PrimeField + PrimeFieldBits,
{
  /// Allocates a new point on the curve using coordinates provided by
  /// `coords`. If coords = None, it allocates the default infinity point
  pub fn alloc<CS>(
    mut cs: CS,
    coords: Option<(Scalar, Scalar, bool)>,
  ) -> Result<Self, SynthesisError>
  where
    CS: ConstraintSystem<Scalar>,
  {
    let x = AllocatedNum::alloc(cs.namespace(|| "x"), || {
      Ok(coords.map_or(Scalar::ZERO, |c| c.0))
    })?;
    let y = AllocatedNum::alloc(cs.namespace(|| "y"), || {
      Ok(coords.map_or(Scalar::ZERO, |c| c.1))
    })?;
    let is_infinity = AllocatedNum::alloc(cs.namespace(|| "is_infinity"), || {
      Ok(if coords.is_none_or(|c| c.2) {
        Scalar::ONE
      } else {
        Scalar::ZERO
      })
    })?;
    cs.enforce(
      || "is_infinity is bit",
      |lc| lc + is_infinity.get_variable(),
      |lc| lc + CS::one() - is_infinity.get_variable(),
      |lc| lc,
    );

    Ok(AllocatedPoint { x, y, is_infinity })
  }

  pub fn inputize<CS: ConstraintSystem<Scalar>>(&self, mut cs: CS) -> Result<(), SynthesisError> {
    self.x.inputize(cs.namespace(|| "x"))?;
    self.y.inputize(cs.namespace(|| "y"))?;
    self.is_infinity.inputize(cs.namespace(|| "is_infinity"))?;
    Ok(())
  }

  /// Allocates a default point on the curve.
  pub fn default<CS>(mut cs: CS) -> Result<Self, SynthesisError>
  where
    CS: ConstraintSystem<Scalar>,
  {
    let zero = alloc_zero(cs.namespace(|| "zero"))?;
    let one = alloc_one(cs.namespace(|| "one"))?;

    Ok(AllocatedPoint {
      x: zero.clone(),
      y: zero,
      is_infinity: one,
    })
  }

  #[allow(unused)]
  /// Returns coordinates associated with the point.
  pub const fn get_coordinates(
    &self,
  ) -> (
    &AllocatedNum<Scalar>,
    &AllocatedNum<Scalar>,
    &AllocatedNum<Scalar>,
  ) {
    (&self.x, &self.y, &self.is_infinity)
  }

  /// Negates the provided point
  pub fn negate<CS: ConstraintSystem<Scalar>>(&self, mut cs: CS) -> Result<Self, SynthesisError> {
    let y = AllocatedNum::alloc(cs.namespace(|| "y"), || Ok(-*self.y.get_value().get()?))?;

    cs.enforce(
      || "check y = - self.y",
      |lc| lc + self.y.get_variable(),
      |lc| lc + CS::one(),
      |lc| lc - y.get_variable(),
    );

    Ok(Self {
      x: self.x.clone(),
      y,
      is_infinity: self.is_infinity.clone(),
    })
  }

  /// Add two points (may be equal)
  pub fn add<CS: ConstraintSystem<Scalar>>(
    &self,
    mut cs: CS,
    other: &AllocatedPoint<Scalar>,
  ) -> Result<Self, SynthesisError> {
    // Compute boolean equal indicating if self = other

    let equal_x = alloc_num_equals(
      cs.namespace(|| "check self.x == other.x"),
      &self.x,
      &other.x,
    )?;

    let equal_y = alloc_num_equals(
      cs.namespace(|| "check self.y == other.y"),
      &self.y,
      &other.y,
    )?;

    // Compute the result of the addition and the result of double self
    let result_from_add = self.add_internal(cs.namespace(|| "add internal"), other, &equal_x)?;
    let result_from_double = self.double(cs.namespace(|| "double"))?;

    // Output:
    // If (self == other) {
    //  return double(self)
    // }else {
    //  if (self.x == other.x){
    //      return infinity [negation]
    //  } else {
    //      return add(self, other)
    //  }
    // }
    let result_for_equal_x = AllocatedPoint::select_point_or_infinity(
      cs.namespace(|| "equal_y ? result_from_double : infinity"),
      &result_from_double,
      &Boolean::from(equal_y),
    )?;

    AllocatedPoint::conditionally_select(
      cs.namespace(|| "equal ? result_from_double : result_from_add"),
      &result_for_equal_x,
      &result_from_add,
      &Boolean::from(equal_x),
    )
  }

  /// Adds other point to this point and returns the result. Assumes that the
  /// two points are different and that both `other.is_infinity` and
  /// `this.is_infinty` are bits
  pub fn add_internal<CS: ConstraintSystem<Scalar>>(
    &self,
    mut cs: CS,
    other: &AllocatedPoint<Scalar>,
    equal_x: &AllocatedBit,
  ) -> Result<Self, SynthesisError> {
    //************************************************************************/
    // lambda = (other.y - self.y) * (other.x - self.x).invert().unwrap();
    //************************************************************************/
    // First compute (other.x - self.x).inverse()
    // If either self or other are the infinity point or self.x = other.x  then
    // compute bogus values Specifically,
    // x_diff = self != inf && other != inf && self.x == other.x ? (other.x -
    // self.x) : 1

    // Compute self.is_infinity OR other.is_infinity =
    // NOT(NOT(self.is_ifninity) AND NOT(other.is_infinity))
    let at_least_one_inf = AllocatedNum::alloc(cs.namespace(|| "at least one inf"), || {
      Ok(
        Scalar::ONE
          - (Scalar::ONE - *self.is_infinity.get_value().get()?)
            * (Scalar::ONE - *other.is_infinity.get_value().get()?),
      )
    })?;
    cs.enforce(
      || "1 - at least one inf = (1-self.is_infinity) * (1-other.is_infinity)",
      |lc| lc + CS::one() - self.is_infinity.get_variable(),
      |lc| lc + CS::one() - other.is_infinity.get_variable(),
      |lc| lc + CS::one() - at_least_one_inf.get_variable(),
    );

    // Now compute x_diff_is_actual = at_least_one_inf OR equal_x
    let x_diff_is_actual =
      AllocatedNum::alloc(cs.namespace(|| "allocate x_diff_is_actual"), || {
        Ok(if *equal_x.get_value().get()? {
          Scalar::ONE
        } else {
          *at_least_one_inf.get_value().get()?
        })
      })?;
    cs.enforce(
      || "1 - x_diff_is_actual = (1-equal_x) * (1-at_least_one_inf)",
      |lc| lc + CS::one() - at_least_one_inf.get_variable(),
      |lc| lc + CS::one() - equal_x.get_variable(),
      |lc| lc + CS::one() - x_diff_is_actual.get_variable(),
    );

    // x_diff = 1 if either self.is_infinity or other.is_infinity or self.x =
    // other.x else self.x - other.x
    let x_diff = select_one_or_diff2(
      cs.namespace(|| "Compute x_diff"),
      &other.x,
      &self.x,
      &x_diff_is_actual,
    )?;

    let lambda = AllocatedNum::alloc(cs.namespace(|| "lambda"), || {
      let x_diff_inv = if *x_diff_is_actual.get_value().get()? == Scalar::ONE {
        // Set to default
        Scalar::ONE
      } else {
        // Set to the actual inverse
        (*other.x.get_value().get()? - *self.x.get_value().get()?)
          .invert()
          .unwrap()
      };

      Ok((*other.y.get_value().get()? - *self.y.get_value().get()?) * x_diff_inv)
    })?;
    cs.enforce(
      || "Check that lambda is correct",
      |lc| lc + lambda.get_variable(),
      |lc| lc + x_diff.get_variable(),
      |lc| lc + other.y.get_variable() - self.y.get_variable(),
    );

    //************************************************************************/
    // x = lambda * lambda - self.x - other.x;
    //************************************************************************/
    let x = AllocatedNum::alloc(cs.namespace(|| "x"), || {
      Ok(
        *lambda.get_value().get()? * lambda.get_value().get()?
          - *self.x.get_value().get()?
          - *other.x.get_value().get()?,
      )
    })?;
    cs.enforce(
      || "check that x is correct",
      |lc| lc + lambda.get_variable(),
      |lc| lc + lambda.get_variable(),
      |lc| lc + x.get_variable() + self.x.get_variable() + other.x.get_variable(),
    );

    //************************************************************************/
    // y = lambda * (self.x - x) - self.y;
    //************************************************************************/
    let y = AllocatedNum::alloc(cs.namespace(|| "y"), || {
      Ok(
        *lambda.get_value().get()? * (*self.x.get_value().get()? - *x.get_value().get()?)
          - *self.y.get_value().get()?,
      )
    })?;

    cs.enforce(
      || "Check that y is correct",
      |lc| lc + lambda.get_variable(),
      |lc| lc + self.x.get_variable() - x.get_variable(),
      |lc| lc + y.get_variable() + self.y.get_variable(),
    );

    //************************************************************************/
    // We only return the computed x, y if neither of the points is infinity
    // and self.x != other.y if self.is_infinity return other.clone()
    // elif other.is_infinity return self.clone()
    // elif self.x == other.x return infinity
    // Otherwise return the computed points.
    //************************************************************************/
    // Now compute the output x

    let x1 = conditionally_select2(
      cs.namespace(|| "x1 = other.is_infinity ? self.x : x"),
      &self.x,
      &x,
      &other.is_infinity,
    )?;

    let x = conditionally_select2(
      cs.namespace(|| "x = self.is_infinity ? other.x : x1"),
      &other.x,
      &x1,
      &self.is_infinity,
    )?;

    let y1 = conditionally_select2(
      cs.namespace(|| "y1 = other.is_infinity ? self.y : y"),
      &self.y,
      &y,
      &other.is_infinity,
    )?;

    let y = conditionally_select2(
      cs.namespace(|| "y = self.is_infinity ? other.y : y1"),
      &other.y,
      &y1,
      &self.is_infinity,
    )?;

    let is_infinity1 = select_num_or_zero2(
      cs.namespace(|| "is_infinity1 = other.is_infinity ? self.is_infinity : 0"),
      &self.is_infinity,
      &other.is_infinity,
    )?;

    let is_infinity = conditionally_select2(
      cs.namespace(|| "is_infinity = self.is_infinity ? other.is_infinity : is_infinity1"),
      &other.is_infinity,
      &is_infinity1,
      &self.is_infinity,
    )?;

    Ok(Self { x, y, is_infinity })
  }


  /// Doubles the supplied point.
  pub fn double<CS: ConstraintSystem<Scalar>>(&self, mut cs: CS) -> Result<Self, SynthesisError> {
    //*************************************************************/
    // Compute lambda = (3x^2 + a) / 2y
    /************************************************************ */

    // Compute denom = 2*y ? self != inf : 1
    let denom_actual = AllocatedNum::alloc(cs.namespace(|| "denom_actual"), || {
      Ok(*self.y.get_value().get()? + *self.y.get_value().get()?)
    })?;
    cs.enforce(
      || "check denom_actual",
      |lc| lc + CS::one() + CS::one(),
      |lc| lc + self.y.get_variable(),
      |lc| lc + denom_actual.get_variable(),
    );
    let denom = select_one_or_num2(cs.namespace(|| "denom"), &denom_actual, &self.is_infinity)?;

    // Compute `numerator = x^2 + a`,  ASSUMES A = -3 (True for P256r1)
    let numerator = AllocatedNum::alloc(cs.namespace(|| "alloc numerator"), || {
      Ok(Scalar::from(3) * self.x.get_value().get()? * self.x.get_value().get()? - Scalar::from(3))
    })?;
    cs.enforce(
      || "Check numerator",
      |lc| lc + (Scalar::from(3), self.x.get_variable()),
      |lc| lc + self.x.get_variable(),
      |lc| lc + numerator.get_variable() + CS::one() + CS::one() + CS::one(), 
    );

    let lambda = AllocatedNum::alloc(cs.namespace(|| "alloc lambda"), || {
      let tmp_inv = if *self.is_infinity.get_value().get()? == Scalar::ONE {
        // Return default value 1
        Scalar::ONE
      } else {
        // Return the actual inverse
        (*denom.get_value().get()?).invert().unwrap()
      };
      Ok(tmp_inv * *numerator.get_value().get()?)
    })?;

    cs.enforce(
      || "Check lambda",
      |lc| lc + denom.get_variable(),
      |lc| lc + lambda.get_variable(),
      |lc| lc + numerator.get_variable(),
    );

    /************************************************************ */
    //          x = lambda * lambda - self.x - self.x;
    /************************************************************ */

    let x = AllocatedNum::alloc(cs.namespace(|| "x"), || {
      Ok(
        ((*lambda.get_value().get()?) * (*lambda.get_value().get()?))
          - *self.x.get_value().get()?
          - self.x.get_value().get()?,
      )
    })?;
    cs.enforce(
      || "Check x",
      |lc| lc + lambda.get_variable(),
      |lc| lc + lambda.get_variable(),
      |lc| lc + x.get_variable() + self.x.get_variable() + self.x.get_variable(),
    );

    /************************************************************ */
    //        y = lambda * (self.x - x) - self.y;
    /************************************************************ */

    let y = AllocatedNum::alloc(cs.namespace(|| "y"), || {
      Ok(
        (*lambda.get_value().get()?) * (*self.x.get_value().get()? - x.get_value().get()?)
          - self.y.get_value().get()?,
      )
    })?;
    cs.enforce(
      || "Check y",
      |lc| lc + lambda.get_variable(),
      |lc| lc + self.x.get_variable() - x.get_variable(),
      |lc| lc + y.get_variable() + self.y.get_variable(),
    );

    /************************************************************ */
    // Only return the computed x and y if the point is not infinity
    /************************************************************ */

    // x
    let x = select_zero_or_num2(cs.namespace(|| "final x"), &x, &self.is_infinity)?;

    // y
    let y = select_zero_or_num2(cs.namespace(|| "final y"), &y, &self.is_infinity)?;

    // is_infinity
    let is_infinity = self.is_infinity.clone();

    Ok(Self { x, y, is_infinity })
  }

  /// A gadget for scalar multiplication, optimized to use incomplete addition
  /// law. The optimization here is analogous to <https://github.com/arkworks-rs/r1cs-std/blob/6d64f379a27011b3629cf4c9cb38b7b7b695d5a0/src/groups/curves/short_weierstrass/mod.rs#L295>,
  /// except we use complete addition law over affine coordinates instead of
  /// projective coordinates for the tail bits
  pub fn scalar_mul<CS: ConstraintSystem<Scalar>>(
    &self,
    mut cs: CS,
    s: &AllocatedNum<Scalar>,
  ) -> Result<Self, SynthesisError> {
    let scalar_bits = s.to_bits_le(cs.namespace(|| "scalar_bits"))?;

    let split_len = core::cmp::min(scalar_bits.len(), (Scalar::NUM_BITS - 2) as usize);
    let (incomplete_bits, complete_bits) = scalar_bits.split_at(split_len);

    // we convert AllocatedPoint into AllocatedPointNonInfinity; we deal with
    // the case where self.is_infinity = 1 below
    let mut p = AllocatedPointNonInfinity::from_allocated_point(self);

    // we assume the first bit to be 1, so we must initialize acc to self and
    // double it we remove this assumption below
    let mut acc = p;
    p = acc.double_incomplete(cs.namespace(|| "double"))?;

    // perform the double-and-add loop to compute the scalar mul using
    // incomplete addition law
    for (i, bit) in incomplete_bits.iter().enumerate().skip(1) {
      let temp = acc.add_incomplete(cs.namespace(|| format!("add {i}")), &p)?;
      acc = AllocatedPointNonInfinity::conditionally_select(
        cs.namespace(|| format!("acc_iteration_{i}")),
        &temp,
        &acc,
        &bit.clone(),
      )?;

      p = p.double_incomplete(cs.namespace(|| format!("double {i}")))?;
    }

    // convert back to AllocatedPoint
    let res = {
      // we set acc.is_infinity = self.is_infinity
      let acc = acc.to_allocated_point(&self.is_infinity)?;

      // we remove the initial slack if bits[0] is as not as assumed (i.e., it
      // is not 1)
      let acc_minus_initial = {
        let neg = self.negate(cs.namespace(|| "negate"))?;
        acc.add(cs.namespace(|| "res minus self"), &neg)
      }?;

      AllocatedPoint::conditionally_select(
        cs.namespace(|| "remove slack if necessary"),
        &acc,
        &acc_minus_initial,
        &scalar_bits[0].clone(),
      )?
    };

    // when self.is_infinity = 1, return the default point, else return res
    // we already set res.is_infinity to be self.is_infinity, so we do not need
    // to set it here
    let default = Self::default(cs.namespace(|| "default"))?;
    let x = conditionally_select2(
      cs.namespace(|| "check if self.is_infinity is zero (x)"),
      &default.x,
      &res.x,
      &self.is_infinity,
    )?;

    let y = conditionally_select2(
      cs.namespace(|| "check if self.is_infinity is zero (y)"),
      &default.y,
      &res.y,
      &self.is_infinity,
    )?;

    // we now perform the remaining scalar mul using complete addition law
    let mut acc = AllocatedPoint {
      x,
      y,
      is_infinity: res.is_infinity,
    };
    let mut p_complete = p.to_allocated_point(&self.is_infinity)?;

    for (i, bit) in complete_bits.iter().enumerate() {
      let temp = acc.add(cs.namespace(|| format!("add_complete {i}")), &p_complete)?;
      acc = AllocatedPoint::conditionally_select(
        cs.namespace(|| format!("acc_complete_iteration_{i}")),
        &temp,
        &acc,
        &bit.clone(),
      )?;

      p_complete = p_complete.double(cs.namespace(|| format!("double_complete {i}")))?;
    }

    Ok(acc)
  }

  /// If condition outputs a otherwise outputs b
  pub fn conditionally_select<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    a: &Self,
    b: &Self,
    condition: &Boolean,
  ) -> Result<Self, SynthesisError> {
    let x = conditionally_select(cs.namespace(|| "select x"), &a.x, &b.x, condition)?;

    let y = conditionally_select(cs.namespace(|| "select y"), &a.y, &b.y, condition)?;

    let is_infinity = conditionally_select(
      cs.namespace(|| "select is_infinity"),
      &a.is_infinity,
      &b.is_infinity,
      condition,
    )?;

    Ok(Self { x, y, is_infinity })
  }

  /// If condition outputs a otherwise infinity
  pub fn select_point_or_infinity<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    a: &Self,
    condition: &Boolean,
  ) -> Result<Self, SynthesisError> {
    let x = select_num_or_zero(cs.namespace(|| "select x"), &a.x, condition)?;

    let y = select_num_or_zero(cs.namespace(|| "select y"), &a.y, condition)?;

    let is_infinity = select_num_or_one(
      cs.namespace(|| "select is_infinity"),
      &a.is_infinity,
      condition,
    )?;

    Ok(Self { x, y, is_infinity })
  }

  /// Compare two points and constrain them to be equal
  #[allow(dead_code)]
  pub fn enforce_equal<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    point1: &AllocatedPoint<Scalar>,
    point2: &AllocatedPoint<Scalar>,
  ) -> Result<(), SynthesisError> {

    // Ensure x are the same
    cs.enforce(
      || "check point1.x == point2.x",
      |lc| lc + point1.x.get_variable(),
      |lc| lc + CS::one(),
      |lc| lc + point2.x.get_variable(),
    );
    // Ensure y are the same
    cs.enforce(
      || "check point1.y == point2.y",
      |lc| lc + point1.y.get_variable(),
      |lc| lc + CS::one(),
      |lc| lc + point2.y.get_variable(),
    );    

    Ok(())
  }

}

#[derive(Clone)]
/// `AllocatedPoint` but one that is guaranteed to be not infinity
pub struct AllocatedPointNonInfinity<Scalar>
where
  Scalar: PrimeField,
{
  x: AllocatedNum<Scalar>,
  y: AllocatedNum<Scalar>,
}

impl<Scalar: PrimeField + PrimeFieldBits> AllocatedPointNonInfinity<Scalar> {
  #[allow(unused)]
  /// Creates a new `AllocatedPointNonInfinity` from the specified coordinates
  pub const fn new(x: AllocatedNum<Scalar>, y: AllocatedNum<Scalar>) -> Self {
    Self { x, y }
  }

  #[allow(unused)]
  /// Allocates a new point on the curve using coordinates provided by
  /// `coords`.
  pub fn alloc<CS>(mut cs: CS, coords: Option<(Scalar, Scalar)>) -> Result<Self, SynthesisError>
  where
    CS: ConstraintSystem<Scalar>,
  {
    let x = AllocatedNum::alloc(cs.namespace(|| "x"), || {
      coords.map_or(Err(SynthesisError::AssignmentMissing), |c| Ok(c.0))
    })?;
    let y = AllocatedNum::alloc(cs.namespace(|| "y"), || {
      coords.map_or(Err(SynthesisError::AssignmentMissing), |c| Ok(c.1))
    })?;

    Ok(Self { x, y })
  }

  /// Turns an `AllocatedPoint` into an `AllocatedPointNonInfinity` (assumes it
  /// is not infinity)
  pub fn from_allocated_point(p: &AllocatedPoint<Scalar>) -> Self {
    Self {
      x: p.x.clone(),
      y: p.y.clone(),
    }
  }

  /// Returns an `AllocatedPoint` from an `AllocatedPointNonInfinity`
  pub fn to_allocated_point(
    &self,
    is_infinity: &AllocatedNum<Scalar>,
  ) -> Result<AllocatedPoint<Scalar>, SynthesisError> {
    Ok(AllocatedPoint {
      x: self.x.clone(),
      y: self.y.clone(),
      is_infinity: is_infinity.clone(),
    })
  }

  #[allow(unused)]
  /// Returns coordinates associated with the point.
  pub const fn get_coordinates(&self) -> (&AllocatedNum<Scalar>, &AllocatedNum<Scalar>) {
    (&self.x, &self.y)
  }

  /// Add two points assuming self != +/- other
  pub fn add_incomplete<CS>(&self, mut cs: CS, other: &Self) -> Result<Self, SynthesisError>
  where
    CS: ConstraintSystem<Scalar>,
  {
    // allocate a free variable that an honest prover sets to lambda =
    // (y2-y1)/(x2-x1)
    let lambda = AllocatedNum::alloc(cs.namespace(|| "lambda"), || {
      if *other.x.get_value().get()? == *self.x.get_value().get()? {
        Ok(Scalar::ONE)
      } else {
        Ok(
          (*other.y.get_value().get()? - *self.y.get_value().get()?)
            * (*other.x.get_value().get()? - *self.x.get_value().get()?)
              .invert()
              .unwrap(),
        )
      }
    })?;
    cs.enforce(
      || "Check that lambda is computed correctly",
      |lc| lc + lambda.get_variable(),
      |lc| lc + other.x.get_variable() - self.x.get_variable(),
      |lc| lc + other.y.get_variable() - self.y.get_variable(),
    );

    //************************************************************************/
    // x = lambda * lambda - self.x - other.x;
    //************************************************************************/
    let x = AllocatedNum::alloc(cs.namespace(|| "x"), || {
      Ok(
        *lambda.get_value().get()? * lambda.get_value().get()?
          - *self.x.get_value().get()?
          - *other.x.get_value().get()?,
      )
    })?;
    cs.enforce(
      || "check that x is correct",
      |lc| lc + lambda.get_variable(),
      |lc| lc + lambda.get_variable(),
      |lc| lc + x.get_variable() + self.x.get_variable() + other.x.get_variable(),
    );

    //************************************************************************/
    // y = lambda * (self.x - x) - self.y;
    //************************************************************************/
    let y = AllocatedNum::alloc(cs.namespace(|| "y"), || {
      Ok(
        *lambda.get_value().get()? * (*self.x.get_value().get()? - *x.get_value().get()?)
          - *self.y.get_value().get()?,
      )
    })?;

    cs.enforce(
      || "Check that y is correct",
      |lc| lc + lambda.get_variable(),
      |lc| lc + self.x.get_variable() - x.get_variable(),
      |lc| lc + y.get_variable() + self.y.get_variable(),
    );

    Ok(Self { x, y })
  }

  /// doubles the point; since this is called with a point not at infinity, it
  /// is guaranteed to be not infinity
  pub fn double_incomplete<CS>(&self, mut cs: CS) -> Result<Self, SynthesisError>
  where
    CS: ConstraintSystem<Scalar>,
  {
    // ASSUMES A = -3
    // lambda = (3 x^2 + a) / 2 * y

    let x_sq = self.x.square(cs.namespace(|| "x_sq"))?;

    let lambda = AllocatedNum::alloc(cs.namespace(|| "lambda"), || {
      let n = Scalar::from(3) * x_sq.get_value().get()? - Scalar::from(3);
      let d = Scalar::from(2) * *self.y.get_value().get()?;
      if d == Scalar::ZERO {
        Ok(Scalar::ONE)
      } else {
        Ok(n * d.invert().unwrap())
      }
    })?;
    cs.enforce(
      || "Check that lambda is computed correctly",
      |lc| lc + lambda.get_variable(),
      |lc| lc + (Scalar::from(2), self.y.get_variable()),
      |lc| lc - CS::one() - CS::one() - CS::one() + (Scalar::from(3), x_sq.get_variable()),
    );

    let x = AllocatedNum::alloc(cs.namespace(|| "x"), || {
      Ok(
        *lambda.get_value().get()? * *lambda.get_value().get()?
          - *self.x.get_value().get()?
          - *self.x.get_value().get()?,
      )
    })?;

    cs.enforce(
      || "check that x is correct",
      |lc| lc + lambda.get_variable(),
      |lc| lc + lambda.get_variable(),
      |lc| lc + x.get_variable() + (Scalar::from(2), self.x.get_variable()),
    );

    let y = AllocatedNum::alloc(cs.namespace(|| "y"), || {
      Ok(
        *lambda.get_value().get()? * (*self.x.get_value().get()? - *x.get_value().get()?)
          - *self.y.get_value().get()?,
      )
    })?;

    cs.enforce(
      || "Check that y is correct",
      |lc| lc + lambda.get_variable(),
      |lc| lc + self.x.get_variable() - x.get_variable(),
      |lc| lc + y.get_variable() + self.y.get_variable(),
    );

    Ok(Self { x, y })
  }

  /// If condition outputs a otherwise outputs b
  pub fn conditionally_select<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    a: &Self,
    b: &Self,
    condition: &Boolean,
  ) -> Result<Self, SynthesisError> {
    let x = conditionally_select(cs.namespace(|| "select x"), &a.x, &b.x, condition)?;
    let y = conditionally_select(cs.namespace(|| "select y"), &a.y, &b.y, condition)?;

    Ok(Self { x, y })
  }

}
