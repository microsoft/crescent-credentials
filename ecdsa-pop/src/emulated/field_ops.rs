use std::{
    fmt::Debug,
    marker::PhantomData,
    ops::{Rem, Shl},
};

use bellpepper_core::boolean::{AllocatedBit, Boolean};
use bellpepper_core::num::{AllocatedNum, Num};
use bellpepper_core::{ConstraintSystem, LinearCombination, SynthesisError};
use ff::PrimeFieldBits;
use num_bigint::BigInt;
use num_traits::One;

use crate::emulated::field_element::{EmulatedFieldElement, EmulatedFieldParams, EmulatedLimbs};
use crate::emulated::util::{bigint_to_scalar, decompose, recompose};

#[derive(Debug, Clone)]
pub enum Optype {
    Add,
    Sub,
    Mul,
}

#[derive(Clone)]
pub struct OverflowError {
    op: Optype,
    next_overflow: usize,
    reduce_right: bool,
}

impl Debug for OverflowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OverflowError")
            .field("op", &self.op)
            .field("next_overflow", &self.next_overflow)
            .field("reduce_right", &self.reduce_right)
            .finish()
    }
}

impl<F, P> EmulatedFieldElement<F, P>
where
    F: PrimeFieldBits,
    P: EmulatedFieldParams,
{
    fn compact(
        a: &Self,
        b: &Self,
    ) -> Result<(EmulatedLimbs<F>, EmulatedLimbs<F>, usize), SynthesisError> {
        let max_overflow = a.overflow.max(b.overflow);
        // Substract one bit to account for overflow due to grouping in compact_limbs
        let max_num_bits = F::CAPACITY as usize - 1 - max_overflow;
        let group_size = max_num_bits / P::bits_per_limb();

        if group_size == 0 {
            // No space for compacting
            return Ok((a.limbs.clone(), b.limbs.clone(), P::bits_per_limb()));
        }

        let new_bits_per_limb = P::bits_per_limb() * group_size;
        let a_compact = a.compact_limbs(group_size, new_bits_per_limb)?;
        let b_compact = b.compact_limbs(group_size, new_bits_per_limb)?;

        Ok((a_compact, b_compact, new_bits_per_limb))
    }

    /// Asserts that two allocated limbs vectors represent the same integer value.
    /// This is a costly operation as it performs bit decomposition of the limbs.
    fn assert_limbs_equality_slow<CS>(
        cs: &mut CS,
        a: &EmulatedLimbs<F>,
        b: &EmulatedLimbs<F>,
        num_bits_per_limb: usize,
        num_carry_bits: usize,
    ) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<F>,
    {
        if let (EmulatedLimbs::Allocated(a_l), EmulatedLimbs::Allocated(b_l)) = (a, b) {
            let num_limbs = a_l.len().max(b_l.len());
            let max_value =
                bigint_to_scalar::<F>(&BigInt::one().shl(num_bits_per_limb + num_carry_bits));
            let max_value_shift = bigint_to_scalar::<F>(&BigInt::one().shl(num_carry_bits));

            let mut carry = Num::<F>::zero();
            for i in 0..num_limbs {
                let mut diff_num = carry.add(&Num::<F>::zero().add_bool_with_coeff(
                    CS::one(),
                    &Boolean::Constant(true),
                    max_value,
                ));
                if i < a_l.len() {
                    diff_num = diff_num.add(&a_l[i]);
                }
                if i < b_l.len() {
                    let mut neg_bl = b_l[i].clone();
                    neg_bl = neg_bl.scale(-F::ONE);
                    diff_num = diff_num.add(&neg_bl);
                }
                if i > 0 {
                    diff_num = diff_num.add_bool_with_coeff(
                        CS::one(),
                        &Boolean::Constant(true),
                        -max_value_shift,
                    );
                }

                carry = Self::right_shift(
                    &mut cs.namespace(|| format!("right shift to get carry {i}")),
                    &diff_num,
                    num_bits_per_limb,
                    num_bits_per_limb + num_carry_bits + 1,
                )?;
            }

            // Check that the final carry equals max_value_shift
            cs.enforce(
                || "enforce equality between final carry and max_value_shift",
                |lc| lc,
                |lc| lc,
                |lc| {
                    lc + &carry
                        .clone()
                        .add_bool_with_coeff(CS::one(), &Boolean::Constant(true), -max_value_shift)
                        .lc(F::ONE)
                },
            );
        } else {
            eprintln!("Both inputs must be allocated limbs, not constants");
            return Err(SynthesisError::Unsatisfiable);
        }
        Ok(())
    }

    fn right_shift<CS>(
        cs: &mut CS,
        v: &Num<F>,
        start_digit: usize,
        end_digit: usize,
    ) -> Result<Num<F>, SynthesisError>
    where
        CS: ConstraintSystem<F>,
    {
        let v_bits = if let Some(v_value) = v.get_value() {
            v_value
                .to_le_bits()
                .into_iter()
                .skip(start_digit)
                .take(end_digit - start_digit)
                .map(Some)
                .collect()
        } else {
            vec![None; end_digit - start_digit]
        };

        let v_booleans = v_bits.into_iter().enumerate().map(|(i, b)| {
            Ok::<Boolean, SynthesisError>(Boolean::from(AllocatedBit::alloc(
                cs.namespace(|| format!("allocate bit {i}")),
                b,
            )?))
        });

        let mut sum_higher_order_bits = Num::<F>::zero();
        let mut sum_shifted_bits = Num::<F>::zero();
        let mut coeff = bigint_to_scalar::<F>(&(BigInt::one() << start_digit));
        let mut coeff_shifted = F::ONE;

        for b in v_booleans {
            let b = b?;
            sum_higher_order_bits = sum_higher_order_bits.add_bool_with_coeff(CS::one(), &b, coeff);
            sum_shifted_bits = sum_shifted_bits.add_bool_with_coeff(CS::one(), &b, coeff_shifted);
            coeff_shifted = coeff_shifted.double();
            coeff = coeff.double();
        }

        cs.enforce(
            || "enforce equality between input value and weighted sum of higher order bits",
            |lc| lc,
            |lc| lc,
            |lc| lc + &v.lc(F::ONE) - &sum_higher_order_bits.lc(F::ONE),
        );

        Ok(sum_shifted_bits)
    }

    /// Asserts that the limbs represent the same integer value.
    /// For constant inputs, it ensures that the values are equal modulo the field order.
    /// For allocated inputs, it does not ensure that the values are equal modulo the field order.
    fn assert_limbs_equality<CS>(cs: &mut CS, a: &Self, b: &Self) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<F>,
    {
        a.enforce_width_conditional(&mut cs.namespace(|| "ensure bitwidths in a"))?;
        b.enforce_width_conditional(&mut cs.namespace(|| "ensure bitwidths in b"))?;

        if a.is_constant() && b.is_constant() {
            let a_i = BigInt::try_from(a)?;
            let b_i = BigInt::try_from(b)?;
            let a_r = a_i.rem(P::modulus());
            let b_r = b_i.rem(P::modulus());
            if a_r != b_r {
                eprintln!("Constant values are not equal");
                return Err(SynthesisError::Unsatisfiable);
            }
        }
        let (a_c, b_c, bits_per_limb) = Self::compact(a, b)?;

        if a.overflow > b.overflow {
            Self::assert_limbs_equality_slow(
                &mut cs.namespace(|| "check limbs equality"),
                &a_c,
                &b_c,
                bits_per_limb,
                a.overflow,
            )?;
        } else {
            Self::assert_limbs_equality_slow(
                &mut cs.namespace(|| "check limbs equality"),
                &b_c,
                &a_c,
                bits_per_limb,
                b.overflow,
            )?;
        }

        Ok(())
    }

    /// Asserts that the limbs represent the same integer value modulo the modulus.
    pub fn assert_is_equal<CS>(cs: &mut CS, a: &Self, b: &Self) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<F>,
    {
        if a.is_constant() && b.is_constant() {
            let a_i = BigInt::try_from(a)?;
            let b_i = BigInt::try_from(b)?;
            let a_r = a_i.rem(P::modulus());
            let b_r = b_i.rem(P::modulus());
            if a_r != b_r {
                eprintln!("Constant values are not equal");
                return Err(SynthesisError::Unsatisfiable);
            } else {
                return Ok(());
            }
        }

        let diff = a.sub(&mut cs.namespace(|| "a-b"), b)?;
        let k = diff.compute_quotient(&mut cs.namespace(|| "quotient when divided by modulus"))?;

        let kp = Self::reduce_and_apply_op(
            &mut cs.namespace(|| "computing product of quotient and modulus"),
            &Optype::Mul,
            &k,
            &Self::modulus(),
        )?;

        Self::assert_limbs_equality(cs, &diff, &kp)?;

        Ok(())
    }

    /// Asserts that the limbs of an allocated `EmulatedFieldElement` limbs equal the
    /// limbs of a specific constant `EmulatedFieldElement`.
    ///
    /// This methods uses fewer constraints (equal to limb count) than the general
    /// `assert_is_equal`. It is useful for checking equality with constants like
    /// 0 or 1 (which constitute the coordinates of the identity in ed25519).
    pub fn assert_equality_to_constant<CS>(
        &self,
        cs: &mut CS,
        constant: &Self,
    ) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<F>,
    {
        if self.is_constant() || !constant.is_constant() {
            eprintln!(
                "Method should be called on a non-constant field element with a constant argument"
            );
            return Err(SynthesisError::Unsatisfiable);
        }

        match (&self.limbs, &constant.limbs) {
            (EmulatedLimbs::Allocated(var_limbs), EmulatedLimbs::Constant(const_limbs)) => {
                if var_limbs.len() != const_limbs.len() {
                    eprintln!(
                        "Limb counts do not match: {} != {}",
                        var_limbs.len(),
                        const_limbs.len()
                    );
                    return Err(SynthesisError::Unsatisfiable);
                }

                for i in 0..var_limbs.len() {
                    cs.enforce(
                        || format!("checking equality of limb {i}"),
                        |lc| lc,
                        |lc| lc,
                        |lc| lc + &var_limbs[i].lc(F::ONE) - (const_limbs[i], CS::one()),
                    );
                }
            }
            _ => panic!("Unreachable code reached"),
        }

        Ok(())
    }

    pub fn reduce<CS>(&self, cs: &mut CS) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<F>,
    {
        assert!(self.overflow + 2 <= Self::max_overflow(),
                "Not enough bits in native field to accomodate a subtraction operation which is performed during reduce: {} > {}",
                self.overflow + 2,
                Self::max_overflow(),
            );

        self.enforce_width_conditional(&mut cs.namespace(|| "ensure bitwidths in input"))?;
        if self.overflow == 0 {
            return Ok(self.clone());
        }

        if self.is_constant() {
            eprintln!("Trying to reduce a constant with overflow flag set; should not happen");
            return Err(SynthesisError::Unsatisfiable);
        }

        let r = self.compute_rem(&mut cs.namespace(|| "remainder modulo field modulus"))?;
        Self::assert_is_equal(&mut cs.namespace(|| "check equality"), &r, self)?;
        Ok(r)
    }

    fn add_precondition(a: &Self, b: &Self) -> Result<usize, OverflowError> {
        let reduce_right = a.overflow < b.overflow;
        let next_overflow = a.overflow.max(b.overflow) + 1;

        if next_overflow > Self::max_overflow() {
            Err(OverflowError {
                op: Optype::Add,
                next_overflow,
                reduce_right,
            })
        } else {
            Ok(next_overflow)
        }
    }

    fn add_op<CS>(a: &Self, b: &Self, next_overflow: usize) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<F>,
    {
        if a.is_constant() && b.is_constant() {
            let a_int = BigInt::try_from(a)?;
            let b_int = BigInt::try_from(b)?;
            let res_int = (a_int + b_int).rem(P::modulus());
            return Ok(Self::from(&res_int));
        }

        let num_res_limbs = a.len().max(b.len());
        let mut res: Vec<Num<F>> = vec![Num::<F>::zero(); num_res_limbs];

        match (a.limbs.clone(), b.limbs.clone()) {
            (EmulatedLimbs::Constant(const_limbs), EmulatedLimbs::Allocated(var_limbs))
            | (EmulatedLimbs::Allocated(var_limbs), EmulatedLimbs::Constant(const_limbs)) => {
                for i in 0..num_res_limbs {
                    if i < var_limbs.len() {
                        res[i] = var_limbs[i].clone();
                    }
                    if i < const_limbs.len() {
                        res[i] = res[i].clone().add_bool_with_coeff(
                            CS::one(),
                            &Boolean::Constant(true),
                            const_limbs[i],
                        );
                    }
                }
            }
            (EmulatedLimbs::Allocated(a_var), EmulatedLimbs::Allocated(b_var)) => {
                for i in 0..num_res_limbs {
                    if i < a_var.len() {
                        res[i] = a_var[i].clone();
                    }
                    if i < b_var.len() {
                        res[i] = res[i].clone().add(&b_var[i]);
                    }
                }
            }
            (EmulatedLimbs::Constant(_), EmulatedLimbs::Constant(_)) => {
                panic!("Constant limb case has already been handled")
            }
        }

        Ok(Self::new_internal_element(
            EmulatedLimbs::Allocated(res),
            next_overflow,
        ))
    }

    pub fn add<CS>(&self, cs: &mut CS, other: &Self) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<F>,
    {
        Self::reduce_and_apply_op(
            &mut cs.namespace(|| "compute a + b"),
            &Optype::Add,
            self,
            other,
        )
    }

    fn sub_precondition(a: &Self, b: &Self) -> Result<usize, OverflowError> {
        let reduce_right = a.overflow < b.overflow;
        let next_overflow = a.overflow.max(b.overflow + 2);

        if next_overflow > Self::max_overflow() {
            Err(OverflowError {
                op: Optype::Sub,
                next_overflow,
                reduce_right,
            })
        } else {
            Ok(next_overflow)
        }
    }

    /// Returns a k*P::modulus() for some k as a [EmulatedFieldElement]
    ///
    /// Underflow may occur when computing a - b. Let d = [d[0], d[1], ...] be the padding.
    /// If d is a multiple of P::modulus() that is greater than b, then
    /// (a[0]+d[0]-b[0], a[1]+d[1]-b[1],...) will not underflow
    fn sub_padding(overflow: usize, limb_count: usize) -> Result<Vec<F>, SynthesisError> {
        let tmp = BigInt::one() << (overflow + P::bits_per_limb());
        let upper_bound_limbs = vec![tmp; limb_count];

        let p = P::modulus();
        let mut padding_int_delta = recompose(&upper_bound_limbs, P::bits_per_limb())?;
        padding_int_delta = padding_int_delta.rem(&p);
        padding_int_delta = p - padding_int_delta;

        let padding_delta = decompose(&padding_int_delta, P::bits_per_limb(), limb_count)?;

        let padding_limbs = upper_bound_limbs
            .into_iter()
            .zip(padding_delta)
            .map(|(a, b)| bigint_to_scalar(&(a + b)))
            .collect::<Vec<F>>();

        Ok(padding_limbs)
    }

    fn sub_op<CS>(a: &Self, b: &Self, next_overflow: usize) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<F>,
    {
        if a.is_constant() && b.is_constant() {
            let a_int = BigInt::try_from(a)?;
            let b_int = BigInt::try_from(b)?;
            let res_int = if a_int >= b_int {
                (a_int - b_int).rem(P::modulus())
            } else {
                P::modulus() - (b_int - a_int).rem(P::modulus())
            };
            return Ok(Self::from(&res_int));
        }

        let num_res_limbs = a.len().max(b.len());
        let mut res: Vec<Num<F>> = vec![];
        let pad_limbs = Self::sub_padding(b.overflow, num_res_limbs)?;
        for limb in pad_limbs.into_iter() {
            res.push(Num::<F>::zero().add_bool_with_coeff(
                CS::one(),
                &Boolean::Constant(true),
                limb,
            ));
        }

        match (a.limbs.clone(), b.limbs.clone()) {
            (EmulatedLimbs::Allocated(a_var), EmulatedLimbs::Constant(b_const)) => {
                for i in 0..num_res_limbs {
                    if i < a_var.len() {
                        res[i] = res[i].clone().add(&a_var[i]);
                    }
                    if i < b_const.len() {
                        res[i] = res[i].clone().add_bool_with_coeff(
                            CS::one(),
                            &Boolean::Constant(true),
                            -b_const[i],
                        );
                    }
                }
            }
            (EmulatedLimbs::Constant(a_const), EmulatedLimbs::Allocated(b_var)) => {
                for i in 0..num_res_limbs {
                    if i < a_const.len() {
                        res[i] = res[i].clone().add_bool_with_coeff(
                            CS::one(),
                            &Boolean::Constant(true),
                            a_const[i],
                        );
                    }
                    if i < b_var.len() {
                        let mut neg_bl = b_var[i].clone();
                        neg_bl = neg_bl.scale(-F::ONE);
                        res[i] = res[i].clone().add(&neg_bl);
                    }
                }
            }
            (EmulatedLimbs::Allocated(a_var), EmulatedLimbs::Allocated(b_var)) => {
                for i in 0..num_res_limbs {
                    if i < a_var.len() {
                        res[i] = res[i].clone().add(&a_var[i]);
                    }
                    if i < b_var.len() {
                        let mut neg_bl = b_var[i].clone();
                        neg_bl = neg_bl.scale(-F::ONE);
                        res[i] = res[i].clone().add(&neg_bl);
                    }
                }
            }
            (EmulatedLimbs::Constant(_), EmulatedLimbs::Constant(_)) => {
                panic!("Constant limb case has already been handled")
            }
        }

        Ok(Self::new_internal_element(
            EmulatedLimbs::Allocated(res),
            next_overflow,
        ))
    }

    pub fn sub<CS>(&self, cs: &mut CS, other: &Self) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<F>,
    {
        Self::reduce_and_apply_op(
            &mut cs.namespace(|| "compute a - b"),
            &Optype::Sub,
            self,
            other,
        )
    }

    pub fn neg<CS>(&self, cs: &mut CS) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<F>,
    {
        let zero = Self::zero();
        zero.sub(&mut cs.namespace(|| "negate"), self)
    }

    fn mul_precondition(a: &Self, b: &Self) -> Result<usize, OverflowError> {
        assert!(
            2 * P::bits_per_limb() <= F::CAPACITY as usize,
            "Not enough bits in native field to accomodate a product of limbs: {} < {}",
            F::CAPACITY,
            2 * P::bits_per_limb(),
        );
        let reduce_right = a.overflow < b.overflow;
        let max_carry_bits = (a.len().min(b.len()) as f32).log2().ceil() as usize;
        let next_overflow = P::bits_per_limb() + a.overflow + b.overflow + max_carry_bits;

        if next_overflow > Self::max_overflow() {
            Err(OverflowError {
                op: Optype::Mul,
                next_overflow,
                reduce_right,
            })
        } else {
            Ok(next_overflow)
        }
    }

    fn mul_op<CS>(
        cs: &mut CS,
        a: &Self,
        b: &Self,
        next_overflow: usize,
    ) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<F>,
    {
        if a.is_constant() && b.is_constant() {
            let a_int = BigInt::try_from(a)?;
            let b_int = BigInt::try_from(b)?;
            let res_int = (a_int * b_int).rem(P::modulus());
            return Ok(Self::from(&res_int));
        }

        let num_prod_limbs = a.len() + b.len() - 1;
        let mut prod: Vec<Num<F>> = vec![Num::<F>::zero(); num_prod_limbs];

        match (a.limbs.clone(), b.limbs.clone()) {
            (EmulatedLimbs::Constant(const_limbs), EmulatedLimbs::Allocated(var_limbs))
            | (EmulatedLimbs::Allocated(var_limbs), EmulatedLimbs::Constant(const_limbs)) => {
                for i in 0..var_limbs.len() {
                    for j in 0..const_limbs.len() {
                        prod[i + j] = prod[i + j]
                            .clone()
                            .add(&var_limbs[i].clone().scale(const_limbs[j]));
                    }
                }
            }
            (EmulatedLimbs::Allocated(a_var), EmulatedLimbs::Allocated(b_var)) => {
                let a_var_limb_values: Option<Vec<F>> = a_var
                    .iter()
                    .map(|v| v.get_value().ok_or(SynthesisError::AssignmentMissing))
                    .collect::<Result<_, _>>()
                    .ok();
                let b_var_limb_values: Option<Vec<F>> = b_var
                    .iter()
                    .map(|v| v.get_value().ok_or(SynthesisError::AssignmentMissing))
                    .collect::<Result<_, _>>()
                    .ok();
                let prod_values: Option<Vec<F>> = a_var_limb_values.and_then(|a_var_limb_values| {
                    b_var_limb_values.map(|b_var_limb_values| {
                        let mut prod_values = vec![F::ZERO; num_prod_limbs];
                        for i in 0..a.len() {
                            for j in 0..b.len() {
                                prod_values[i + j] += a_var_limb_values[i] * b_var_limb_values[j];
                            }
                        }
                        prod_values
                    })
                });

                let prod_allocated_nums: Vec<AllocatedNum<F>> = (0..num_prod_limbs)
                    .map(|i| {
                        AllocatedNum::alloc(cs.namespace(|| format!("product limb {i}")), || {
                            prod_values
                                .as_ref()
                                .map(|prod_values| prod_values[i])
                                .ok_or(SynthesisError::AssignmentMissing)
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                prod = prod_allocated_nums.into_iter().map(Num::from).collect();

                let mut c = F::ZERO;
                for _ in 0..num_prod_limbs {
                    c += F::ONE;
                    cs.enforce(
                        || format!("pointwise product @ {c:?}"),
                        |lc| {
                            let mut coeff = F::ONE;
                            let a_lcs: Vec<LinearCombination<F>> =
                                a_var.iter().map(|x| x.lc(F::ONE)).collect();

                            a_lcs.iter().fold(lc, |acc, elem| {
                                let r = acc + (coeff, elem);
                                coeff *= c;
                                r
                            })
                        },
                        |lc| {
                            let mut coeff = F::ONE;
                            let b_lcs: Vec<LinearCombination<F>> =
                                b_var.iter().map(|x| x.lc(F::ONE)).collect();

                            b_lcs.iter().fold(lc, |acc, elem| {
                                let r = acc + (coeff, elem);
                                coeff *= c;
                                r
                            })
                        },
                        |lc| {
                            let mut coeff = F::ONE;
                            let prod_lcs: Vec<LinearCombination<F>> =
                                prod.iter().map(|x| x.lc(F::ONE)).collect();

                            prod_lcs.iter().fold(lc, |acc, elem| {
                                let r = acc + (coeff, elem);
                                coeff *= c;
                                r
                            })
                        },
                    )
                }
            }
            (EmulatedLimbs::Constant(_), EmulatedLimbs::Constant(_)) => {
                panic!("Constant limb case has already been handled")
            }
        }

        Ok(Self::new_internal_element(
            EmulatedLimbs::Allocated(prod),
            next_overflow,
        ))
    }

    pub fn mul<CS>(&self, cs: &mut CS, other: &Self) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<F>,
    {
        let mut prod = Self::reduce_and_apply_op(
            &mut cs.namespace(|| "compute a * b"),
            &Optype::Mul,
            self,
            other,
        )?;
        if !prod.is_constant() {
            prod.fold_limbs(&mut cs.namespace(|| "fold limbs of product"))?;
        }
        Ok(prod)
    }

    pub fn mul_const<CS>(&self, cs: &mut CS, constant: &BigInt) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<F>,
    {
        if constant.bits() as usize > Self::max_overflow() {
            eprintln!(
                "constant and limb product will overflow native limb capacity even after reduction"
            );
            return Err(SynthesisError::Unsatisfiable);
        }
        let mut next_overflow: usize = constant.bits() as usize + self.overflow;

        let elem = if next_overflow > Self::max_overflow() {
            next_overflow = constant.bits() as usize;
            self.reduce(
                &mut cs.namespace(|| "reduce element to accommodate mul with const".to_string()),
            )?
        } else {
            self.clone()
        };

        let mut prod: Vec<Num<F>> = vec![];
        let constant_scalar = bigint_to_scalar(constant);

        match elem.limbs {
            EmulatedLimbs::Allocated(allocated_limbs) => {
                for limb in &allocated_limbs {
                    prod.push(limb.clone().scale(constant_scalar));
                }
            }
            EmulatedLimbs::Constant(_) => {
                panic!("mul_const not implemented for element with constant limbs")
            }
        }

        Ok(Self::new_internal_element(
            EmulatedLimbs::Allocated(prod),
            next_overflow,
        ))
    }

    pub fn inverse<CS>(&self, cs: &mut CS) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<F>,
    {
        let a_inv = self.compute_inverse(&mut cs.namespace(|| "multiplicative inverse"))?;
        let prod = self.mul(&mut cs.namespace(|| "product of a and a_inv"), &a_inv)?;
        Self::assert_is_equal(
            &mut cs.namespace(|| "product equals one"),
            &prod,
            &Self::one(),
        )?;

        Ok(a_inv)
    }

    pub fn divide<CS>(&self, cs: &mut CS, denom: &Self) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<F>,
    {
        let ratio = self.compute_ratio(&mut cs.namespace(|| "ratio"), denom)?;
        let prod = ratio.mul(
            &mut cs.namespace(|| "product of ratio and denominator"),
            denom,
        )?;
        Self::assert_is_equal(
            &mut cs.namespace(|| "product equals numerator"),
            &prod,
            self,
        )?;

        Ok(ratio)
    }

    pub fn fold_limbs<CS>(&mut self, cs: &mut CS) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<F>,
    {
        // No folding algorithm for non-pseudo Mersenne primes; this method becomes a no-op
        if !P::is_modulus_pseudo_mersenne() {
            return Ok(());
        }

        if self.is_constant() {
            eprintln!("fold_limbs not implemented for constants");
            return Err(SynthesisError::Unsatisfiable);
        }

        // No extra limbs to fold
        if self.len() <= P::num_limbs() {
            return Ok(());
        }

        let num_chunks = (self.len() + P::num_limbs() - 1) / P::num_limbs();
        let mut chunks: Vec<Self> = vec![];

        match &self.limbs {
            EmulatedLimbs::Allocated(var) => {
                for i in 0..num_chunks {
                    let mut part_lcs = vec![];
                    for j in 0..P::num_limbs() {
                        if i * P::num_limbs() + j < self.len() {
                            part_lcs.push(var[i * P::num_limbs() + j].clone());
                        }
                    }

                    let chunk = Self {
                        limbs: EmulatedLimbs::Allocated(part_lcs),
                        overflow: self.overflow,
                        internal: self.internal,
                        marker: PhantomData,
                    };
                    chunks.push(chunk);
                }
            }
            EmulatedLimbs::Constant(_) => panic!(
                "Constant input already handled with a return. Execution should not reach here"
            ),
        }

        let pseudo_mersenne_params = P::pseudo_mersenne_params().unwrap();
        assert!(P::num_limbs() * P::bits_per_limb() >= pseudo_mersenne_params.e as usize, "The number of bits available is too small to accommodate the non-native field elements");

        let mut acc = chunks[0].clone();

        for (i, chunk) in chunks.iter().enumerate().skip(1) {
            let bitwidth = (i * P::num_limbs() * P::bits_per_limb()) as u32;
            let q = bitwidth / pseudo_mersenne_params.e;
            let r = bitwidth % pseudo_mersenne_params.e;
            let mut scale = pseudo_mersenne_params.c.pow(q);
            scale *= BigInt::one() << r;
            let scaled_chunk = chunk.mul_const(
                &mut cs.namespace(|| format!("multiplying chunk {i} with {scale}")),
                &scale,
            )?;
            acc = acc.add(
                &mut cs.namespace(|| format!("adding chunk {i}-1 and chunk {i}")),
                &scaled_chunk,
            )?;
        }

        *self = acc;

        Ok(())
    }

    fn reduce_and_apply_op<CS>(
        cs: &mut CS,
        op_type: &Optype,
        a: &Self,
        b: &Self,
    ) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<F>,
    {
        a.enforce_width_conditional(&mut cs.namespace(|| "ensure bitwidths in a"))?;
        b.enforce_width_conditional(&mut cs.namespace(|| "ensure bitwidths in b"))?;

        let precondition = match op_type {
            Optype::Add => Self::add_precondition,
            Optype::Sub => Self::sub_precondition,
            Optype::Mul => Self::mul_precondition,
        };

        let mut a_r: Self = a.clone();
        let mut b_r: Self = b.clone();
        let mut loop_iteration = 0u32; // Used to prevent namespace collisions in below loop
        let next_overflow: usize = loop {
            let res = precondition(&a_r, &b_r);
            if let Ok(res_next_overflow) = res {
                break res_next_overflow;
            } else {
                let err = res.err().unwrap();
                if err.reduce_right {
                    b_r = b_r.reduce(&mut cs.namespace(|| format!("reduce b {loop_iteration}")))?;
                } else {
                    a_r = a_r.reduce(&mut cs.namespace(|| format!("reduce a {loop_iteration}")))?;
                }
            }
            loop_iteration += 1;
        };

        let res = match op_type {
            Optype::Add => Self::add_op::<CS>(&a_r, &b_r, next_overflow),
            Optype::Sub => Self::sub_op::<CS>(&a_r, &b_r, next_overflow),
            Optype::Mul => Self::mul_op(&mut cs.namespace(|| "mul_op"), &a_r, &b_r, next_overflow),
        };

        res
    }
}
