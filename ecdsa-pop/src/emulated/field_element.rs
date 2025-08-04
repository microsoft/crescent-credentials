use std::vec;
use std::{marker::PhantomData, ops::Rem};

use bellpepper_core::num::AllocatedNum;
use bellpepper_core::{
    boolean::{AllocatedBit, Boolean},
    num::Num,
};
use bellpepper_core::{ConstraintSystem, LinearCombination, SynthesisError};
use ff::PrimeFieldBits;
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, Signed, Zero};

use crate::emulated::util::*;

#[derive(Clone)]
pub enum EmulatedLimbs<F: PrimeFieldBits> {
    Allocated(Vec<Num<F>>),
    Constant(Vec<F>),
}

impl<F> From<Vec<F>> for EmulatedLimbs<F>
where
    F: PrimeFieldBits,
{
    fn from(value: Vec<F>) -> Self {
        Self::Constant(value)
    }
}

impl<F> AsRef<Self> for EmulatedLimbs<F>
where
    F: PrimeFieldBits,
{
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<F> EmulatedLimbs<F>
where
    F: PrimeFieldBits,
{
    pub(crate) fn allocate_limbs<CS>(cs: &mut CS, limb_values: &[F]) -> Self
    where
        CS: ConstraintSystem<F>,
    {
        let mut num_vec: Vec<Num<F>> = vec![];

        for (i, v) in limb_values.iter().enumerate() {
            let allocated_limb = AllocatedNum::alloc(
                cs.namespace(|| format!("allocating limb {i}")),
                || Ok(*v),
            ).unwrap();
            num_vec.push(Num::<F>::from(allocated_limb));
        }

        Self::Allocated(num_vec)
    }

    /// Used to allocate EmulatedLimbs when no assignments are provided. Useful for MetricCS.
    pub(crate) fn allocate_empty_limbs<CS>(
        mut cs: CS,
        limb_count: usize,
    ) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<F>,
    {
        let mut num_vec: Vec<Num<F>> = vec![];

        for i in 0..limb_count {
            let allocated_limb =
                AllocatedNum::alloc(cs.namespace(|| format!("allocating limb {i}")), || {
                    Err(SynthesisError::AssignmentMissing)
                })?;
            num_vec.push(Num::<F>::from(allocated_limb));
        }

        Ok(Self::Allocated(num_vec))
    }
}

/// Parameters of a prime of the form `2^e-c`
pub struct PseudoMersennePrime {
    pub e: u32,
    pub c: BigInt,
}

/// Emulated field is assumed to be prime. So inverses always
/// exist for non-zero field elements
pub trait EmulatedFieldParams {
    fn num_limbs() -> usize;
    fn bits_per_limb() -> usize;
    fn modulus() -> BigInt;

    fn is_modulus_pseudo_mersenne() -> bool {
        false
    }

    fn pseudo_mersenne_params() -> Option<PseudoMersennePrime> {
        None
    }
}

#[allow(clippy::len_without_is_empty)]
pub struct EmulatedFieldElement<F: PrimeFieldBits, P: EmulatedFieldParams> {
    pub(crate) limbs: EmulatedLimbs<F>,
    pub(crate) overflow: usize,
    pub(crate) internal: bool,
    pub(crate) marker: PhantomData<P>,
}

impl<F, P> Clone for EmulatedFieldElement<F, P>
where
    F: PrimeFieldBits,
    P: EmulatedFieldParams,
{
    fn clone(&self) -> Self {
        Self {
            limbs: self.limbs.clone(),
            overflow: self.overflow,
            internal: self.internal,
            marker: self.marker,
        }
    }
}

impl<F, P> From<&BigInt> for EmulatedFieldElement<F, P>
where
    F: PrimeFieldBits,
    P: EmulatedFieldParams,
{
    /// Converts a [BigInt] into an [EmulatedFieldElement]
    ///
    /// Note that any [BigInt] larger than the field modulus is
    /// first reduced. A [BigInt] equal to the modulus itself is not
    /// reduced.
    fn from(value: &BigInt) -> Self {
        let mut v = value.clone();
        assert!(!v.is_negative());

        if v > P::modulus() {
            v = v.rem(P::modulus());
        }

        assert!(v.bits() <= (P::num_limbs() * P::bits_per_limb()) as u64);
        let mut v_bits: Vec<bool> = vec![false; P::num_limbs() * P::bits_per_limb()];

        let v_bytes = v.to_biguint().map(|w| w.to_bytes_le()).unwrap();
        for (i, b) in v_bytes.into_iter().enumerate() {
            for j in 0..8usize {
                if b & (1u8 << j) != 0 {
                    v_bits[i * 8 + j] = true;
                }
            }
        }

        let mut limbs = vec![F::ZERO; P::num_limbs()];
        for i in 0..P::num_limbs() {
            let mut coeff = F::ONE;
            for j in 0..P::bits_per_limb() {
                if v_bits[i * P::bits_per_limb() + j] {
                    limbs[i] += coeff
                }
                coeff = coeff.double();
            }
        }

        Self {
            limbs: EmulatedLimbs::Constant(limbs),
            overflow: 0,
            internal: true,
            marker: PhantomData,
        }
    }
}

impl<F, P> TryFrom<&EmulatedFieldElement<F, P>> for BigInt
where
    F: PrimeFieldBits,
    P: EmulatedFieldParams,
{
    type Error = SynthesisError;

    fn try_from(value: &EmulatedFieldElement<F, P>) -> Result<Self, Self::Error> {
        let mut res: BigUint = Zero::zero();
        let one: &BigUint = &One::one();
        let mut base: BigUint = one.clone();
        let limbs = match value.limbs.clone() {
            EmulatedLimbs::Allocated(x) => x
                .into_iter()
                .map(|a| a.get_value().ok_or(SynthesisError::AssignmentMissing))
                .collect::<Result<_, _>>()?,
            EmulatedLimbs::Constant(x) => x,
        };
        for limb in limbs {
            res += base.clone() * BigUint::from_bytes_le(limb.to_repr().as_ref());
            base *= one << P::bits_per_limb();
        }
        Ok(Self::from(res))
    }
}

impl<F, P> EmulatedFieldElement<F, P>
where
    F: PrimeFieldBits,
    P: EmulatedFieldParams,
{
    pub fn zero() -> Self {
        Self::from(&BigInt::zero())
    }

    pub fn one() -> Self {
        Self::from(&BigInt::one())
    }

    pub fn modulus() -> Self {
        Self::from(&P::modulus())
    }

    pub fn max_overflow() -> usize {
        F::CAPACITY as usize - P::bits_per_limb()
    }

    pub fn new_internal_element(limbs: EmulatedLimbs<F>, overflow: usize) -> Self {
        Self {
            limbs,
            overflow,
            internal: true,
            marker: PhantomData,
        }
    }

    pub fn len(&self) -> usize {
        match &self.limbs {
            EmulatedLimbs::Allocated(allocated_limbs) => allocated_limbs.len(),
            EmulatedLimbs::Constant(constant_limbs) => constant_limbs.len(),
        }
    }

    pub fn is_constant(&self) -> bool {
        matches!(self.limbs, EmulatedLimbs::Constant(_))
    }

    pub fn allocate_optional_limbs<CS>(
        cs: &mut CS,
        value: Option<BigInt>,
    ) -> Result<EmulatedLimbs<F>, SynthesisError>
    where
        CS: ConstraintSystem<F>,
    {
        // This is uniform because constants generated by the `From` impl always
        // have exactly `P::num_limbs()` limbs
        if let Some(val) = value {
            let res = Self::from(&val);
            assert_eq!(res.len(), P::num_limbs());
            res.allocate_limbs(cs)
        } else {
            EmulatedLimbs::<F>::allocate_empty_limbs(cs, P::num_limbs())
        }
    }

    pub fn allocate_limbs<CS>(&self, cs: &mut CS) -> Result<EmulatedLimbs<F>, SynthesisError>
    where
        CS: ConstraintSystem<F>,
    {
        if let EmulatedLimbs::Constant(limb_values) = &self.limbs {
            assert_eq!(limb_values.len(), P::num_limbs());
            Ok(EmulatedLimbs::<F>::allocate_limbs(
                &mut cs.namespace(|| "allocate variables from constant limbs"),
                limb_values,
            ))
        } else {
            eprintln!("input must have constant limb values");
            Err(SynthesisError::Unsatisfiable)
        }
    }

    /// Allocates an `AllocatedBit` that is set if and only if the element is
    /// congruent to 0 modulo the field prime.
    ///
    /// First reduces the field element, then allocates a bit per limb using
    /// `alloc_num_equals_constant` and `AND`s them all together.
    pub fn alloc_is_zero<CS>(&self, cs: &mut CS) -> Result<AllocatedBit, SynthesisError>
    where
        CS: ConstraintSystem<F>,
    {
        if self.is_constant() {
            eprintln!("alloc_is_zero not implemented for constants");
            return Err(SynthesisError::Unsatisfiable);
        }

        // allocate one bit per limb of the allocated limbs and AND them all together
        let mut final_bit: Option<AllocatedBit> = None;

        // explicitly reduce so we can use `alloc_num_equals_constant` on every limb and directly compare against 0
        let k = self.reduce(&mut cs.namespace(|| "self mod P"))?;

        if let EmulatedLimbs::Allocated(alloc_limbs) = &k.limbs {
            assert!(
                alloc_limbs.len() > 1,
                "alloc_is_zero needs more than 1 limb"
            );

            for (i, v) in alloc_limbs.iter().enumerate() {
                let new_allocated_limb_bit = alloc_num_equals_constant(
                    &mut cs.namespace(|| format!("alloc limb is_zero {i}")),
                    v,
                    F::ZERO,
                )?;
                if let Some(accumulated_bit) = final_bit {
                    final_bit = Some(AllocatedBit::and(
                        &mut cs.namespace(|| format!("alloc and bit {i}")),
                        &accumulated_bit,
                        &new_allocated_limb_bit,
                    )?);
                } else {
                    final_bit = Some(new_allocated_limb_bit);
                }
            }
        } else {
            panic!("cannot alloc is_zero for constant limbs");
        }

        Ok(final_bit.unwrap())
    }

    pub fn allocate_optional_field_element_unchecked<CS>(
        cs: &mut CS,
        value: &Option<BigInt>,
    ) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<F>,
    {
        if let Some(value) = value {
            let res = Self::from(value);
            res.allocate_field_element_unchecked(cs)
        } else {
            let allocated_limbs = Self::allocate_optional_limbs(cs, None)?;
            let allocated_field_element = Self::new_internal_element(allocated_limbs, 0);
            Ok(allocated_field_element)
        }
    }

    /// Allocates an emulated field element from constant limbs **without**
    /// in-circuit checks for field membership. If you want to enforce membership
    /// in the field, you can call `check_field_membership` on the output of this
    /// method.
    ///
    /// This method is suitable for allocating field elements from public inputs
    /// that are known to be in the field.
    pub fn allocate_field_element_unchecked<CS>(&self, cs: &mut CS) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<F>,
    {
        if self.is_constant() {
            // Below statement does not perform a in-circuit check as the input is a constant
            self.check_field_membership(
                &mut cs.namespace(|| "check field membership of constant input"),
            )?;

            let allocated_limbs = self
                .allocate_limbs(&mut cs.namespace(|| "allocate variables from constant limbs"))?;

            let allocated_field_element = Self::new_internal_element(allocated_limbs, 0);
            Ok(allocated_field_element)
        } else {
            eprintln!("input must have constant limb values");
            Err(SynthesisError::Unsatisfiable)
        }
    }

    /// Enforces limb bit widths in a [EmulatedFieldElement]
    ///
    /// All the limbs are constrained to have width that is at most equal to the width
    /// specified by [EmulatedFieldParams].
    /// If `modulus_width` is `true`, the most significant limb will be constrained to have
    /// width less than or equal to the most significant limb of the modulus.
    /// For constant elements, the number of limbs is required to be equal to P::num_limbs().
    /// For allocated elements, the number of limbs is required to be equal to P::num_limbs()
    /// only if `modulus_width` is true. In the calculation of quotients, the limbs may not
    /// be equal to P::num_limbs()
    fn enforce_width<CS>(&self, cs: &mut CS, modulus_width: bool) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<F>,
    {
        if let EmulatedLimbs::Constant(limb_values) = &self.limbs {
            if limb_values.len() != P::num_limbs() {
                eprintln!("Constant limb count does not match required count");
                return Err(SynthesisError::Unsatisfiable);
            }

            for (i, limb) in limb_values.iter().enumerate() {
                let mut required_bit_width = P::bits_per_limb();
                if modulus_width && i == P::num_limbs() - 1 {
                    required_bit_width =
                        (P::modulus().bits() as usize - 1) % P::bits_per_limb() + 1;
                }
                range_check_constant(*limb, required_bit_width)?;
            }
        }
        if let EmulatedLimbs::Allocated(allocated_limbs) = &self.limbs {
            if modulus_width && allocated_limbs.len() != P::num_limbs() {
                eprintln!("Allocated limb count does not match required count");
                return Err(SynthesisError::Unsatisfiable);
            }

            for (i, limb) in allocated_limbs.iter().enumerate() {
                let mut required_bit_width = P::bits_per_limb();
                if modulus_width && i == P::num_limbs() - 1 {
                    required_bit_width =
                        (P::modulus().bits() as usize - 1) % P::bits_per_limb() + 1;
                }

                range_check_num(
                    &mut cs.namespace(|| format!("range check limb {i}")),
                    limb,
                    required_bit_width,
                )?;
            }
        }
        Ok(())
    }

    /// Enforces limb bit widths in a [EmulatedFieldElement] if it is not an
    /// internal element or a constant
    ///
    /// The number of limbs is required to be equal to P::num_limbs(), and
    /// the most significant limb will be constrained to have
    /// width less than or equal to the most significant limb of the modulus.
    pub(crate) fn enforce_width_conditional<CS>(&self, cs: &mut CS) -> Result<bool, SynthesisError>
    where
        CS: ConstraintSystem<F>,
    {
        if self.internal {
            return Ok(false);
        }
        if self.is_constant() {
            return Ok(false);
        }
        self.enforce_width(&mut cs.namespace(|| "enforce width"), true)?;
        Ok(true)
    }

    /// Constructs a [EmulatedFieldElement] from limbs of type [EmulatedLimbs].
    /// The method name is inherited from gnark.
    ///
    /// All the limbs are constrained to have width that is at most equal to the width
    /// specified by [EmulatedFieldParams].
    /// If `strict` is `true`, the most significant limb will be constrained to have
    /// width less than or equal to the most significant limb of the modulus.
    pub(crate) fn pack_limbs<CS>(
        cs: &mut CS,
        limbs: EmulatedLimbs<F>,
        strict: bool,
    ) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<F>,
    {
        let elem = Self::new_internal_element(limbs, 0);
        elem.enforce_width(&mut cs.namespace(|| "pack limbs"), strict)?;
        Ok(elem)
    }

    pub fn compact_limbs(
        &self,
        group_size: usize,
        new_bits_per_limb: usize,
    ) -> Result<EmulatedLimbs<F>, SynthesisError> {
        if P::bits_per_limb() == new_bits_per_limb {
            return Ok(self.limbs.clone());
        }
        if self.is_constant() {
            eprintln!("compact_limbs not implemented for constants");
            return Err(SynthesisError::Unsatisfiable);
        }

        if let EmulatedLimbs::<F>::Allocated(allocated_limbs) = &self.limbs {
            let mut coeffs = vec![];
            for i in 0..group_size {
                coeffs.push(bigint_to_scalar(
                    &(BigInt::one() << (P::bits_per_limb() * i)),
                ));
            }

            let new_num_limbs = allocated_limbs.len().div_ceil(group_size);
            let mut res = vec![Num::<F>::zero(); new_num_limbs];

            for i in 0..new_num_limbs {
                for j in 0..group_size {
                    if i * group_size + j < allocated_limbs.len() {
                        res[i] = allocated_limbs[i * group_size + j]
                            .clone()
                            .scale(coeffs[j])
                            .add(&res[i]);
                    }
                }
            }
            return Ok(EmulatedLimbs::Allocated(res));
        }
        // Should not reach this line
        Err(SynthesisError::Unsatisfiable)
    }

    pub fn check_field_membership<CS>(&self, cs: &mut CS) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<F>,
    {
        if self.is_constant() {
            if BigInt::try_from(self)? < P::modulus() {
                return Ok(());
            } else {
                return Err(SynthesisError::Unsatisfiable);
            }
        }

        if self.len() != P::num_limbs() {
            eprintln!("Field membership check only implemented for limb count equal to default");
            return Err(SynthesisError::Unsatisfiable);
        }

        match &self.limbs {
            EmulatedLimbs::Allocated(allocated_limbs) => {
                // Number of modulus bits in most significant limb
                let num_mod_bits_in_msl =
                    (P::modulus().bits() as usize - 1) % P::bits_per_limb() + 1;

                for (i, limb) in allocated_limbs.iter().enumerate() {
                    let num_bits = if i == P::num_limbs() - 1 {
                        num_mod_bits_in_msl
                    } else {
                        P::bits_per_limb()
                    };

                    range_check_num(
                        &mut cs.namespace(|| format!("range check limb {i}")),
                        limb,
                        num_bits,
                    )?;
                }

                if P::is_modulus_pseudo_mersenne() {
                    let pseudo_mersenne_params = P::pseudo_mersenne_params().unwrap();
                    // Maximum value of most significant limb
                    let max_msl_value = (BigInt::one() << num_mod_bits_in_msl) - BigInt::one();
                    // Maximum value of least significant limbs
                    let max_lsl_value = (BigInt::one() << P::bits_per_limb()) - BigInt::one();

                    let equality_bits: Vec<AllocatedBit> = (1..P::num_limbs())
                        .map(|i| {
                            let max_limb_value = if i == P::num_limbs() - 1 {
                                bigint_to_scalar(&max_msl_value)
                            } else {
                                bigint_to_scalar(&max_lsl_value)
                            };

                            let bit = alloc_num_equals_constant(
                                cs.namespace(|| format!("limb {i} equals max value")),
                                &allocated_limbs[i],
                                max_limb_value,
                            );
                            bit.unwrap()
                        })
                        .collect();

                    let mut kary_and = equality_bits[0].clone();
                    #[allow(clippy::needless_range_loop)]
                    for i in 1..P::num_limbs() - 1 {
                        kary_and = AllocatedBit::and(
                            cs.namespace(|| format!("and of bits {} and {}", i - 1, i)),
                            &kary_and,
                            &equality_bits[i],
                        )?
                    }

                    let c = bigint_to_scalar(&pseudo_mersenne_params.c);

                    // Least significant limb increased by c if all the most significant limbs are maxxed out
                    // If kary_and is true, then lsl_num = allocated_limbs[0] + c. Otherwise, lsl_num = allocated_limbs[0].
                    // The latter is already within P::bits_per_limb(). If the former only has P::bits_per_limb(),
                    // then allocated_limbs[0] is at most 2^(P::bits_per_limb())-1-c
                    let lsl_num = allocated_limbs[0].clone().add_bool_with_coeff(
                        CS::one(),
                        &Boolean::Is(kary_and),
                        c,
                    );
                    range_check_num(
                        &mut cs.namespace(|| {
                            "range check limb least significant limb + possibly c".to_string()
                        }),
                        &lsl_num,
                        P::bits_per_limb(),
                    )?;
                } else {
                    panic!(
                        "Check field membership implemented only for pseudo-Mersenne prime moduli"
                    );
                }
            }
            EmulatedLimbs::Constant(_) => {
                panic!("constant case is already handled; this code should be unreachable")
            }
        }

        Ok(())
    }

    // If condition is true, return a1. Otherwise return a0.
    // Based on Nova/src/gadgets/utils.rs:conditionally_select
    pub fn conditionally_select<CS>(
        cs: &mut CS,
        a0: &Self,
        a1: &Self,
        condition: &Boolean,
    ) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<F>,
    {
        if a1.len() != a0.len() {
            eprintln!(
                "Current implementation of conditionally_select only allows same number of limbs"
            );
            return Err(SynthesisError::Unsatisfiable);
        }
        let limb_count = a0.len();
        let res_overflow = a1.overflow.max(a0.overflow);

        let res_alloc_limbs = if let Some(cond) = condition.get_value() {
            // If the condition has a value, then the limbs must also have a value, so we bubble
            // the assignment missing error in this case
            let res_values = if cond {
                match &a1.limbs {
                    EmulatedLimbs::Allocated(a1_var) => a1_var
                        .iter()
                        .map(|v| v.get_value().ok_or(SynthesisError::AssignmentMissing))
                        .collect::<Result<_, _>>()?,
                    EmulatedLimbs::Constant(a1_const) => a1_const.clone(),
                }
            } else {
                match &a0.limbs {
                    EmulatedLimbs::Allocated(a0_var) => a0_var
                        .iter()
                        .map(|v| v.get_value().ok_or(SynthesisError::AssignmentMissing))
                        .collect::<Result<_, _>>()?,
                    EmulatedLimbs::Constant(a0_const) => a0_const.clone(),
                }
            };
            EmulatedLimbs::allocate_limbs(
                &mut cs.namespace(|| "allocate result limbs"),
                &res_values,
            )
        } else {
            // Otherwise, allocate "empty" limbs in case this is a MetricCS or TestCS
            EmulatedLimbs::allocate_empty_limbs(
                &mut cs.namespace(|| "allocate result limbs"),
                limb_count,
            )?
        };

        match &res_alloc_limbs {
            EmulatedLimbs::Allocated(res_limbs) => {
                for i in 0..limb_count {
                    let a1_lc = match &a1.limbs {
                        EmulatedLimbs::Allocated(a1_var) => a1_var[i].lc(F::ONE),
                        EmulatedLimbs::Constant(a1_const) => {
                            LinearCombination::<F>::from_coeff(CS::one(), a1_const[i])
                        }
                    };
                    let a0_lc = match &a0.limbs {
                        EmulatedLimbs::Allocated(a0_var) => a0_var[i].lc(F::ONE),
                        EmulatedLimbs::Constant(a0_const) => {
                            LinearCombination::<F>::from_coeff(CS::one(), a0_const[i])
                        }
                    };

                    cs.enforce(
                        || format!("conditional select constraint on limb {i}"),
                        |lc| lc + &a1_lc - &a0_lc,
                        |_| condition.lc(CS::one(), F::ONE),
                        |lc| lc + &res_limbs[i].lc(F::ONE) - &a0_lc,
                    );
                }
            }
            EmulatedLimbs::Constant(_) => panic!("Unreachable match arm"),
        }
        let res = Self::new_internal_element(res_alloc_limbs, res_overflow);
        Ok(res)
    }

    // Based on bellperson-nonnative/src/util/gadget.rs:mux_tree
    // `select_bits` are given in big-endian order and `inputs` have
    // the zero index input first, i.e. [a0, a1, a2, ...]
    pub fn mux_tree<'a, CS>(
        cs: &mut CS,
        mut select_bits: impl Iterator<Item = &'a Boolean> + Clone,
        inputs: &[Self],
    ) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<F>,
    {
        if let Some(bit) = select_bits.next() {
            if inputs.len() & 1 != 0 {
                return Err(SynthesisError::Unsatisfiable);
            }
            let left_half = &inputs[..(inputs.len() / 2)];
            let right_half = &inputs[(inputs.len() / 2)..];
            let left =
                Self::mux_tree(&mut cs.namespace(|| "left"), select_bits.clone(), left_half)?;
            let right = Self::mux_tree(&mut cs.namespace(|| "right"), select_bits, right_half)?;
            Self::conditionally_select(&mut cs.namespace(|| "join"), &left, &right, bit)
        } else {
            if inputs.len() != 1 {
                return Err(SynthesisError::Unsatisfiable);
            }
            Ok(inputs[0].clone())
        }
    }

    /// Implements the `sgn0` function from [RFC 9380](https://datatracker.ietf.org/doc/html/rfc9380#name-the-sgn0-function)
    /// which returns `x mod 2`
    pub fn sgn0<CS>(&self, cs: &mut CS) -> Result<Boolean, SynthesisError>
    where
        CS: ConstraintSystem<F>,
    {
        self.enforce_width_conditional(&mut cs.namespace(|| "ensure bitwidths in input"))?;

        let least_sig = match &self.limbs {
            EmulatedLimbs::Allocated(limbs) => limbs[0].get_value().unwrap(),
            EmulatedLimbs::Constant(limbs) => limbs[0],
        };

        let (out_val, div) = {
            let val = BigInt::from_bytes_le(Sign::Plus, least_sig.to_repr().as_ref());
            let out = &val % 2u64;
            let div = &val / 2u64;
            assert_eq!(2u64 * &div + &out, val.clone(), "sanity check");
            if out == BigInt::from(0u64) {
                (false, div)
            } else if out == BigInt::from(1u64) {
                (true, div)
            } else {
                unreachable!("Division by 2 always returns 0 or 1")
            }
        };

        let out = match &self.limbs {
            EmulatedLimbs::Allocated(limbs) => {
                let out_bit =
                    AllocatedBit::alloc(&mut cs.namespace(|| "alloc sgn0 out"), Some(out_val))?;
                let div = AllocatedNum::alloc(&mut cs.namespace(|| "alloc sgn0 div"), || {
                    Ok(bigint_to_scalar(&div))
                })?;

                // enforce that least significant limb is divisible by 2
                let two = F::ONE + F::ONE;
                cs.enforce(
                    || "enforce sgn0 bit",
                    |lc| lc + CS::one(),
                    |lc| lc + (two, div.get_variable()) + out_bit.get_variable(), // 2 * div + out
                    |lc| lc + &limbs[0].lc(F::ONE),                               // least_sig
                );
                Boolean::from(out_bit)
            }
            EmulatedLimbs::Constant(_) => Boolean::Constant(out_val),
        };

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bellpepper::gadgets::multipack::pack_bits;
    use bellpepper_core::test_cs::TestConstraintSystem;
    use num_bigint::RandBigInt;
    use num_traits::FromPrimitive;
    use ff::Field;
    use ark_std::rand::thread_rng;
    use crate::utils::scalar_to_bigint;
    use halo2curves::secp256r1::Fp;
    use halo2curves::bn256::Fr;

    struct Ed25519Fp;

    impl EmulatedFieldParams for Ed25519Fp {
        fn num_limbs() -> usize {
            5
        }

        fn bits_per_limb() -> usize {
            51
        }

        fn modulus() -> BigInt {
            BigInt::parse_bytes(
                b"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",
                16,
            )
            .unwrap()
        }

        fn is_modulus_pseudo_mersenne() -> bool {
            true
        }

        fn pseudo_mersenne_params() -> Option<PseudoMersennePrime> {
            Some(PseudoMersennePrime {
                e: 255,
                c: BigInt::from(19),
            })
        }
    }



    #[test]
    fn test_constant_equality() {
        let mut cs = TestConstraintSystem::<Fp>::new();
        let mut rng = thread_rng();
        let a_int = rng.gen_bigint_range(&BigInt::zero(), &Ed25519Fp::modulus());

        let a_const = EmulatedFieldElement::<Fp, Ed25519Fp>::from(&a_int);

        let a = a_const.allocate_field_element_unchecked(&mut cs.namespace(|| "a"));
        assert!(a.is_ok());
        let a = a.unwrap();

        let res = a.assert_equality_to_constant(&mut cs.namespace(|| "check equality"), &a_const);
        assert!(res.is_ok());

        if !cs.is_satisfied() {
            println!("{:?}", cs.which_is_unsatisfied());
        }
        assert!(cs.is_satisfied());
        assert_eq!(cs.num_constraints(), 5);
    }

    #[test]
    fn test_alloc_is_zero() {
        let mut cs = TestConstraintSystem::<Fp>::new();

        let one_const = EmulatedFieldElement::<Fp, Ed25519Fp>::one();
        let one_alloc = one_const.allocate_field_element_unchecked(&mut cs.namespace(|| "one"));
        assert!(one_alloc.is_ok());
        let one = one_alloc.unwrap();

        let res = one.alloc_is_zero(&mut cs.namespace(|| "check if one == zero"));
        assert!(res.is_ok());
        let one_is_zero = res.unwrap();
        assert!(!one_is_zero.get_value().unwrap());

        if !cs.is_satisfied() {
            println!("{:?}", cs.which_is_unsatisfied());
        }
        assert!(cs.is_satisfied());
        assert_eq!(cs.num_constraints(), 19);

        let zero_const = EmulatedFieldElement::<Fp, Ed25519Fp>::zero();
        let zero_alloc = zero_const.allocate_field_element_unchecked(&mut cs.namespace(|| "zero"));
        assert!(zero_alloc.is_ok());
        let zero = zero_alloc.unwrap();

        let res = zero.alloc_is_zero(&mut cs.namespace(|| "check if zero == zero"));
        assert!(res.is_ok());
        let zero_is_zero = res.unwrap();
        assert!(zero_is_zero.get_value().unwrap());

        if !cs.is_satisfied() {
            println!("{:?}", cs.which_is_unsatisfied());
        }
        assert!(cs.is_satisfied());
        assert_eq!(cs.num_constraints(), 38);
    }

    #[test]
    fn test_add() {
        let mut cs = TestConstraintSystem::<Fp>::new();
        let mut rng = thread_rng();
        let a_int = rng.gen_bigint_range(&BigInt::zero(), &Ed25519Fp::modulus());
        let b_int = rng.gen_bigint_range(&BigInt::zero(), &Ed25519Fp::modulus());
        let sum_int = (&a_int + &b_int).rem(&Ed25519Fp::modulus());

        let a_const = EmulatedFieldElement::<Fp, Ed25519Fp>::from(&a_int);
        let b_const = EmulatedFieldElement::<Fp, Ed25519Fp>::from(&b_int);
        let sum_const = EmulatedFieldElement::<Fp, Ed25519Fp>::from(&sum_int);

        let a = a_const.allocate_field_element_unchecked(&mut cs.namespace(|| "a"));
        let b = b_const.allocate_field_element_unchecked(&mut cs.namespace(|| "b"));
        let sum = sum_const.allocate_field_element_unchecked(&mut cs.namespace(|| "sum"));
        assert!(a.is_ok());
        assert!(b.is_ok());
        assert!(sum.is_ok());
        let a = a.unwrap();
        let b = b.unwrap();
        let sum = sum.unwrap();

        let sum_calc = a.add(&mut cs.namespace(|| "a + b"), &b);
        assert!(sum_calc.is_ok());
        let sum_calc = sum_calc.unwrap();

        let res = EmulatedFieldElement::<Fp, Ed25519Fp>::assert_is_equal(
            &mut cs.namespace(|| "check equality"),
            &sum_calc,
            &sum,
        );
        assert!(res.is_ok());

        if !cs.is_satisfied() {
            println!("{:?}", cs.which_is_unsatisfied());
        }
        assert!(cs.is_satisfied());
        assert_eq!(cs.num_constraints(), 158);
    }

    #[test]
    fn test_sub() {
        let mut cs = TestConstraintSystem::<Fp>::new();
        let mut rng = thread_rng();
        let tmp1 = rng.gen_bigint_range(&BigInt::zero(), &Ed25519Fp::modulus());
        let tmp2 = rng.gen_bigint_range(&BigInt::zero(), &Ed25519Fp::modulus());
        let a_int = (&tmp1).max(&tmp2);
        let b_int = (&tmp1).min(&tmp2);
        let diff_int = (a_int - b_int).rem(&Ed25519Fp::modulus());

        let a_const = EmulatedFieldElement::<Fp, Ed25519Fp>::from(a_int);
        let b_const = EmulatedFieldElement::<Fp, Ed25519Fp>::from(b_int);
        let diff_const = EmulatedFieldElement::<Fp, Ed25519Fp>::from(&diff_int);

        let a = a_const.allocate_field_element_unchecked(&mut cs.namespace(|| "a"));
        let b = b_const.allocate_field_element_unchecked(&mut cs.namespace(|| "b"));
        let diff = diff_const.allocate_field_element_unchecked(&mut cs.namespace(|| "diff"));
        assert!(a.is_ok());
        assert!(b.is_ok());
        assert!(diff.is_ok());
        let a = a.unwrap();
        let b = b.unwrap();
        let diff = diff.unwrap();

        let diff_calc = a.sub(&mut cs.namespace(|| "a - b"), &b);
        assert!(diff_calc.is_ok());
        let diff_calc = diff_calc.unwrap();

        let res = EmulatedFieldElement::<Fp, Ed25519Fp>::assert_is_equal(
            &mut cs.namespace(|| "check equality"),
            &diff_calc,
            &diff,
        );
        assert!(res.is_ok());

        if !cs.is_satisfied() {
            println!("{:?}", cs.which_is_unsatisfied());
        }
        assert!(cs.is_satisfied());
        assert_eq!(cs.num_constraints(), 158);
    }

    #[test]
    fn test_mul() {
        let mut cs = TestConstraintSystem::<Fp>::new();
        let mut rng = thread_rng();
        let a_int = rng.gen_bigint_range(&BigInt::zero(), &Ed25519Fp::modulus());
        let b_int = rng.gen_bigint_range(&BigInt::zero(), &Ed25519Fp::modulus());
        let prod_int = (&a_int * &b_int).rem(&Ed25519Fp::modulus());

        let a_const = EmulatedFieldElement::<Fp, Ed25519Fp>::from(&a_int);
        let b_const = EmulatedFieldElement::<Fp, Ed25519Fp>::from(&b_int);
        let prod_const = EmulatedFieldElement::<Fp, Ed25519Fp>::from(&prod_int);

        let a = a_const.allocate_field_element_unchecked(&mut cs.namespace(|| "a"));
        let b = b_const.allocate_field_element_unchecked(&mut cs.namespace(|| "b"));
        let prod = prod_const.allocate_field_element_unchecked(&mut cs.namespace(|| "prod"));
        assert!(a.is_ok());
        assert!(b.is_ok());
        assert!(prod.is_ok());
        let a = a.unwrap();
        let b = b.unwrap();
        let prod = prod.unwrap();

        let prod_calc = a.mul(&mut cs.namespace(|| "a * b"), &b);
        assert!(prod_calc.is_ok());
        let prod_calc = prod_calc.unwrap();

        let res = EmulatedFieldElement::<Fp, Ed25519Fp>::assert_is_equal(
            &mut cs.namespace(|| "check equality"),
            &prod_calc,
            &prod,
        );
        assert!(res.is_ok());

        if !cs.is_satisfied() {
            println!("{:?}", cs.which_is_unsatisfied());
        }
        assert!(cs.is_satisfied());
        assert_eq!(cs.num_constraints(), 236);
    }

    #[test]
    fn test_divide() {
        let mut cs = TestConstraintSystem::<Fp>::new();
        let mut rng = thread_rng();
        let a_int = rng.gen_bigint_range(&BigInt::zero(), &Ed25519Fp::modulus());
        let b_int = rng.gen_bigint_range(&BigInt::one(), &Ed25519Fp::modulus());
        let p = Ed25519Fp::modulus();
        let p_minus_2 = &p - BigInt::from(2);
        // b^(p-1) = 1 mod p for non-zero b. So b^(-1) = b^(p-2)
        let b_inv_int = b_int.modpow(&p_minus_2, &p);
        let ratio_int = (&a_int * b_inv_int).rem(&p);

        let a_const = EmulatedFieldElement::<Fp, Ed25519Fp>::from(&a_int);
        let b_const = EmulatedFieldElement::<Fp, Ed25519Fp>::from(&b_int);
        let ratio_const = EmulatedFieldElement::<Fp, Ed25519Fp>::from(&ratio_int);

        let a = a_const.allocate_field_element_unchecked(&mut cs.namespace(|| "a"));
        let b = b_const.allocate_field_element_unchecked(&mut cs.namespace(|| "b"));
        let ratio = ratio_const.allocate_field_element_unchecked(&mut cs.namespace(|| "ratio"));
        assert!(a.is_ok());
        assert!(b.is_ok());
        assert!(ratio.is_ok());
        let a = a.unwrap();
        let b = b.unwrap();
        let ratio = ratio.unwrap();

        let ratio_calc = a.divide(&mut cs.namespace(|| "a divided by b"), &b);
        assert!(ratio_calc.is_ok());
        let ratio_calc = ratio_calc.unwrap();

        let res = EmulatedFieldElement::<Fp, Ed25519Fp>::assert_is_equal(
            &mut cs.namespace(|| "check equality"),
            &ratio_calc,
            &ratio,
        );
        assert!(res.is_ok());

        let b_mul_ratio = b.mul(&mut cs.namespace(|| "b * (a div b)"), &ratio);
        assert!(b_mul_ratio.is_ok());
        let b_mul_ratio = b_mul_ratio.unwrap();

        let res = EmulatedFieldElement::<Fp, Ed25519Fp>::assert_is_equal(
            &mut cs.namespace(|| "check equality of a and b * (a div b)"),
            &b_mul_ratio,
            &a,
        );
        assert!(res.is_ok());

        if !cs.is_satisfied() {
            println!("{:?}", cs.which_is_unsatisfied());
        }
        assert!(cs.is_satisfied());
        assert_eq!(cs.num_constraints(), 885);
    }

    #[test]
    fn test_inverse() {
        let mut cs = TestConstraintSystem::<Fp>::new();
        let mut rng = thread_rng();
        let b_int = rng.gen_bigint_range(&BigInt::one(), &Ed25519Fp::modulus());
        let p = Ed25519Fp::modulus();
        let p_minus_2 = &p - BigInt::from(2);
        // b^(p-1) = 1 mod p for non-zero b. So b^(-1) = b^(p-2)
        let b_inv_int = b_int.modpow(&p_minus_2, &p);

        let b_const = EmulatedFieldElement::<Fp, Ed25519Fp>::from(&b_int);
        let b_inv_const = EmulatedFieldElement::<Fp, Ed25519Fp>::from(&b_inv_int);

        let b = b_const.allocate_field_element_unchecked(&mut cs.namespace(|| "b"));
        let b_inv = b_inv_const.allocate_field_element_unchecked(&mut cs.namespace(|| "b_inv"));
        assert!(b.is_ok());
        assert!(b_inv.is_ok());
        let b = b.unwrap();
        let b_inv = b_inv.unwrap();

        let b_inv_calc = b.inverse(&mut cs.namespace(|| "b inverse"));
        assert!(b_inv_calc.is_ok());
        let b_inv_calc = b_inv_calc.unwrap();

        let res = EmulatedFieldElement::<Fp, Ed25519Fp>::assert_is_equal(
            &mut cs.namespace(|| "check equality"),
            &b_inv_calc,
            &b_inv,
        );
        assert!(res.is_ok());

        let b_mul_b_inv = b.mul(&mut cs.namespace(|| "b * b_inv"), &b_inv);
        assert!(b_mul_b_inv.is_ok());
        let b_mul_b_inv = b_mul_b_inv.unwrap();

        let res = EmulatedFieldElement::<Fp, Ed25519Fp>::assert_is_equal(
            &mut cs.namespace(|| "check equality one and b * b_inv"),
            &b_mul_b_inv,
            &EmulatedFieldElement::<Fp, Ed25519Fp>::one(),
        );
        assert!(res.is_ok());

        if !cs.is_satisfied() {
            println!("{:?}", cs.which_is_unsatisfied());
        }
        assert!(cs.is_satisfied());
        assert_eq!(cs.num_constraints(), 885);
    }

    #[test]
    fn test_field_membership() {
        let mut cs = TestConstraintSystem::<Fp>::new();
        let mut rng = thread_rng();

        let a_int = rng.gen_bigint_range(&BigInt::zero(), &Ed25519Fp::modulus());
        let a_const = EmulatedFieldElement::<Fp, Ed25519Fp>::from(&a_int);
        let a = a_const.allocate_field_element_unchecked(&mut cs.namespace(|| "a"));
        // Num constraints before field membership check = 0
        assert_eq!(cs.num_constraints(), 0);
        assert!(a.is_ok());
        let a = a.unwrap();

        let res =
            a.check_field_membership(&mut cs.namespace(|| "check field membership of random a"));
        assert!(res.is_ok());

        assert!(cs.is_satisfied());
        // Num constraints after field membership check = 321
        assert_eq!(cs.num_constraints(), 321);

        let b_int = &Ed25519Fp::modulus() - BigInt::one();
        let b_const = EmulatedFieldElement::<Fp, Ed25519Fp>::from(&b_int);
        let b = b_const.allocate_field_element_unchecked(&mut cs.namespace(|| "q-1"));
        assert!(b.is_ok());
        let b = b.unwrap();

        let res = b.check_field_membership(&mut cs.namespace(|| "check field membership of q-1"));
        assert!(res.is_ok());

        assert!(cs.is_satisfied());

        let one = EmulatedFieldElement::<Fp, Ed25519Fp>::one();
        let q = b.add(&mut cs.namespace(|| "add 1 to q-1"), &one);
        assert!(q.is_ok());
        let q = q.unwrap();

        let res = q.check_field_membership(&mut cs.namespace(|| "check field non-membership of q"));
        assert!(res.is_ok());

        assert!(!cs.is_satisfied());
    }

    #[test]
    fn test_conditionally_select() {
        let mut cs = TestConstraintSystem::<Fp>::new();
        let mut rng = thread_rng();
        let a0_int = rng.gen_bigint_range(&BigInt::zero(), &Ed25519Fp::modulus());
        let a1_int = rng.gen_bigint_range(&BigInt::zero(), &Ed25519Fp::modulus());

        let a0_const = EmulatedFieldElement::<Fp, Ed25519Fp>::from(&a0_int);
        let a1_const = EmulatedFieldElement::<Fp, Ed25519Fp>::from(&a1_int);

        let one = TestConstraintSystem::<Fp>::one();
        let conditions = vec![false, true];
        for c in conditions.clone() {
            let condition = Boolean::constant(c);

            let res = EmulatedFieldElement::<Fp, Ed25519Fp>::conditionally_select(
                &mut cs.namespace(|| {
                    format!("conditionally select constant a0 or a1 for condition = {c}")
                }),
                &a0_const,
                &a1_const,
                &condition,
            );
            assert!(res.is_ok());
            if !c {
                assert_eq!(cs.num_constraints(), 5);
            }
            let res = res.unwrap();

            let res_expected_limbs = match (&a0_const.limbs, &a1_const.limbs) {
                (
                    EmulatedLimbs::Constant(a0_const_limbs),
                    EmulatedLimbs::Constant(a1_const_limbs),
                ) => {
                    if c {
                        a1_const_limbs
                    } else {
                        a0_const_limbs
                    }
                }
                _ => panic!("Both sets of limbs must be constant"),
            };

            if let EmulatedLimbs::Allocated(res_limbs) = res.limbs {
                for i in 0..res_limbs.len() {
                    cs.enforce(
                        || format!("c constant limb {i} equality for condition = {c}"),
                        |lc| lc + &res_limbs[i].lc(Fp::one()),
                        |lc| lc + one,
                        |lc| lc + (res_expected_limbs[i], one),
                    );
                }
            } else {
                // Execution should not reach this line
                eprintln!("res should have allocated limbs");
                unreachable!();
            }

            if !cs.is_satisfied() {
                eprintln!("{:?}", cs.which_is_unsatisfied());
            }
            assert!(cs.is_satisfied());
        }
        let num_constraints_here = cs.num_constraints();

        let a0 = a0_const.allocate_field_element_unchecked(&mut cs.namespace(|| "a"));
        let a1 = a1_const.allocate_field_element_unchecked(&mut cs.namespace(|| "b"));
        assert!(a0.is_ok());
        assert!(a1.is_ok());
        let a0 = a0.unwrap();
        let a1 = a1.unwrap();

        for c in conditions {
            let condition = Boolean::constant(c);

            let res = EmulatedFieldElement::<Fp, Ed25519Fp>::conditionally_select(
                &mut cs.namespace(|| {
                    format!("conditionally select variable a or b for condition = {c}")
                }),
                &a0,
                &a1,
                &condition,
            );
            assert!(res.is_ok());
            if !c {
                assert_eq!(cs.num_constraints() - num_constraints_here, 5);
            }
            let res = res.unwrap();

            let res_expected_limbs = match (&a0.limbs, &a1.limbs) {
                (EmulatedLimbs::Allocated(a0_limbs), EmulatedLimbs::Allocated(a1_limbs)) => {
                    if c {
                        a1_limbs
                    } else {
                        a0_limbs
                    }
                }
                _ => panic!("Both sets of limbs must be allocated"),
            };

            if let EmulatedLimbs::Allocated(res_limbs) = res.limbs {
                for i in 0..res_limbs.len() {
                    cs.enforce(
                        || format!("c variable limb {i} equality for condition = {c}"),
                        |lc| lc + &res_limbs[i].lc(Fp::one()),
                        |lc| lc + one,
                        |lc| lc + &res_expected_limbs[i].lc(Fp::one()),
                    );
                }
            } else {
                // Execution should not reach this line
                eprintln!("res should have allocated limbs");
                unreachable!();
            }

            if !cs.is_satisfied() {
                eprintln!("{:?}", cs.which_is_unsatisfied());
            }
            assert!(cs.is_satisfied());
        }
    }

    #[test]
    fn test_mux_tree() {
        test_mux_tree_helper(1, 5);
        test_mux_tree_helper(2, 15);
        test_mux_tree_helper(3, 35);
        test_mux_tree_helper(4, 75);
    }

    fn test_mux_tree_helper(num_selector_bits: usize, expected_num_constraints: usize) {
        let mut cs = TestConstraintSystem::<Fp>::new();
        let num_inputs = 1usize << num_selector_bits;
        let mut rng = thread_rng();
        let mut a_ints = vec![];
        (0..num_inputs).for_each(|_| {
            a_ints.push(rng.gen_bigint_range(&BigInt::zero(), &Ed25519Fp::modulus()));
        });

        let a_consts = a_ints
            .iter()
            .map(EmulatedFieldElement::<Fp, Ed25519Fp>::from)
            .collect::<Vec<_>>();
        let one = TestConstraintSystem::<Fp>::one();

        let mut conditions: Vec<Vec<bool>> = vec![];
        for i in 0..num_inputs {
            let mut bool_vec = vec![];
            for j in 0..num_selector_bits {
                let bit = (i >> j) & 1 == 1;
                bool_vec.push(bit);
            }
            conditions.push(bool_vec); // little-endian
        }

        for i in 0..num_inputs {
            let condition_bools = &conditions[i];
            let condition_booleans = condition_bools
                .iter()
                .rev() // mux_tree takes slice with MSB first
                .map(|b| Boolean::constant(*b))
                .collect::<Vec<_>>();

            let res = EmulatedFieldElement::<Fp, Ed25519Fp>::mux_tree(
                &mut cs.namespace(|| {
                    format!(
                        "select one of constants a0 to a{} for conditions = {:?}",
                        num_inputs - 1,
                        condition_bools
                    )
                }),
                condition_booleans.iter(),
                &a_consts,
            );
            assert!(res.is_ok());
            if condition_bools.iter().all(|&x| !x) {
                // Number of constraints for a window size and constant inputs
                assert_eq!(cs.num_constraints(), expected_num_constraints);
            }
            let res = res.unwrap();

            let a_const_limbs_vec = a_consts
                .clone()
                .into_iter()
                .map(|a_const| match &a_const.limbs {
                    EmulatedLimbs::Constant(a_const_limbs) => a_const_limbs.clone(),
                    EmulatedLimbs::Allocated(_) => panic!("Unreachable match arm"),
                })
                .collect::<Vec<_>>();

            let res_expected_limbs = &a_const_limbs_vec[i];

            if let EmulatedLimbs::Allocated(res_limbs) = res.limbs {
                for i in 0..res_limbs.len() {
                    cs.enforce(
                        || {
                            format!(
                                "c constant limb {i} equality for condition = {condition_bools:?}"
                            )
                        },
                        |lc| lc + &res_limbs[i].lc(Fp::one()),
                        |lc| lc + one,
                        |lc| lc + (res_expected_limbs[i], one),
                    );
                }
            } else {
                // Execution should not reach this line
                eprintln!("res should have allocated limbs");
                unreachable!();
            }

            if !cs.is_satisfied() {
                eprintln!("{:?}", cs.which_is_unsatisfied());
            }
            assert!(cs.is_satisfied());
        }

        let num_constraints_here = cs.num_constraints();

        let a_vars = a_consts
            .iter()
            .enumerate()
            .map(|(i, a_const)| {
                let a = a_const
                    .allocate_field_element_unchecked(&mut cs.namespace(|| format!("a[{i}]")));
                assert!(a.is_ok());
                a.unwrap()
            })
            .collect::<Vec<_>>();

        for i in 0..num_inputs {
            let condition_bools = &conditions[i];
            let condition_booleans = condition_bools
                .iter()
                .rev() // mux_tree takes slice with MSB first
                .map(|b| Boolean::constant(*b))
                .collect::<Vec<_>>();

            let res = EmulatedFieldElement::<Fp, Ed25519Fp>::mux_tree(
                &mut cs.namespace(|| {
                    format!(
                        "select one of variables a0 to a{} for conditions = {:?}",
                        num_inputs - 1,
                        condition_bools
                    )
                }),
                condition_booleans.iter(),
                &a_vars,
            );
            assert!(res.is_ok());
            if condition_bools.iter().all(|&x| !x) {
                // Number of constraints for a window size and variable inputs
                assert_eq!(
                    cs.num_constraints() - num_constraints_here,
                    expected_num_constraints
                );
            }
            let res = res.unwrap();

            let a_var_limbs_vec = a_vars
                .clone()
                .into_iter()
                .map(|a_var| match &a_var.limbs {
                    EmulatedLimbs::Allocated(a_var_limbs) => a_var_limbs.clone(),
                    EmulatedLimbs::Constant(_) => panic!("Unreachable match arm"),
                })
                .collect::<Vec<_>>();

            let res_expected_limbs = &a_var_limbs_vec[i];

            if let EmulatedLimbs::Allocated(res_limbs) = res.limbs {
                for i in 0..res_limbs.len() {
                    cs.enforce(
                        || {
                            format!(
                                "c variable limb {i} equality for condition = {condition_bools:?}"
                            )
                        },
                        |lc| lc + &res_limbs[i].lc(Fp::one()),
                        |lc| lc + one,
                        |lc| lc + &res_expected_limbs[i].lc(Fp::one()),
                    );
                }
            } else {
                // Execution should not reach this line
                eprintln!("res should have allocated limbs");
                unreachable!();
            }

            if !cs.is_satisfied() {
                eprintln!("{:?}", cs.which_is_unsatisfied());
            }
            assert!(cs.is_satisfied());
        }
    }

    #[test]
    fn test_const_ops() {
        let mut cs = TestConstraintSystem::<Fp>::new();
        let mut rng = thread_rng();
        let a_int = rng.gen_bigint_range(&BigInt::zero(), &Ed25519Fp::modulus());
        let b_int = rng.gen_bigint_range(&BigInt::zero(), &Ed25519Fp::modulus());
        let a_const = EmulatedFieldElement::<Fp, Ed25519Fp>::from(&a_int);
        let b_const = EmulatedFieldElement::<Fp, Ed25519Fp>::from(&b_int);
        assert!(a_const.is_constant());
        assert!(b_const.is_constant());

        // mul
        let prod_int = (&a_int * &b_int).rem(&Ed25519Fp::modulus());
        let prod_const_res = a_const.mul(&mut cs.namespace(|| "mul"), &b_const).unwrap();
        let prod_const = EmulatedFieldElement::<Fp, Ed25519Fp>::from(&prod_int);
        assert!(prod_const_res.is_constant());
        assert!(prod_const.is_constant());
        EmulatedFieldElement::<Fp, Ed25519Fp>::assert_is_equal(
            &mut cs.namespace(|| "mul assert"),
            &prod_const,
            &prod_const_res,
        )
        .unwrap();

        // add
        let add_int = (&a_int + &b_int).rem(&Ed25519Fp::modulus());
        let add_const_res = a_const.add(&mut cs.namespace(|| "add"), &b_const).unwrap();
        let add_const = EmulatedFieldElement::<Fp, Ed25519Fp>::from(&add_int);
        assert!(add_const_res.is_constant());
        assert!(add_const.is_constant());
        EmulatedFieldElement::<Fp, Ed25519Fp>::assert_is_equal(
            &mut cs.namespace(|| "add assert"),
            &add_const,
            &add_const_res,
        )
        .unwrap();

        // sub
        let sub_int = if a_int >= b_int {
            &a_int - &b_int
        } else {
            &Ed25519Fp::modulus() + &a_int - &b_int
        };
        let sub_int = sub_int.rem(&Ed25519Fp::modulus());
        let sub_const_res = a_const.sub(&mut cs.namespace(|| "sub1"), &b_const).unwrap();
        let sub_const = EmulatedFieldElement::<Fp, Ed25519Fp>::from(&sub_int);
        assert!(sub_const_res.is_constant());
        assert!(sub_const.is_constant());
        EmulatedFieldElement::<Fp, Ed25519Fp>::assert_is_equal(
            &mut cs.namespace(|| "sub1 assert"),
            &sub_const,
            &sub_const_res,
        )
        .unwrap();

        // sub reversed
        let sub_int = if b_int >= a_int {
            &b_int - &a_int
        } else {
            &Ed25519Fp::modulus() + &b_int - &a_int
        };
        let sub_int = sub_int.rem(&Ed25519Fp::modulus());
        let sub_const_res = b_const.sub(&mut cs.namespace(|| "sub2"), &a_const).unwrap();
        let sub_const = EmulatedFieldElement::<Fp, Ed25519Fp>::from(&sub_int);
        assert!(sub_const_res.is_constant());
        assert!(sub_const.is_constant());
        EmulatedFieldElement::<Fp, Ed25519Fp>::assert_is_equal(
            &mut cs.namespace(|| "sub2 assert"),
            &sub_const,
            &sub_const_res,
        )
        .unwrap();

        if !cs.is_satisfied() {
            println!("{:?}", cs.which_is_unsatisfied());
        }
        assert!(cs.is_satisfied());
        assert_eq!(cs.num_constraints(), 0);
    }

    #[test]
    fn test_sgn0() {
        let mut cs = TestConstraintSystem::<Fp>::new();
        let zero = EmulatedFieldElement::<Fp, Ed25519Fp>::zero()
            .sgn0(&mut cs.namespace(|| "sgn0(0)"))
            .unwrap();
        assert!(matches!(zero, Boolean::Constant(false)));
        let one = EmulatedFieldElement::<Fp, Ed25519Fp>::one()
            .sgn0(&mut cs.namespace(|| "sgn0(1)"))
            .unwrap();
        assert!(matches!(one, Boolean::Constant(true)));
        let neg_one = EmulatedFieldElement::<Fp, Ed25519Fp>::one()
            .neg(&mut cs.namespace(|| "-1"))
            .unwrap();
        let neg_one = neg_one.sgn0(&mut cs.namespace(|| "sgn0(-1)")).unwrap();
        assert!(matches!(neg_one, Boolean::Constant(false)));
        let neg_zero = EmulatedFieldElement::<Fp, Ed25519Fp>::zero()
            .neg(&mut cs.namespace(|| "-0"))
            .unwrap();
        let neg_zero = neg_zero.sgn0(&mut cs.namespace(|| "sgn0(-0)")).unwrap();
        assert!(matches!(neg_zero, Boolean::Constant(false)));

        // p-1 / 2
        let p_m1_over2 = EmulatedFieldElement::<Fp, Ed25519Fp>::from(
            &((Ed25519Fp::modulus() - BigInt::from(1)) / BigInt::from(2)),
        );
        let p_p1_over2 = p_m1_over2
            .add(
                &mut cs.namespace(|| "p-1_over2 + 1"),
                &EmulatedFieldElement::<Fp, Ed25519Fp>::one(),
            )
            .unwrap();
        let neg_p_p1_over2 = p_p1_over2
            .neg(&mut cs.namespace(|| "-(p-1_over2+1)"))
            .unwrap();
        let p_m1_over2 = p_m1_over2
            .sgn0(&mut cs.namespace(|| "sgn0(p-1_over2)"))
            .unwrap();
        assert!(matches!(p_m1_over2, Boolean::Constant(false)));
        let p_p1_over2 = p_p1_over2
            .sgn0(&mut cs.namespace(|| "sgn0(p-1_over2+1)"))
            .unwrap();
        assert!(matches!(p_p1_over2, Boolean::Constant(true)));
        let neg_p_p1_over2 = neg_p_p1_over2
            .sgn0(&mut cs.namespace(|| "sgn0(-(p-1_over2+1))"))
            .unwrap();
        Boolean::enforce_equal(
            &mut cs.namespace(|| "-(p-1_over2+1) == p_m1_over2"),
            &neg_p_p1_over2,
            &p_m1_over2,
        )
        .unwrap();

        if !cs.is_satisfied() {
            eprintln!("{:?}", cs.which_is_unsatisfied())
        }
        assert!(cs.is_satisfied());
        assert_eq!(cs.scalar_aux().len(), 0);
        assert_eq!(cs.num_constraints(), 0);
    }

    //////////////////////////////////////////
    /// Tests for emulating Bn254's Fr
    struct Bn254Fr;
    impl EmulatedFieldParams for Bn254Fr {
        fn num_limbs() -> usize {
            16
        }

        fn bits_per_limb() -> usize {
            16
        }

        fn modulus() -> BigInt {
            BigInt::parse_bytes(
                b"2523648240000001BA344D8000000007FF9F800000000010A10000000000000D",
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

    #[test]
    fn test_mul_bn254() {
        let mut cs = TestConstraintSystem::<Fr>::new();
        let mut rng = thread_rng();
        let a_int = rng.gen_bigint_range(&BigInt::zero(), &Bn254Fr::modulus());
        let b_int = rng.gen_bigint_range(&BigInt::zero(), &Bn254Fr::modulus());
        let prod_int = (&a_int * &b_int).rem(&Bn254Fr::modulus());

        let a_const = EmulatedFieldElement::<Fr, Bn254Fr>::from(&a_int);
        let b_const = EmulatedFieldElement::<Fr, Bn254Fr>::from(&b_int);
        let prod_const = EmulatedFieldElement::<Fr, Bn254Fr>::from(&prod_int);

        let a = a_const.allocate_field_element_unchecked(&mut cs.namespace(|| "a"));
        let b = b_const.allocate_field_element_unchecked(&mut cs.namespace(|| "b"));
        let prod = prod_const.allocate_field_element_unchecked(&mut cs.namespace(|| "prod"));
        assert!(a.is_ok());
        assert!(b.is_ok());
        assert!(prod.is_ok());
        let a = a.unwrap();
        let b = b.unwrap();
        let prod = prod.unwrap();

        let prod_calc = a.mul(&mut cs.namespace(|| "a * b"), &b);
        assert!(prod_calc.is_ok());
        let prod_calc = prod_calc.unwrap();

        let res = EmulatedFieldElement::<Fr, Bn254Fr>::assert_is_equal(
            &mut cs.namespace(|| "check equality"),
            &prod_calc,
            &prod,
        );
        assert!(res.is_ok());

        if !cs.is_satisfied() {
            println!("{:?}", cs.which_is_unsatisfied());
        }
        assert!(cs.is_satisfied());
        assert_eq!(cs.num_constraints(), 370);
    }    

    #[test]
    fn test_m_check_bn254_noconvert() {
        let mut cs = TestConstraintSystem::<Fp>::new();
        let mut rng = thread_rng();
        let q0_int = rng.gen_bigint_range(&BigInt::zero(), &BigInt::from_u128(u128::MAX).unwrap());
        let q1_int = rng.gen_bigint_range(&BigInt::zero(), &BigInt::from_u128(u128::MAX).unwrap());
        let e1_int = rng.gen_bigint_range(&BigInt::zero(), &BigInt::from_u128(u128::MAX).unwrap());
        let e2_int = rng.gen_bigint_range(&BigInt::zero(), &BigInt::from_u128(u128::MAX).unwrap());
        let z_int = rng.gen_bigint_range(&BigInt::zero(), &Bn254Fr::modulus());
        let prod_int = (&q0_int + &q1_int*&e1_int + &z_int*&e2_int).rem(&Bn254Fr::modulus());

        let q0_const = EmulatedFieldElement::<Fp, Bn254Fr>::from(&q0_int);
        let q1_const = EmulatedFieldElement::<Fp, Bn254Fr>::from(&q1_int);
        let e1_const = EmulatedFieldElement::<Fp, Bn254Fr>::from(&e1_int);
        let e2_const = EmulatedFieldElement::<Fp, Bn254Fr>::from(&e2_int);
        let z_const = EmulatedFieldElement::<Fp, Bn254Fr>::from(&z_int);
        let prod_const = EmulatedFieldElement::<Fp, Bn254Fr>::from(&prod_int);

        let q0 = q0_const.allocate_field_element_unchecked(&mut cs.namespace(|| "q0")).unwrap();
        let q1 = q1_const.allocate_field_element_unchecked(&mut cs.namespace(|| "q1")).unwrap();
        let e1 = e1_const.allocate_field_element_unchecked(&mut cs.namespace(|| "e1")).unwrap();
        let e2 = e2_const.allocate_field_element_unchecked(&mut cs.namespace(|| "e2")).unwrap();        
        let z = z_const.allocate_field_element_unchecked(&mut cs.namespace(|| "z")).unwrap();
        let prod = prod_const.allocate_field_element_unchecked(&mut cs.namespace(|| "prod")).unwrap();
        
        let tmp = e1.mul(&mut cs.namespace(||"e1*q1"), &q1).unwrap();
        let tmp2 = e2.mul(&mut cs.namespace(||"e2*z"), &z).unwrap();
        let tmp3 = tmp.add(&mut cs.namespace(||"tmp + tmp2"), &tmp2).unwrap();
        let prod_calc = q0.add(&mut cs.namespace(||"q0 + tmp3"), &tmp3).unwrap();

        let res = EmulatedFieldElement::<Fp, Bn254Fr>::assert_is_equal(
            &mut cs.namespace(|| "check equality"),
            &prod_calc,
            &prod,
        );
        assert!(res.is_ok());

        if !cs.is_satisfied() {
            println!("{:?}", cs.which_is_unsatisfied());
        }
        assert!(cs.is_satisfied());
        assert_eq!(cs.num_constraints(), 407);
    }     

    #[test]
    fn test_m_check_bn254() {
        let mut cs = TestConstraintSystem::<Fp>::new();
        let mut rng = thread_rng();

        let q0_fp = Fp::random(&mut rng);
        let q1_fp = Fp::random(&mut rng);
        let z_fp = Fp::random(&mut rng);
        
        let q0_int = scalar_to_bigint(&q0_fp);
        let q1_int = scalar_to_bigint(&q1_fp);
        let z_int = scalar_to_bigint(&z_fp);
        
        let e1_int = rng.gen_bigint_range(&BigInt::zero(), &Bn254Fr::modulus());
        let e2_int = rng.gen_bigint_range(&BigInt::zero(), &Bn254Fr::modulus());
        
        let res_int = (&q0_int + &q1_int*&e1_int + &z_int*&e2_int).rem(&Bn254Fr::modulus());

        let e1_const = EmulatedFieldElement::<Fp, Bn254Fr>::from(&e1_int);
        let e2_const = EmulatedFieldElement::<Fp, Bn254Fr>::from(&e2_int);
        let res_const = EmulatedFieldElement::<Fp, Bn254Fr>::from(&res_int);

        let q0_alloc = AllocatedNum::<Fp>::alloc(&mut cs.namespace(||"alloc q0"), || Ok(q0_fp)).unwrap();
        let q1_alloc = AllocatedNum::<Fp>::alloc(&mut cs.namespace(||"alloc q1"), || Ok(q1_fp)).unwrap();
        let z_alloc = AllocatedNum::<Fp>::alloc(&mut cs.namespace(||"alloc z"), || Ok(z_fp)).unwrap();

        let q0 = allocated_num_to_emulated_fe(&mut cs.namespace(||"convert q0"), &q0_alloc).unwrap();
        let q1 = allocated_num_to_emulated_fe(&mut cs.namespace(||"convert q1"), &q1_alloc).unwrap();
        let z = allocated_num_to_emulated_fe(&mut cs.namespace(||"convert z"), &z_alloc).unwrap();
        let e1 = e1_const.allocate_field_element_unchecked(&mut cs.namespace(|| "e1")).unwrap();
        let e2 = e2_const.allocate_field_element_unchecked(&mut cs.namespace(|| "e2")).unwrap();        
        let res = res_const.allocate_field_element_unchecked(&mut cs.namespace(|| "res")).unwrap();
        
        let tmp = e1.mul(&mut cs.namespace(||"e1*q1"), &q1).unwrap();
        let tmp2 = e2.mul(&mut cs.namespace(||"e2*z"), &z).unwrap();
        let tmp3 = tmp.add(&mut cs.namespace(||"tmp + tmp2"), &tmp2).unwrap();
        let res_calc = q0.add(&mut cs.namespace(||"q0 + tmp3"), &tmp3).unwrap();

        let res = EmulatedFieldElement::<Fp, Bn254Fr>::assert_is_equal(
            &mut cs.namespace(|| "check equality"),
            &res_calc,
            &res,
        );
        assert!(res.is_ok());

        if !cs.is_satisfied() {
            println!("{:?}", cs.which_is_unsatisfied());
        }
        assert!(cs.is_satisfied());
        assert_eq!(cs.num_constraints(), 1226);
    }

    fn allocated_bits_to_emulated_fe<CS, F1, EFP>(mut cs: CS, a : &[AllocatedBit]) 
    -> Result<EmulatedFieldElement<F1, EFP>, SynthesisError>
        where 
        CS: ConstraintSystem<F1>,
        F1: PrimeFieldBits,
        EFP: EmulatedFieldParams
    {
        assert!(!a.is_empty());

        // Make vector of limbs (F1 values used to emulate F2)
        let mut limbs : Vec<Num<F1>> = Vec::with_capacity(16);
        let num_limbs = (a.len()-1)/EFP::bits_per_limb() + 1;
        
        for i in 0..num_limbs {    // foreach limb
            let bpl = EFP::bits_per_limb();
            let limb_size = if i == num_limbs - 1 && a.len()%bpl!=0 {a.len()%bpl} else {bpl};
            let limb_bits = &a[i*bpl .. i*bpl + limb_size];
            let limb_bits : Vec<Boolean> = limb_bits.iter().map(|x| Boolean::from(x.clone())).collect();
            let limb_i = pack_bits(&mut cs.namespace(|| format!("pack limb {i}")), &limb_bits)?.into();
            limbs.push(limb_i);
        }
        
        for _ in num_limbs .. EFP::num_limbs() {
            limbs.push(Num::zero());
        }
        

        let em_fe = EmulatedFieldElement {
            limbs: EmulatedLimbs::Allocated(limbs),
            overflow: 0,
            internal: true,
            marker: PhantomData,
        };
        
        Ok(em_fe)
    }    

    #[test]
    fn test_allocated_bits_to_emulated_fe() {
        let mut cs = TestConstraintSystem::<Fp>::new();
        let mut rng = thread_rng();
        
        let a_int = rng.gen_bigint_range(&BigInt::zero(), &BigInt::from_u128(u128::MAX).unwrap());
        let a_const = EmulatedFieldElement::<Fp, Bn254Fr>::from(&a_int);
        let a_known = a_const.allocate_field_element_unchecked(&mut cs.namespace(|| "a_known")).unwrap();

        let mut a_bits = vec![];
        for i in 0..a_int.bits() {
            let bit = AllocatedBit::alloc(&mut cs.namespace(||format!("bit {i}")), Some(a_int.bit(i))).unwrap();
            a_bits.push(bit);
        }
        for i in a_int.bits()..128 {
            let bit = AllocatedBit::alloc(&mut cs.namespace(||format!("bit {i}")), Some(false)).unwrap();
            a_bits.push(bit);
        }

        let a = allocated_bits_to_emulated_fe(&mut cs.namespace(||"a_bits to a"), &a_bits).unwrap();

        let res = EmulatedFieldElement::<Fp, Bn254Fr>::assert_is_equal(
            &mut cs.namespace(|| "check equality"),
            &a,
            &a_known,
        );
        assert!(res.is_ok());

        if !cs.is_satisfied() {
            println!("{:?}", cs.which_is_unsatisfied());
        }
        assert!(cs.is_satisfied());
        assert_eq!(cs.num_constraints(), 189);        

    }

}
