use std::ops::Rem;
use bellpepper::gadgets::multipack::pack_bits;
use bellpepper_core::boolean::AllocatedBit;
use bellpepper_core::num::{AllocatedNum, Num};
use bellpepper_core::{ConstraintSystem, LinearCombination, SynthesisError, Variable};
use ff::{PrimeField, PrimeFieldBits};
use num_bigint::BigInt;
use num_traits::{One, Signed, Zero};
use crate::emulated::field_element::{EmulatedFieldParams,EmulatedFieldElement, EmulatedLimbs};
use std::marker::PhantomData;

/// Range check a Num
pub fn range_check_num<F, CS>(
    cs: &mut CS,
    num: &Num<F>,
    num_bits: usize,
) -> Result<(), SynthesisError>
where
    F: PrimeFieldBits,
    CS: ConstraintSystem<F>,
{
    range_check_lc(cs, &num.lc(F::ONE), num.get_value(), num_bits)
}

/// Range check an expression represented by a LinearCombination
///
/// From `fits_in_bits` of `bellperson-nonnative`
pub fn range_check_lc<F, CS>(
    cs: &mut CS,
    lc_input: &LinearCombination<F>,
    lc_value: Option<F>,
    num_bits: usize,
) -> Result<(), SynthesisError>
where
    F: PrimeFieldBits,
    CS: ConstraintSystem<F>,
{
    let value_bits = lc_value.map(|v| v.to_le_bits());

    // Allocate all but the first bit.
    let bits: Vec<Variable> = (1..num_bits)
        .map(|i| {
            cs.alloc(
                || format!("bit {i}"),
                || {
                    if let Some(bits) = &value_bits {
                        let r = if bits[i] { F::ONE } else { F::ZERO };
                        Ok(r)
                    } else {
                        Err(SynthesisError::AssignmentMissing)
                    }
                },
            )
        })
        .collect::<Result<_, _>>()?;

    for (i, v) in bits.iter().enumerate() {
        cs.enforce(
            || format!("bit {i} is bit"),
            |lc| lc + *v,
            |lc| lc + CS::one() - *v,
            |lc| lc,
        )
    }

    // Last bit
    cs.enforce(
        || "last bit of variable is a bit".to_string(),
        |mut lc| {
            let mut f = F::ONE;
            lc = lc + lc_input;
            for v in bits.iter() {
                f = f.double();
                lc = lc - (f, *v);
            }
            lc
        },
        |mut lc| {
            lc = lc + CS::one();
            let mut f = F::ONE;
            lc = lc - lc_input;
            for v in bits.iter() {
                f = f.double();
                lc = lc + (f, *v);
            }
            lc
        },
        |lc| lc,
    );

    Ok(())
}

/// Range check a constant field element
pub fn range_check_constant<F>(value: F, num_bits: usize) -> Result<(), SynthesisError>
where
    F: PrimeFieldBits,
{
    let value_bits = value.to_le_bits();
    let mut res = F::ZERO;
    let mut coeff = F::ONE;
    for i in 0..num_bits {
        if value_bits[i] {
            res += coeff;
        }
        coeff = coeff.double();
    }
    if res != value {
        eprintln!("value does not fit in the required number of bits");
        return Err(SynthesisError::Unsatisfiable);
    }

    Ok(())
}

/// Check that a Num equals a constant and return a bit
///
/// Based on `alloc_num_equals` in `Nova/src/gadgets/utils.rs`
pub fn alloc_num_equals_constant<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    a: &Num<F>,
    b: F,
) -> Result<AllocatedBit, SynthesisError> {
    // Allocate and constrain `r`: result boolean bit.
    // It equals `true` if `a` equals `b`, `false` otherwise
    let a_value = a.get_value().ok_or(SynthesisError::AssignmentMissing)?;
    let r = AllocatedBit::alloc(cs.namespace(|| "r"), Some(a_value == b))?;

    // Allocate t s.t. t=1 if a == b else 1/(a - b)
    let t_value = if a_value == b {
        F::ONE
    } else {
        (a_value - b).invert().unwrap()
    };
    let t = AllocatedNum::alloc(cs.namespace(|| "t"), || Ok(t_value))?;

    cs.enforce(
        || "t*(a - b) = 1 - r",
        |lc| lc + t.get_variable(),
        |lc| lc + &a.lc(F::ONE) - &LinearCombination::from_coeff(CS::one(), b),
        |lc| lc + CS::one() - r.get_variable(),
    );

    cs.enforce(
        || "r*(a - b) = 0",
        |lc| lc + r.get_variable(),
        |lc| lc + &a.lc(F::ONE) - &LinearCombination::from_coeff(CS::one(), b),
        |lc| lc,
    );

    Ok(r)
}

/// Convert a non-negative BigInt into a field element
pub fn bigint_to_scalar<F>(value: &BigInt) -> F
where
    F: PrimeFieldBits,
{
    assert!(value.bits() as u32 <= F::CAPACITY);
    assert!(!value.is_negative());

    let mut base = F::from(u64::MAX);
    base += F::ONE; // 2^64 in the field
    let mut coeff = F::ONE;
    let mut res = F::ZERO;

    let (_sign, digits) = value.to_u64_digits();
    for d in digits.into_iter() {
        let d_f = F::from(d);
        res += d_f * coeff;
        coeff *= base;
    }
    res
}

/// Construct a [BigInt] from a vector of [BigInt] limbs with base equal to 2^num_bits_per_limb
pub fn recompose(limbs: &[BigInt], num_bits_per_limb: usize) -> Result<BigInt, SynthesisError> {
    if limbs.is_empty() {
        eprintln!("Empty input");
        return Err(SynthesisError::Unsatisfiable);
    }

    let mut res = BigInt::zero();
    for i in 0..limbs.len() {
        res <<= num_bits_per_limb;
        res += &limbs[limbs.len() - i - 1];
    }
    Ok(res)
}

/// Decompose a [BigInt] into a vector of [BigInt] limbs each occupying `num_bits_per_limb` bits.
pub fn decompose(
    input: &BigInt,
    num_bits_per_limb: usize,
    num_limbs: usize,
) -> Result<Vec<BigInt>, SynthesisError> {
    if input.bits() as usize > num_limbs * num_bits_per_limb {
        eprintln!("Not enough limbs to represent input {:?}", input);
        return Err(SynthesisError::Unsatisfiable);
    }

    let mut res = vec![BigInt::zero(); num_limbs];
    let base = BigInt::one() << num_bits_per_limb;
    let mut tmp = input.clone();
    for r in res.iter_mut() {
        *r = tmp.clone().rem(&base);
        tmp >>= num_bits_per_limb;
    }
    Ok(res)
}


pub fn allocated_num_to_emulated_fe<CS, F1, EFP>(mut cs: CS, a : &AllocatedNum<F1>) 
-> Result<EmulatedFieldElement<F1, EFP>, SynthesisError>
    where 
    CS: ConstraintSystem<F1>,
    F1: PrimeFieldBits,
    EFP: EmulatedFieldParams
{
    let a_bits = a.to_bits_le(&mut cs.namespace(||"a bits"))?;  
    // Make vector of limbs (F1 values used to emulate F2)
    let mut limbs : Vec<Num<F1>> = Vec::with_capacity(16);
    let n_limbs = EFP::num_limbs();
    let limb_size = EFP::bits_per_limb();
    for i in 0..n_limbs {    // foreach limb
        let this_limb_size = if i == n_limbs - 1 && a_bits.len() % limb_size != 0{
            a_bits.len()%limb_size
        } else {
            limb_size
        };
        let limb_bits = &a_bits[i*limb_size .. i*limb_size + this_limb_size];
        let limb_i = pack_bits(&mut cs.namespace(|| format!("pack limb {}", i)), limb_bits)?.into();
        limbs.push(limb_i);
    }

    let em_fe = EmulatedFieldElement {
        limbs: EmulatedLimbs::Allocated(limbs),
        overflow: 0,
        internal: true,
        marker: PhantomData,
    };

    Ok(em_fe)
}    