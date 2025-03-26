use std::ops::{Div, Rem};

use bellpepper_core::{ConstraintSystem, SynthesisError};
use ff::PrimeFieldBits;
use num_bigint::BigInt;
use num_traits::Zero;

use crate::emulated::field_element::EmulatedLimbs;
use crate::emulated::util::{bigint_to_scalar, decompose};
use crate::emulated::{field_element::EmulatedFieldElement, field_element::EmulatedFieldParams};

impl<F, P> EmulatedFieldElement<F, P>
where
    F: PrimeFieldBits,
    P: EmulatedFieldParams,
{
    /// Computes the remainder modulo the field modulus
    pub(crate) fn compute_rem<CS>(&self, cs: &mut CS) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<F>,
    {
        let a_int: Option<BigInt> = self.try_into().ok();
        let r_int = a_int.map(|v| v.rem(P::modulus()));

        let res_limbs = Self::allocate_optional_limbs(
            &mut cs.namespace(|| "allocate from remainder value"),
            r_int,
        )?;

        let res = Self::pack_limbs(
            &mut cs.namespace(|| "enforce bitwidths on remainder"),
            res_limbs,
            true,
        )?;
        Ok(res)
    }

    /// Computes the quotient
    pub(crate) fn compute_quotient<CS>(&self, cs: &mut CS) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<F>,
    {
        // TODO: Check the need for the "+ 1"
        let num_res_limbs = (self.len()*P::bits_per_limb() + self.overflow + 1
            - (P::modulus().bits() as usize)    // Deduct the modulus bit size
            + P::bits_per_limb() - 1) /         // This term is to round up to next integer
            P::bits_per_limb();

        let a_int: Option<BigInt> = self.try_into().ok();
        let p = P::modulus();
        let k_int = a_int.map(|v| v.div(p));

        let res_limbs = if let Some(k_int) = k_int {
            let k_int_limbs = decompose(&k_int, P::bits_per_limb(), num_res_limbs)?;
            let res_limb_values: Vec<F> = k_int_limbs
                .into_iter()
                .map(|i| bigint_to_scalar(&i))
                .collect::<Vec<F>>();
            EmulatedLimbs::<F>::allocate_limbs(
                &mut cs.namespace(|| "allocate from quotient value"),
                &res_limb_values,
            )
        } else {
            EmulatedLimbs::<F>::allocate_empty_limbs(
                &mut cs.namespace(|| "allocate from quotient value"),
                num_res_limbs,
            )?
        };

        let res = Self::pack_limbs(
            &mut cs.namespace(|| "enforce bitwidths on quotient"),
            res_limbs,
            false,
        )?;
        Ok(res)
    }

    /// Computes the multiplicative inverse
    pub(crate) fn compute_inverse<CS>(&self, cs: &mut CS) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<F>,
    {
        let p = P::modulus();
        let a_int: Option<BigInt> = self.try_into().ok().map(|v: BigInt| v.rem(&p));
        let a_inv_int = a_int.and_then(|a| {
            if a.is_zero() {
                eprintln!("Inverse of zero element cannot be calculated");
                return None;
            }
            let p_minus_2 = &p - BigInt::from(2);
            // a^(p-1) = 1 mod p for non-zero a. So a^(-1) = a^(p-2)
            Some(a.modpow(&p_minus_2, &p))
        });

        let a_inv_limbs = Self::allocate_optional_limbs(
            &mut cs.namespace(|| "allocate from inverse value"),
            a_inv_int,
        )?;

        let a_inv = Self::pack_limbs(
            &mut cs.namespace(|| "enforce bitwidths on inverse"),
            a_inv_limbs,
            true,
        )?;

        Ok(a_inv)
    }

    /// Computes the ratio modulo the field modulus
    pub(crate) fn compute_ratio<CS>(
        &self,
        cs: &mut CS,
        other: &Self,
    ) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<F>,
    {
        let p = P::modulus();
        let numer_int: Option<BigInt> = self.try_into().ok();
        let denom_int: Option<BigInt> = other.try_into().ok().map(|v: BigInt| v.rem(&p));
        let ratio_int = denom_int.and_then(|denom_int| {
            numer_int.and_then(|numer_int| {
                if denom_int.is_zero() {
                    eprintln!("Inverse of zero element cannot be calculated");
                    return None;
                }
                let p_minus_2 = &p - BigInt::from(2);
                // a^(p-1) = 1 mod p for non-zero a. So a^(-1) = a^(p-2)
                let denom_inv_int = denom_int.modpow(&p_minus_2, &p);
                Some((numer_int * denom_inv_int).rem(&p))
            })
        });

        let ratio_limbs = Self::allocate_optional_limbs(
            &mut cs.namespace(|| "allocate from ratio value"),
            ratio_int,
        )?;

        let ratio = Self::pack_limbs(
            &mut cs.namespace(|| "enforce bitwidths on ratio"),
            ratio_limbs,
            true,
        )?;

        Ok(ratio)
    }
}
