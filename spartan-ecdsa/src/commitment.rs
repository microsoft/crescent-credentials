use core::marker::PhantomData;
use bellpepper_core::{boolean::AllocatedBit, num::AllocatedNum, ConstraintSystem, SynthesisError};
use bellpepper::gadgets::boolean::Boolean;
use ff::{PrimeField, PrimeFieldBits};
use num_bigint::{BigUint, RandBigInt, ToBigInt};
//use num_traits::Num;
use std::ops::Rem;
use serde::{Deserialize, Serialize};

use crate::nonnative::bignat::BigNat;
use crate::poseidon::{Poseidon, PoseidonConstantsCircuit, PoseidonCircuit};
use crate::utils::{biguint_to_scalar, le_bits_to_num, mod_inverse, scalar_to_bigint, scalar_to_biguint};


/// Functions related to creating commitments to ECDSA hashes
pub struct Commitment<Scalar>
{
    _p: PhantomData<Scalar>,
} // Empty struct for now, used to group related functions


#[derive(Serialize, Deserialize, Clone)]
/// The private opening data associated to a commitment
pub struct CommitmentOpening {
    /// The commitment (public part)
    pub c: Option<BigUint>,
    /// The randomness k
    pub k: BigUint,
    /// The first 31 bytes of the digest
    pub x: BigUint,
    /// The last byte of the digest
    pub b: u8,
    /// The mask value of the commitment
    pub mask: BigUint
}


impl<Scalar: PrimeField> Commitment<Scalar> {
    const NUM_ABSORBS: usize = 2;
    const NUM_HASH_BITS : usize = 248;

    /// The length of the challenge used to create commitments
    pub const CHALLENGE_BITLEN : usize = 248;    
    /// Size of each limb in the representation of a bignat
    pub const LIMB_WIDTH : usize = 16;
    /// Number of limbs in the representation of a bignat
    pub const N_LIMBS : usize = 16;

    /// Create constants for the commitment scheme (Poseidon constants)
    pub fn create_constants() -> PoseidonConstantsCircuit<Scalar> {
        PoseidonConstantsCircuit::<Scalar>::default()
    }

    /// Commit to the digest h, a 256-bit string as follows.
    /// Let h = x||b where x is the first 248 bits of h, and b is the last byte
    /// To avoid using two commitments (since our field size can't fit the whole 256-bit digest), we commit only the first 248 bits and 
    /// let the prover set the last 8 bits arbitrarily. Since the digest must be signed, and truncating SHA-256 to 248 bits
    /// is collision resistant, this is sound.
    /// This is the first part of creating a commitment, once the challenge is created, call part2
    pub fn commit_digest_part1(constants: &PoseidonConstantsCircuit<Scalar>, h: &BigUint, p: &BigUint) -> CommitmentOpening
    where Scalar: PrimeField + PrimeFieldBits + Serialize + for<'de> Deserialize<'de>,
    {
        let h_bytes = h.to_bytes_be();
        assert_eq!(h_bytes.len(), 32);
        let x = &h_bytes[0..31];
        let b = h_bytes[31];
        let x = BigUint::from_bytes_be(&x);

        let (k, mask) = Self::commit_part1(constants, &x, p);

        CommitmentOpening{c: None, k: k.clone(), x, b, mask}
    }

    /// Second phase of creating a commitment, uses the challenge
    pub fn commit_digest_part2(opening: &CommitmentOpening, challenge: &BigUint, p: &BigUint) -> CommitmentOpening
    {
        let c = Self::commit_part2(challenge, &opening.x, &opening.mask, p);
        let mut new_opening = opening.clone();
        new_opening.c = Some(c);

        new_opening
    }

    // Compute c = r*x + H(k,x) (mod p).  H(k,x) is computed with the Scalar parameter, and is cast as an element mod p
    fn commit_part1(constants: &PoseidonConstantsCircuit<Scalar>, x: &BigUint, p: &BigUint) -> (BigUint, BigUint) 
        where Scalar: PrimeField + PrimeFieldBits + Serialize + for<'de> Deserialize<'de>,
    {
        // Need to make sure k, x fit in both fields; we allow 248-bit values:
        assert!(x.to_radix_le(2).len() <= Self::NUM_HASH_BITS);
        // Need to make sure that Poseidon digests can be larger than p:
        assert!(Scalar::NUM_BITS as u64 > p.bits());

        let x_scalar = biguint_to_scalar(&x);
        let mut rng = rand::thread_rng();
        let hash_len = p.bits() as usize;
        let mut mask;
        let mut k;
        loop {
            // We need a mask value that is uniformly random mod p.  
            // We sample k and compute mask = H(x,k) such the bitlength of mask and p are the same, 
            // and reject values larger than p until we find mask < p.
            // We assert above that the native field (where H/Poseidon is defined) is larger than p.
            k = rng.gen_biguint(Self::NUM_HASH_BITS as u64);
            let k_scalar = biguint_to_scalar(&k);
            let mut poseidon: Poseidon<Scalar> = Poseidon::new(constants.clone(), Self::NUM_ABSORBS);
            poseidon.absorb(k_scalar);
            poseidon.absorb(x_scalar);            

            let mask_scalar = poseidon.squeeze(hash_len);
            mask = scalar_to_biguint(&mask_scalar);
            if mask < *p {
                break;
            }
        }

        (k, mask)
    }   

    fn commit_part2(challenge: &BigUint, x: &BigUint, mask: &BigUint, p: &BigUint) -> BigUint {
        
        let tmp = x*challenge + mask;
        let c = tmp.rem(p);

        c
    } 

    /// Open a commitment.  Input: commitment C, opening (k, h), output h' = C - H(h, r)
    pub fn open_digest(constants: &PoseidonConstantsCircuit<Scalar>, opening: CommitmentOpening, r: &BigUint, p: &BigUint) -> BigUint
        where Scalar: PrimeField + PrimeFieldBits + Serialize + for<'de> Deserialize<'de>,
    {
        let mut poseidon: Poseidon<Scalar> = Poseidon::new(constants.clone(), Self::NUM_ABSORBS);
        poseidon.absorb(biguint_to_scalar(&opening.k));
        poseidon.absorb(biguint_to_scalar(&opening.x)); 
        let digest = poseidon.squeeze(p.bits() as usize);
        let mask = scalar_to_bigint(&digest);

        assert!(opening.c.is_some());
        let c = opening.c.unwrap().to_bigint().unwrap();
        let r_inv = mod_inverse(r, p).to_bigint().unwrap();
        let p = p.to_bigint().unwrap();
        let tmp = (c - mask + &p).rem(&p);
        let xPrime = (tmp*r_inv).rem(&p);
        assert_eq!(opening.x.to_bigint().unwrap(), xPrime);

        let hPrime = BigUint::from(opening.b) + xPrime.to_biguint().unwrap() * BigUint::from(256 as u32);

        hPrime
    }     
}

pub(crate) struct CommitmentGadget<Scalar>{
    _p: PhantomData<Scalar>,
}

impl<Scalar> CommitmentGadget<Scalar> {

    #[allow(unused)]
    fn truncate<CS: ConstraintSystem<Scalar>>(mut cs: CS, x: &AllocatedNum<Scalar>, num_bits: usize) -> Result<AllocatedNum<Scalar>, SynthesisError>
    where Scalar: PrimeField + PrimeFieldBits + Serialize + for<'de> Deserialize<'de>,
    {
        let x_bits = x
        .to_bits_le(&mut cs.namespace(|| "to_bits"))?
        .iter()
        .map(|boolean| match boolean {
          Boolean::Is(ref x) => x.clone(),
          _ => panic!("Wrong type of input. We should have never reached there"),
        })
        .collect::<Vec<AllocatedBit>>();

        le_bits_to_num(&mut cs.namespace(||"Convert truncated x bits to num"), &x_bits[..num_bits])

    }

    // Create an AllocatedNum that is constrained to be one byte
    fn alloc_byte<CS: ConstraintSystem<Scalar>>(
        mut cs: CS, 
        b : Option<u8>
    ) -> Result<AllocatedNum<Scalar>, SynthesisError>
        where Scalar: PrimeField
    {
        // TODO: BUG Cheating for now; need to constrain length of b
        let b_res = if b.is_some() {
            Ok(Scalar::from(b.unwrap() as u64))
        } else {
            Err(SynthesisError::AssignmentMissing)
        };

        AllocatedNum::alloc(&mut cs.namespace(||"alloc b"), ||b_res)
    }

    pub fn build_digest<CS: ConstraintSystem<Scalar>>(
        mut cs: CS, 
        constants: &PoseidonConstantsCircuit<Scalar>,
        c: &BigNat<Scalar>, 
        r: &BigNat<Scalar>,
        p: &BigNat<Scalar>,
        p_bitlen: usize,
        k:  &AllocatedNum<Scalar>, 
        x:  &AllocatedNum<Scalar>, 
        b: Option<u8>
        ) -> Result<AllocatedNum<Scalar>, SynthesisError>
    where Scalar: PrimeField + PrimeFieldBits + Serialize + for<'de> Deserialize<'de>,
    {
        // output h = x||b, x is input and b can be anything constrained only to be 8 bits long
        let x = Self::open(&mut cs.namespace(||"Open commitment to x"), constants, c, r, p, p_bitlen, k, x)?;

        // Compute h = x||b
        let h = AllocatedNum::<Scalar>::alloc(&mut cs.namespace(||"alloc h"), || {
            if x.get_value().is_some() && b.is_some() {
                let h = x.get_value().unwrap() * Scalar::from(256) + Scalar::from(b.unwrap() as u64);
                Ok(h)
            } else {
                Err(SynthesisError::AssignmentMissing)
            }
        })?;

        let b_alloc = Self::alloc_byte(&mut cs.namespace(||"Allocate b, constrain to be a byte"), b)?;        
        let shift = AllocatedNum::alloc(&mut cs.namespace(||"alloc 256"), ||Ok(Scalar::from(256)))?;
        cs.enforce(
            || "Enforce h = x*256 + b", 
            |lc| lc + x.get_variable(), 
            |lc| lc + shift.get_variable(),
            |lc| lc + h.get_variable() - b_alloc.get_variable()
        );

        Ok(h)
    }    
   
    fn allocated_to_bignat<CS: ConstraintSystem<Scalar>>(mut cs: CS, x: &AllocatedNum<Scalar>)
        -> Result<BigNat<Scalar>, SynthesisError> 
    where Scalar: PrimeField
    {
        // TODO: BUG Convert digest properly; from AllocatedNum<Scalar> to BigNat<Scalar>; For now we cheat
        let x_bigint_res = {
            if x.get_value().is_some() {
                    Ok(scalar_to_bigint(&x.get_value().unwrap()))
            }
            else {
                Err(SynthesisError::AssignmentMissing)
            }
        };
        
        BigNat::alloc_from_nat(cs.namespace(||"alloc x"), ||x_bigint_res, Commitment::<Scalar>::LIMB_WIDTH, Commitment::<Scalar>::N_LIMBS)

    }

    fn open<CS: ConstraintSystem<Scalar>>(
        mut cs: CS,
        constants: &PoseidonConstantsCircuit<Scalar>,
        c: &BigNat<Scalar>, 
        r: &BigNat<Scalar>,
        p: &BigNat<Scalar>,
        p_bitlen: usize,
        k: &AllocatedNum<Scalar>,
        x: &AllocatedNum<Scalar>, 
        ) -> Result<AllocatedNum<Scalar>, SynthesisError>
    where Scalar: PrimeField + PrimeFieldBits + Serialize + for<'de> Deserialize<'de>,
    {
        let mut poseidon: PoseidonCircuit<Scalar> = PoseidonCircuit::new(constants.clone(), Commitment::<Scalar>::NUM_ABSORBS);
        poseidon.absorb(k);
        poseidon.absorb(x);
        let digest = poseidon.squeeze(&mut cs.namespace(||"squeeze"), p_bitlen)?;

        // Recompute c' from x,r,k, c = x*r + H(x,k), ensure c' = c
        let digest_bn = Self::allocated_to_bignat(&mut cs.namespace(||"convert digest"), &digest)?;
        let x_bn = Self::allocated_to_bignat(&mut cs.namespace(||"convert x"), &x)?;

        let (_, tmp) = x_bn.mult_mod(&mut cs.namespace(||"x*r"), &r, &p)?;
        let tmp = tmp.add(&digest_bn)?;
        let cPrime = tmp.red_mod(&mut cs.namespace(||"reduce x*r + digest"), &p)?;

        cPrime.equal_when_carried(&mut cs.namespace(||"cPrime =? c"), c)?;

        Ok(x.clone())
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::{RandBigInt, ToBigInt};
    use num_traits::Num;
    use halo2curves::secp256k1::Fp as Scalar;
    use bellpepper_core::test_cs::TestConstraintSystem;

  #[test]
  fn test_commit_digest() {
    let mut rng = rand::thread_rng();
    let h = BigUint::from_str_radix("115792089237316195423570985008687907853269984665640564039457584007913129639680", 10).unwrap(); // 256-bit, 248 ones followed by 8 zeros
    let x = BigUint::from_str_radix("452312848583266388373324160190187140051835877600158453279131187530910662655", 10).unwrap(); // 248 ones
    let challenge = rng.gen_biguint(Commitment::<Scalar>::CHALLENGE_BITLEN as u64);
    let p_bn254 = BigUint::from_str_radix("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", 16).unwrap();     // 254 bits

    let constants = Commitment::<Scalar>::create_constants();
     
    let opening = Commitment::commit_digest_part1(&constants, &h, &p_bn254);
    assert_eq!(0u8, opening.b);
    assert_eq!(x, opening.x);

    let opening = Commitment::<Scalar>::commit_digest_part2(&opening, &challenge, &p_bn254);

    let hPrime = Commitment::open_digest(&constants, opening, &challenge, &p_bn254);
    assert_eq!(h, hPrime);
  }  

  #[test]
  fn test_commitment_gadget()
  {
    let mut rng = rand::thread_rng();
    let h = BigUint::from_str_radix("115792089237316195423570985008687907853269984665640564039457584007913129639680", 10).unwrap(); // 256-bit, 248 ones followed by 8 zeros
    let b = 0u8;
    let x = BigUint::from_str_radix("452312848583266388373324160190187140051835877600158453279131187530910662655", 10).unwrap(); // 248 ones
    let challenge = rng.gen_biguint(Commitment::<Scalar>::CHALLENGE_BITLEN as u64);
    let p_bn254 = BigUint::from_str_radix("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", 16).unwrap();     // 254 bits
    let constants = Commitment::<Scalar>::create_constants();
    let limb_width = Commitment::<Scalar>::LIMB_WIDTH;
    let n_limbs = Commitment::<Scalar>::N_LIMBS;
    
    let (k, mask) = Commitment::commit_part1(&constants, &x, &p_bn254);
    let c = Commitment::<Scalar>::commit_part2(&challenge, &x, &mask, &p_bn254);

    // Suppose the prover has created k, x, c, r, h, b as above.
    // Now in the circuit we want to prove that
    // h = x||b   and   c = x + H(k||x)
    let mut cs = TestConstraintSystem::<Scalar>::new();    
    
    // k and x are AllocatedNums
    let k_alloc = AllocatedNum::alloc(&mut cs.namespace(||"k"), ||Ok(biguint_to_scalar(&k))).unwrap();
    let x_alloc = AllocatedNum::alloc(&mut cs.namespace(||"x"), ||Ok(biguint_to_scalar(&x))).unwrap();

    //c, r, p as BigNats
    let c_alloc = BigNat::alloc_from_nat(cs.namespace(||"alloc c"), ||Ok(c.to_bigint().unwrap()), limb_width, n_limbs).unwrap();
    let r_alloc = BigNat::alloc_from_nat(cs.namespace(||"alloc r"), ||Ok(challenge.to_bigint().unwrap()), limb_width, n_limbs).unwrap();
    let p_alloc = BigNat::alloc_from_nat(cs.namespace(||"alloc p"), ||Ok(p_bn254.to_bigint().unwrap()), limb_width, n_limbs).unwrap();

    let constants = Commitment::create_constants();
    let hPrime_alloc = CommitmentGadget::build_digest(cs.namespace(||"build_digest"), &constants, &c_alloc, &r_alloc, &p_alloc, p_bn254.bits() as usize, &k_alloc, &x_alloc, Some(b)).unwrap();

    let h_alloc = AllocatedNum::alloc(&mut cs.namespace(||"hPrime known"), ||Ok(biguint_to_scalar(&h))).unwrap();

    cs.enforce(
        || "hPrime*1 = hPrime known", 
        |lc| lc + hPrime_alloc.get_variable(), 
        |lc| lc + TestConstraintSystem::<Scalar>::one(),
        |lc| lc + h_alloc.get_variable()
    );    

    assert!(cs.is_satisfied());

    assert_eq!(cs.num_constraints(), 2008); // was 1512

    // Poseidon is about 250 const/block, we do one hash with two blocks, that accounts for about ~500 constraints
    // The non-native arithmetic is about 1500 constraints
    //println!("{}", cs.pretty_print());
  }  

}