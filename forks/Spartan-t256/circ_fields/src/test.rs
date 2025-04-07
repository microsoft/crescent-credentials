use super::*;
use rand::thread_rng;
use rand::Rng;
use num_bigint::BigInt as Integer;
use num_integer::Integer as NumInteger;
use num_traits::{One, Signed};
use num_primes::Verification;
use num_bigint_02::BigUint as BigUint02;

#[test]
fn inline_signed_bits() {
    assert_eq!(InlineFieldV(-2, InlineFieldTag::Bls12381).signed_bits(), 2);
    assert_eq!(InlineFieldV(1, InlineFieldTag::Bls12381).signed_bits(), 2);
    assert_eq!(
        InlineFieldV(i64::MAX, InlineFieldTag::Bls12381).signed_bits(),
        64
    );
    assert_eq!(
        InlineFieldV(i64::MIN, InlineFieldTag::Bls12381).signed_bits(),
        64
    );
    assert_eq!(
        InlineFieldV(i64::MAX / 2, InlineFieldTag::Bls12381).signed_bits(),
        63
    );
    assert_eq!(
        InlineFieldV(i64::MIN / 2, InlineFieldTag::Bls12381).signed_bits(),
        63
    );
    assert_eq!(
        InlineFieldV(i64::MAX / 2 + 1, InlineFieldTag::Bls12381).signed_bits(),
        64
    );
    assert_eq!(
        InlineFieldV(i64::MIN / 2 - 1, InlineFieldTag::Bls12381).signed_bits(),
        64
    );
}

#[test]
fn inline_signed_bits_randomized() {
    let mut rng = thread_rng();
    for _ in 0..1024 {
        let i: i64 = rng.gen();
        let n_bits = rng.gen_range(0..64);
        let i = i % (1 << n_bits);
        let big_i = Integer::from(i);
        assert_eq!(
            InlineFieldV(i, InlineFieldTag::Bls12381).signed_bits(),
            signed_bits(&big_i),
            "wrong answer on {:b}",
            i
        )
    }
}

fn signed_bits(x: &Integer) -> u32 {
    if x.is_negative() {
        (-(x + Integer::one())).bits() as u32 + 1
    } else {
        x.bits() as u32 + 1
    }
}

/// Samples a random integer with up to `max_bits` bits.
///
/// A number with `i` is chosen with probability proportional to `2^-i`.
fn random_bigint_exp(rng: &mut impl Rng, max_bits: u32) -> Integer {
    use num_bigint::RandBigInt;
    let num_bits = rng.gen_range(1u32..max_bits);
    rng.gen_biguint(num_bits as u64).into() // into a non-negative BigInt
}

/// Sample a [FieldT] that is:
/// * Bls w/ p = 0.25
/// * Bn w/ p = 0.25
/// * An integer field otherwise
///   * with a number of bits sampled uniformly between 1..max_bits
pub fn sample_field_t(r: &mut impl Rng, max_bits: u32) -> FieldT {
    
    if r.gen_bool(0.5) {
        let result = if r.gen_bool(0.5) {
            FieldT::FBls12381
        } else {
            FieldT::FBn254
        };
        result
    } else {
        let result = FieldT::IntField(Arc::new(next_prime(random_bigint_exp(r, max_bits))));        
        result
    }
}

fn next_prime(n: Integer) -> Integer {

    let mut candidate = n;

    if candidate.is_even() {
        candidate += 1u8;
    }

    // is_prime below will fail if candidate < 4
    if candidate < 4u8.into() {
        candidate = 5u8.into();
    }

    while !Verification::is_prime(&BigUint02::from_bytes_le(&candidate.to_bytes_le().1)) {
        candidate += 2u8;
    }

    candidate
}

fn sample_field_v(ty: &FieldT, r: &mut impl Rng) -> FieldV {
    if let Some(t) = ty.inline_tag() {
        if r.gen_bool(0.5) {
            let num_bits = r.gen_range(0..62);
            let i: i64 = r.gen();
            return FieldV::from(InlineFieldV(i % (1 << num_bits), t));
        }
    }
    let i = random_bigint_exp(r, ty.modulus().bits() as u32);
    ty.new_v(i)
}

#[test]
fn random() {
    let mut rng = thread_rng();
    for _ in 0..1024 {
        let f = sample_field_t(&mut rng, 256);
        let a = sample_field_v(&f, &mut rng);
        let b = sample_field_v(&f, &mut rng);
        let a_i = a.i();
        let b_i = b.i();

        // add
        let c = a.clone() + &b;
        let c_i = (a_i.clone() + &b_i).mod_floor(f.modulus());
        assert_eq!(c.i(), c_i);

        // sub
        let c = a.clone() - &b;
        let c_i = (a_i.clone() - &b_i).mod_floor(f.modulus());
        assert_eq!(c.i(), c_i);

        // mul
        let c = a.clone() * &b;
        let c_i = (a_i.clone() * &b_i).mod_floor(f.modulus());
        assert_eq!(c.i(), c_i);

        // neg
        let c = -a.clone();
        let c_i = (-a_i.clone()).mod_floor(f.modulus());
        assert_eq!(c.i(), c_i);
    }
}
