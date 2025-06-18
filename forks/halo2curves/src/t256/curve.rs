use core::{
    cmp,
    fmt::Debug,
    iter::Sum,
    ops::{Add, Mul, Neg, Sub},
};

use rand::RngCore;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

use crate::{
    ff::{Field, PrimeField, WithSmallOrderMulGroup},
    group::{prime::PrimeCurveAffine, Curve, Group as _, GroupEncoding},
    t256::{Fp, Fq},
    Coordinates, CurveAffine, CurveExt,
};

impl group::cofactor::CofactorGroup for T256 {
    type Subgroup = T256;

    fn clear_cofactor(&self) -> Self {
        *self
    }

    fn into_subgroup(self) -> CtOption<Self::Subgroup> {
        CtOption::new(self, 1.into())
    }

    fn is_torsion_free(&self) -> Choice {
        1.into()
    }
}


const T256_GENERATOR_X: Fp = Fp::from_raw([
    0x0000000000000005,
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
]);
const T256_GENERATOR_Y: Fp = Fp::from_raw([
    0x5826108A653DE28D,
    0x0ED60B9E33CE397C, 
    0x5EFC7B55F6B24FBE, 
    0x3E86C0CFEBF2C716,     
]);

const T256_A: Fp = Fp::from_raw([
    0x93135661B1C4B114,
    0x7E72B42B30E73177,
    0x0000000000000001,
    0xFFFFFFFF00000001,
]);
const T256_B: Fp = Fp::from_raw([
    0x863E60F20219FC56,
    0x36B06ACEEB354224,
    0x6FB552F8E21ED4AC,
    0xB441071B12F4A036,    
]);

use crate::{
    impl_binops_additive, impl_binops_additive_specify_output, impl_binops_multiplicative,
    impl_binops_multiplicative_mixed, new_curve_impl,
};

new_curve_impl!(
    (pub),
    T256,
    T256Affine,
    Fp,
    Fq,
    (T256_GENERATOR_X,T256_GENERATOR_Y),
    T256_A,
    T256_B,
    "t256",
    |domain_prefix| hash_to_curve(domain_prefix, hash_to_curve_suite(b"T256_XMD:SHA-256_SSWU_RO_")),
    crate::serde::CompressedFlagConfig::Extra,
    standard_sign
);

fn hash_to_curve_suite(domain: &[u8]) -> crate::hash_to_curve::Suite<T256, sha2::Sha256, 48> {
    // Z : <https://datatracker.ietf.org/doc/html/rfc9380#sswu-z-code>
    const SSWU_Z: Fp = Fp::from_raw([
        0x93135661B1C4B116,
        0x7E72B42B30E73177,
        0x0000000000000001,
        0xFFFFFFFF00000001,        
    ]);

    let iso_map = crate::hash_to_curve::Iso {
        a: T256::a(),
        b: T256::b(),
        map: Box::new(move |x, y, z| T256 { x, y, z }),
    };

    crate::hash_to_curve::Suite::new(domain, SSWU_Z, crate::hash_to_curve::Method::SSWU(iso_map))
}

#[allow(clippy::type_complexity)]
pub(crate) fn hash_to_curve<'a>(
    domain_prefix: &'a str,
    suite: crate::hash_to_curve::Suite<T256, sha2::Sha256, 48>,
) -> Box<dyn Fn(&[u8]) -> T256 + 'a> {
    Box::new(move |message| suite.hash_to_curve(domain_prefix, message))
}

#[cfg(test)]
mod test {
    use group::UncompressedEncoding;
    use rand::{thread_rng, Rng};
    use rand_core::OsRng;
    use crate::{curve, msm::{msm_best, msm_serial}};

    use super::*;
    use crate::{serde::SerdeObject, tests::curve::TestH2C};
    crate::curve_testing_suite!(T256);
    crate::curve_testing_suite!(T256, "ecdsa_example");
    crate::curve_testing_suite!(
        T256,
        "constants",
        Fp::MODULUS,
        T256_A,
        T256_B,
        T256_GENERATOR_X,
        T256_GENERATOR_Y,
        Fq::MODULUS
    );

    #[test] // TODO: once we have the real T256 params we'll have to create new test vectors, and maybe some hashtocurve constants
    fn test_hash_to_curve() {

        for i in 1..10 {
        let r0 = <T256Affine as curve::CurveAffine>::CurveExt::hash_to_curve("t256 domain prefix")(format!("Test {}", i).as_bytes());
        assert!(r0.to_affine().is_on_curve().unwrap_u8() == 1);
        assert!(r0.to_affine().is_identity().unwrap_u8() == 0);
        }
    }

    #[test]
    fn test_msm() {
        let mut rng = thread_rng();
        let mut scalars : Vec<Fq> = vec![];
        let mut bases : Vec<T256Affine> = vec![];
        for _ in 1..(1<<13) {
            bases.push(T256Affine::random(&mut rng));
            scalars.push(Fq::random(&mut rng));
        }
        let res1 = msm_best(&scalars, &bases);
        let res2 = T256Affine::identity();
        msm_serial(&scalars, &bases, &mut res2.into());
        assert!(res1 == res1);
    }
}
