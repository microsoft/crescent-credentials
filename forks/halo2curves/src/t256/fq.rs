use core::convert::TryInto;

use halo2derive::impl_field;
use rand::RngCore;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

impl_field!(
    t256_scalar,
    Fq,
    modulus = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    mul_gen = "6",
    zeta = "4d6ea8928adb86cf62388a8e0ef623312e68c59bdef3e53fd964598eb819acce",
    from_uniform = [48, 64],
    endian = "little",
);

crate::extend_field_legendre!(Fq);
crate::impl_binops_calls!(Fq);
crate::impl_binops_additive!(Fq, Fq);
crate::impl_binops_multiplicative!(Fq, Fq);
crate::field_bits!(Fq);
crate::serialize_deserialize_primefield!(Fq);
crate::impl_from_u64!(Fq);
crate::impl_from_bool!(Fq);

#[cfg(test)]
mod test {
    use super::Fq;
    use crate::{
        arith_test, constants_test, from_uniform_bytes_test, legendre_test, serde_test, test,
    };

    constants_test!(Fq);

    arith_test!(Fq);
    legendre_test!(Fq);
    test!(arith, Fq, sqrt_test, 1000);

    serde_test!(Fq PrimeFieldBits);
    from_uniform_bytes_test!(Fq, 1000, L 64, L 48);
}
