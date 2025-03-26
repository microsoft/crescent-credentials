//! This module implements t256 curve
use ark_ec::{
    models::CurveConfig,
    short_weierstrass::{self as sw, SWCurveConfig},
};

use super::{fq::Fq, fr::Fr, fr::FrConfig};
// use crate::{fq::Fq, fr::Fr, fr::FrConfig};
use ark_secp256r1::Config as secp256r1conf;
use ark_secp256r1::Fq as secp256r1Fq;
use ark_secp256r1::FqConfig as secp256FqConfig;
use ark_secp256r1::Fr as secp256r1Fr;
#[allow(unused_imports)]
// This is actually used in the macro below, but rustfmt seems to
// be unable to deduce that...
use ark_secp256r1::FrConfig as secp256FrConfig;
#[warn(unused_imports)]
// use cdls_macros::derive_conversion;
use crate::derive_conversion;
// use ark_ff::{Field, MontConfig, MontFp};
// use serde_bytes::ByteArray;

// #[cfg(test)]
// mod tests;
/// Affine
pub type Affine = sw::Affine<Config>;
/// Projective
pub type Projective = sw::Projective<Config>;
/// Define ScalarBytes
pub type ScalarField = <Config as CurveConfig>::ScalarField;

/// Compressed form of the generator
pub const BASEPOINT_COMPRESSED: [u8; 33] = [3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
// pub const BASEPOINT_COMPRESSED: ByteArray<33> = ByteArray::new([3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

#[derive(Copy, Clone, Default, PartialEq, Eq)]
/// Config
pub struct Config;

impl CurveConfig for Config {
    type BaseField = Fq;
    type ScalarField = Fr;

    // We're dealing with prime order curves.

    /// COFACTOR = 1
    const COFACTOR: &'static [u64] = &[0x1];

    /// COFACTOR_INV = COFACTOR^{-1} mod r = 1
    const COFACTOR_INV: Fr = Fr::ONE;
}

impl SWCurveConfig for Config {
    /// COEFF_A = a4 in the docs, which is a very large string.
    const COEFF_A: Fq =
        MontFp!("115792089210356248762697446949407573530594504085698471288169790229257723883796");

    /// COEFF_B = a6 in the docs, which is a very large string.
    const COEFF_B: Fq =
        MontFp!("81531206846337786915455327229510804132577517753388365729879493166393691077718");

    /// GENERATOR = (G_GENERATOR_X, G_GENERATOR_Y)
    const GENERATOR: Affine = Affine::new_unchecked(G_GENERATOR_X, G_GENERATOR_Y);

}

/// G_GENERATOR_X = 3
pub const G_GENERATOR_X: Fq = MontFp!("3");

/// G_GENERATOR_Y = 40902200210088653215032584946694356296222563095503428277299570638400093548589
pub const G_GENERATOR_Y: Fq =
    MontFp!("40902200210088653215032584946694356296222563095503428277299570638400093548589");

/// G_GENERATOR_X2 = 5
pub const G_GENERATOR_X2: Fq = MontFp!("5");

/// G_GENERATOR_Y2 = 28281484859698624956664858566852274012236038028101624500031073655422126514829
pub const G_GENERATOR_Y2: Fq =
    MontFp!("28281484859698624956664858566852274012236038028101624500031073655422126514829");

/// The x co-ordinate of the other generator for secp256r1.
pub const G_SECP256_O_X: &str = "5";

/// The y co-ordinate of the other generator for secp256r1.
pub const G_SECP256_O_Y: &str =
    "31468013646237722594854082025316614106172411895747863909393730389177298123724";

// Now we instantiate everything else.
derive_conversion!(
    Config,
    4,
    128,
    secp256r1conf,
    G_GENERATOR_X2,
    G_GENERATOR_Y2,
    Fr,
    FrConfig,
    secp256r1Fq,
    secp256r1Fr,
    secp256FqConfig,
    secp256FrConfig,
    Affine,
    "5",
    "31468013646237722594854082025316614106172411895747863909393730389177298123724"
);
