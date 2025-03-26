#![forbid(unsafe_code)]
//! From https://github.com/brave-experiments/CDLS/blob/main/t256/src/lib.rs
//! This library implements the 256-bit prime order curve used inside ZKAttest.
//! Note: we use the values here from the ZKAttest implementation:
//!    https://github.com/cloudflare/zkp-ecdsa/blob/0af748d23b535a8fffebca34ab51abf37ef1ea13/src/curves/instances.ts#L34,
//! which are different from those that are given in the paper.
//!
//! Curve infomration:
//! * Base field:   q = 0xffffffff0000000100000000000000017e72b42b30e7317793135661b1c4b117
//! * Scalar field: r = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
//!
//! Note that by "base field" we mean "the characteristic of the underlying finite field" and by "scalar field" we mean
//! "the order of the curve".
//!
//! * Curve equation: y^2 = x^3 + a_4*x + a_6, where
//!   a_4 = -3
//!   a_6 = 0xb441071b12f4a0366fb552f8e21ed4ac36b06aceeb354224863e60f20219fc56
//!
//! Or, in decimal, a_4 = -3
//!                 a_6 = 81531206846337786915455327229510804132577517753388365729879493166393691077718

//#[cfg(feature = "r1cs")]
///// constraints
//pub mod constraints;
pub mod curves;
pub mod hash_to_curve;
mod fields;
mod macros;
/// utils
pub mod utils;

pub use curves::*;
pub use hash_to_curve::*;
pub use fields::*;
