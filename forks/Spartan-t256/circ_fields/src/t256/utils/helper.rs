// use crate::Config;
use crate::t256::Config;
use ark_ec::{models::CurveConfig};
use ark_serialize::CanonicalSerialize;
// type SF = <Config as CurveConfig>::ScalarField; // scalar field of T256

/// Trait for Spartan
pub trait SpartanTrait {
    /// Convert to bytes
    fn to_bytes(&self) -> [u8; 32];
    // /// Create a zero scalar
    // fn zero() -> Self;
}

impl SpartanTrait for <Config as CurveConfig>::ScalarField {
    // /// Convert Scalar to bytes
    // fn to_bytes(&self) -> [u8; 32] {
    //     let mut compressed_bytes: Vec<u8> = Vec::new();
    //     self.serialize_compressed(&mut compressed_bytes).unwrap();
    //     assert!(compressed_bytes.len() == 32);
    //     let mut array_bytes = [0u8; 32];
    //     array_bytes.copy_from_slice(&compressed_bytes);
    //     array_bytes
    // }

    /// Convert Scalar to bytes
    fn to_bytes(&self) -> [u8; 32] {
        let mut array_bytes = [0u8; 32];
        self.serialize_compressed(&mut &mut array_bytes[..]).unwrap();
        array_bytes
    }
    // /// Create a zero scalar
    // fn zero() -> Self {
    //     Self::from(0)
    // }
}