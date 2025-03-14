use super::errors::ProofVerifyError;
use super::scalar::{Scalar, ScalarBytesFromScalar};
use core::borrow::Borrow;
use core::ops::{Mul, MulAssign, Add, Sub};
use circ_fields::t256::{Affine, Projective};
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use ark_ec::{Group, CurveGroup};
use serde_bytes::ByteArray;

use lazy_static::lazy_static;
use serde::{Deserialize, Serialize, Serializer, Deserializer};


#[derive(Copy, Clone,Debug,PartialEq)] // , Serialize, Deserialize
pub struct GroupElement(circ_fields::t256::Projective); // curve25519_dalek::ristretto::RistrettoPoint;
pub type GroupElementOri = circ_fields::t256::Projective;
pub type CompressedGroup = ByteArray<33>;// [u8; 33]; // curve25519_dalek::ristretto::CompressedRistretto;

lazy_static! {
  /// Compressed form of the generator
  pub static ref GROUP_BASEPOINT_COMPRESSED: CompressedGroup = CompressedGroup::new(circ_fields::t256::curves::BASEPOINT_COMPRESSED);
}

// Define an extension trait that offers the as_bytes functionality
pub trait AsBytesDev {
  fn as_bytes(&self) -> &[u8];
}

impl AsBytesDev for CompressedGroup {
  fn as_bytes(&self) -> &[u8] {
      // &self.into_array()
      &self[..]
  }
}

impl GroupElement {
  pub fn generator() -> Self {
    GroupElement(GroupElementOri::generator())
  }
  pub fn into(&self) -> GroupElementOri{
    self.0
  }
  pub fn from_affine(point: Affine) -> Self {
    GroupElement(Projective::from(point))
  }
  pub fn compress(&self) -> CompressedGroup {
    let mut compressed_bytes = Vec::new();
    // let mut compressed_bytes = [0u8; 33];
    self.0.serialize_compressed(&mut compressed_bytes).unwrap();
    CompressedGroup::new(compressed_bytes.try_into().unwrap()) //.into_array())
  }
}

impl Serialize for GroupElement {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
      S: Serializer,
  {
      let mut bytes = Vec::new();
      self.0.serialize_compressed(&mut bytes).unwrap();
      bytes.serialize(serializer)
  }
}

impl<'de> Deserialize<'de> for GroupElement { // ** to do
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
      D: Deserializer<'de>,
  {
      let bytes = Vec::<u8>::deserialize(deserializer)?;
      let point = Projective::deserialize_compressed(&bytes[..])
          .map_err(|e| serde::de::Error::custom(format!("Deserialization error: {:?}", e)))?;
      Ok(GroupElement(point))
  }
}

pub trait CompressedGroupExt {
  type Group;
  fn unpack(&self) -> Result<Self::Group, ProofVerifyError>;
  // fn decompress(&self) -> Self::Group;
  fn decompress(&self) -> Option<Self::Group>;
}

impl CompressedGroupExt for CompressedGroup {
  // type Group = circ_fields::t256::Projective; // curve25519_dalek::ristretto::RistrettoPoint;
  type Group = GroupElement; // curve25519_dalek::ristretto::RistrettoPoint;
  fn unpack(&self) -> Result<Self::Group, ProofVerifyError> {
    let result = Projective::deserialize_compressed(&self[..]);
    // let result = Self::Group::deserialize_compressed(&self[..]);
    if result.is_ok() {
      Ok(GroupElement(result.unwrap()))
    } else {
      Err(ProofVerifyError::DecompressionError(self[1..].try_into().unwrap()))     
      // let last_32_bytes = &self[1..];
      // let last_32_bytes_array: [u8; 32] = last_32_bytes.try_into()
      //                                     .expect("slice with incorrect length");
      // Err(ProofVerifyError::DecompressionError(last_32_bytes.into_array()))                                    
    }
    // Self::Group::deserialize_compressed(&self[..]).ok_or_else(|| ProofVerifyError::DecompressionError(last_32_bytes_array))
    // self
    //   .decompress()
    //   .ok_or_else(|| ProofVerifyError::DecompressionError(self.to_bytes()))
  }

  #[inline]
  fn decompress(&self) -> Option<Self::Group> {
    // Projective::deserialize_compressed(&self[..])
    //     .map_or_else(|_| None, |result| Some(GroupElement(result)))
    // Projective::deserialize_compressed(&self[..])
    //       .ok().map(|r| GroupElement(r))
    let result = Projective::deserialize_compressed(&self[..]);
    // result.ok().map(|r| Self::Group(r))
    result.ok().map(|r| GroupElement(r))
  }
}


impl<'b> MulAssign<&'b Scalar> for GroupElement { // to do: modify Scalar to that it can fit original MulAssign
  fn mul_assign(&mut self, scalar: &'b Scalar) {
    let point = (self as &GroupElement).into();
    let result = point * Scalar::decompress_scalar(scalar);
    *self = GroupElement(result);
  }
}

impl<'a, 'b> Mul<&'b Scalar> for &'a GroupElement {
  type Output = GroupElement;
  fn mul(self, scalar: &'b Scalar) -> GroupElement { 
    GroupElement(self.into() * Scalar::decompress_scalar(scalar)) // right is of type ScalarBytes
  }
}



impl<'a, 'b> Mul<&'b GroupElement> for &'a Scalar {
  type Output = GroupElement;

  fn mul(self, point: &'b GroupElement) -> GroupElement { // to test
    GroupElement(point.into() * Scalar::decompress_scalar(self))
    // Scalar::decompress_scalar(self) * point
  }
}

macro_rules! define_mul_variants {
  (LHS = $lhs:ty, RHS = $rhs:ty, Output = $out:ty) => {
    impl<'b> Mul<&'b $rhs> for $lhs {
      type Output = $out;
      fn mul(self, rhs: &'b $rhs) -> $out {
        &self * rhs
      }
    }

    impl<'a> Mul<$rhs> for &'a $lhs {
      type Output = $out;
      fn mul(self, rhs: $rhs) -> $out {
        self * &rhs
      }
    }

    impl Mul<$rhs> for $lhs {
      type Output = $out;
      fn mul(self, rhs: $rhs) -> $out {
        &self * &rhs
      }
    }
  };
}

macro_rules! define_mul_assign_variants {
  (LHS = $lhs:ty, RHS = $rhs:ty) => {
    impl MulAssign<$rhs> for $lhs {
      fn mul_assign(&mut self, rhs: $rhs) {
        *self *= &rhs;
      }
    }
  };
}

define_mul_assign_variants!(LHS = GroupElement, RHS = Scalar);
define_mul_variants!(LHS = GroupElement, RHS = Scalar, Output = GroupElement);
define_mul_variants!(LHS = Scalar, RHS = GroupElement, Output = GroupElement);

// implement Add for GroupElement
impl<'a, 'b> Add<&'b GroupElement> for &'a GroupElement {
  type Output = GroupElement;

  fn add(self, other: &'b GroupElement) -> Self::Output {
      GroupElement(&self.0 + &other.0)
  }
}

macro_rules! define_add_variants {
  (LHS = $lhs:ty, RHS = $rhs:ty, Output = $out:ty) => {
      impl<'b> Add<&'b $rhs> for $lhs {
          type Output = $out;
          fn add(self, rhs: &'b $rhs) -> $out {
              &self + rhs
          }
      }

      impl<'a> Add<$rhs> for &'a $lhs {
          type Output = $out;
          fn add(self, rhs: $rhs) -> $out {
              self + &rhs
          }
      }

      impl Add<$rhs> for $lhs {
          type Output = $out;
          fn add(self, rhs: $rhs) -> $out {
              &self + &rhs
          }
      }
  };
}

// implement Sub for GroupElement
impl<'a, 'b> Sub<&'b GroupElement> for &'a GroupElement {
  type Output = GroupElement;

  fn sub(self, other: &'b GroupElement) -> Self::Output {
      GroupElement(&self.0 - &other.0)
  }
}

macro_rules! define_sub_variants {
  (LHS = $lhs:ty, RHS = $rhs:ty, Output = $out:ty) => {
      impl<'b> Sub<&'b $rhs> for $lhs {
          type Output = $out;
          fn sub(self, rhs: &'b $rhs) -> $out {
              &self - rhs
          }
      }

      impl<'a> Sub<$rhs> for &'a $lhs {
          type Output = $out;
          fn sub(self, rhs: $rhs) -> $out {
              self - &rhs
          }
      }

      impl Sub<$rhs> for $lhs {
          type Output = $out;
          fn sub(self, rhs: $rhs) -> $out {
              &self - &rhs
          }
      }
  };
}

define_add_variants!(LHS = GroupElement, RHS = GroupElement, Output = GroupElement);
define_sub_variants!(LHS = GroupElement, RHS = GroupElement, Output = GroupElement);

pub trait VartimeMultiscalarMul {
  type Scalar;
  fn vartime_multiscalar_mul<I, J>(scalars: I, points: J) -> Self
  where
    I: IntoIterator,
    I::Item: Borrow<Self::Scalar>,
    J: IntoIterator,
    J::Item: Borrow<Self>,
    Self: Clone;
}

impl VartimeMultiscalarMul for GroupElement {
  type Scalar = super::scalar::Scalar;
  // TODO Borrow the arguments so we don't have to clone them, as it was in the original implementation
  // fn vartime_multiscalar_mul(scalars: Vec<Scalar>, points: Vec<GroupElement>) -> Self {

  // }
  // #[inline] // ** to test improve 1ms
  fn vartime_multiscalar_mul<I, J>(scalars: I, points: J) -> Self // to do: use msm instead
  where
    I: IntoIterator,
    I::Item: Borrow<Self::Scalar>,
    J: IntoIterator,
    J::Item: Borrow<Self>,
    Self: Clone,
  {
    use ark_ec::VariableBaseMSM;
    use ark_ff::biginteger::BigInteger256;
    let points_affine: Vec<Affine> = points
                                      .into_iter()
                                      .map(|p| p.borrow().into().into_affine())
                                      .collect::<Vec<Affine>>(); 
    let result = GroupElementOri::msm_bigint(
                    &points_affine,
                    // &points
                    // .into_iter()
                    // .map(|p| p.borrow().into().into_affine())
                    // .collect::<Vec<Affine>>(),
                    &scalars
                      .into_iter()
                      .map(|s| s.borrow().to_bigint())
                      .collect::<Vec<BigInteger256>>(),
                  );
              
    // let result = GroupElementOri::msm(
    //                 &points_affine,
    //                 &scalars
    //                   .into_iter()
    //                   .map(|s| Scalar::decompress_scalar(s.borrow()))
    //                   .collect::<Vec<ScalarBytes>>(),
    //               ).unwrap();
    GroupElement(result)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  // use ark_ff::fields::PrimeField;
  #[test]
  fn msm() { // https://github.com/personaelabs/spartan-ecdsa/blob/main/packages/Spartan-secq/src/group.rs
    for i in 0..5000 {
      let scalars = vec![Scalar::from(i+1), Scalar::from(i+2), Scalar::from(i+3)];
      let points = vec![
        GroupElement::generator(),
        GroupElement::generator(),
        GroupElement::generator(),
      ];
      let result = GroupElement::vartime_multiscalar_mul(scalars, points);
  
      // println!("msm result {:?}", result);
      assert_eq!(result, GroupElement::generator() * Scalar::from(3*i+6));
    }
  }

}