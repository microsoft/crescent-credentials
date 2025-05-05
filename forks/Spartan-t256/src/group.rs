use super::errors::ProofVerifyError;
use super::scalar::Scalar;
use core::borrow::Borrow;
use core::ops::{Mul, MulAssign, Add, Sub};
use halo2curves::serde::Repr;
use halo2curves::t256::{T256Affine as Affine, T256 as Projective};
use halo2curves::group::{Curve, GroupEncoding};
use serde_bytes::ByteArray;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize, Serializer, Deserializer};
use crate::scalar::ScalarBytesFromScalar;


#[derive(Copy, Clone,Debug,PartialEq)]
pub struct GroupElement(pub Projective); 
pub type GroupElementOri = Projective;
pub type CompressedGroup = ByteArray<33>;

lazy_static! {
  /// Compressed form of the generator
  pub static ref GROUP_BASEPOINT_COMPRESSED: CompressedGroup = CompressedGroup::new(Affine::generator().to_bytes().into());
}

// Define an extension trait that offers the as_bytes functionality
pub trait AsBytesDev {
  fn as_bytes(&self) -> &[u8];
}

impl AsBytesDev for CompressedGroup {
  fn as_bytes(&self) -> &[u8] {
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
    CompressedGroup::new(self.0.to_bytes().into())
  }
}

impl Serialize for GroupElement {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
      S: Serializer,
  {
      self.0.to_bytes().as_ref().serialize(serializer)
  }
}

impl<'de> Deserialize<'de> for GroupElement { // ** to do
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
      D: Deserializer<'de>,
  {
      let bytes = Vec::<u8>::deserialize(deserializer)?;
      let point = Projective::from_bytes(&Repr::from(bytes.as_slice())).into_option().map(GroupElement).ok_or_else(||serde::de::Error::custom("Deserialization error 1"))?;
      Ok(point)
  }
}

pub trait CompressedGroupExt {
  type Group;
  fn unpack(&self) -> Result<Self::Group, ProofVerifyError>;
  fn decompress(&self) -> Option<Self::Group>;
}

impl CompressedGroupExt for CompressedGroup {
  type Group = GroupElement;
  fn unpack(&self) -> Result<Self::Group, ProofVerifyError> {
    Projective::from_bytes(&Repr::from(self.into_array())).into_option().map(GroupElement).ok_or_else(||ProofVerifyError::DecompressionError([2;32]))    
  }

  #[inline]
  fn decompress(&self) -> Option<Self::Group> {
    let result = Projective::from_bytes(&Repr::from(self.into_array()));
    result.into_option().map(|r| GroupElement(r))
  }
}

impl<'b> MulAssign<&'b Scalar> for GroupElement {
  fn mul_assign(&mut self, scalar: &'b Scalar) {
    let point = (self as &GroupElement).into();
    let result = point * Scalar::decompress_scalar(scalar);
    *self = GroupElement(result);
  }
}

impl<'a, 'b> Mul<&'b Scalar> for &'a GroupElement {
  type Output = GroupElement;
  fn mul(self, scalar: &'b Scalar) -> GroupElement { 
    GroupElement(self.into() * Scalar::decompress_scalar(scalar))
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

  fn vartime_multiscalar_mul<I, J>(scalars: I, points: J) -> Self // to do: use msm instead
  where
    I: IntoIterator,
    I::Item: Borrow<Self::Scalar>,
    J: IntoIterator,
    J::Item: Borrow<Self>,
    Self: Clone,
  {
    use halo2curves::msm::msm_best;
    use halo2curves::group::prime::PrimeCurveAffine;

    let points_projective: Vec<Projective> = points
    .into_iter()
    .map(|p| p.borrow().0)
    .collect();    
    let mut points_affine = vec![Affine::identity(); points_projective.len()];
    Projective::batch_normalize(&points_projective, &mut points_affine);

    let scalars_bigint: Vec<_> = scalars
      .into_iter()
      .map(|s| Scalar::decompress_scalar(s.borrow()))
      .collect();

    let result = msm_best::<Affine>(&scalars_bigint, &points_affine);

    GroupElement(result)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

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