use circ_fields::t256::ScalarField;
// use ark_serialize::CanonicalDeserialize;
// use ark_serialize::CanonicalSerialize;

use ark_ff::PrimeField;

mod scalar;

pub type Scalar = scalar::Scalar;
pub type ScalarBytes = ScalarField;


pub trait ScalarFromPrimitives {
  fn to_scalar(self) -> Scalar;
}

impl ScalarFromPrimitives for usize {
  #[inline]
  fn to_scalar(self) -> Scalar {
    (0..self).map(|_i| Scalar::one()).sum()
  }
}

impl ScalarFromPrimitives for bool {
  #[inline]
  fn to_scalar(self) -> Scalar {
    if self {
      Scalar::one()
    } else {
      Scalar::zero()
    }
  }
}

pub trait ScalarBytesFromScalar {
  fn decompress_scalar(s: &Scalar) -> ScalarBytes;
  fn decompress_vector(s: &[Scalar]) -> Vec<ScalarBytes>;
}

impl ScalarBytesFromScalar for Scalar {
  fn decompress_scalar(s: &Scalar) -> ScalarBytes {
    // ScalarBytes::deserialize_compressed(&s.to_bytes()[..]).unwrap()
    ScalarBytes::from_bigint(s.to_bigint()).unwrap()
  }

  fn decompress_vector(s: &[Scalar]) -> Vec<ScalarBytes> {
    (0..s.len())
      .map(|i| Scalar::decompress_scalar(&s[i]))
      .collect::<Vec<ScalarBytes>>()
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn test_decompress_scalar() {
    for i in 0..50000 {
      let scalars = vec![Scalar::from(i+1), Scalar::from(i+2), Scalar::from(i+3), Scalar::from(i+4), Scalar::from(i+5), Scalar::from(i+6), Scalar::from(i+7), Scalar::from(i+8), Scalar::from(i+9), Scalar::from(i+10)];

      let _result = Scalar::decompress_vector(&scalars);
      // let result_v2 = Scalar::decompress_vector_v2(&scalars);
      // println!("result {:?}", result);
      // assert!(result == result_v2);
    }
  }

}