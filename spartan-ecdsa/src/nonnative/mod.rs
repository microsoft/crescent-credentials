//! This module implements various gadgets necessary for doing non-native arithmetic
//! Code in this module is taken from [Nova](https://github.com/microsoft/Nova/tree/main/src/gadgets/nonnative) which in turn adapted it
//! from [bellman-bignat](https://github.com/alex-ozdemir/bellman-bignat) (which is MIT licensed)

use bellpepper_core::SynthesisError;
use ff::PrimeField;

trait OptionExt<T> {
  fn grab(&self) -> Result<&T, SynthesisError>;
  #[allow(unused)]
  fn grab_mut(&mut self) -> Result<&mut T, SynthesisError>;
}

impl<T> OptionExt<T> for Option<T> {
  fn grab(&self) -> Result<&T, SynthesisError> {
    self.as_ref().ok_or(SynthesisError::AssignmentMissing)
  }
  fn grab_mut(&mut self) -> Result<&mut T, SynthesisError> {
    self.as_mut().ok_or(SynthesisError::AssignmentMissing)
  }
}

trait BitAccess {
  fn get_bit(&self, i: usize) -> Option<bool>;
}

impl<Scalar: PrimeField> BitAccess for Scalar {
  fn get_bit(&self, i: usize) -> Option<bool> {
    if i as u32 >= Scalar::NUM_BITS {
      return None;
    }

    let (byte_pos, bit_pos) = (i / 8, i % 8);
    let byte = self.to_repr().as_ref()[byte_pos];
    let bit = byte >> bit_pos & 1;
    Some(bit == 1)
  }
}

pub mod bignat;
pub mod bignat_utils;
