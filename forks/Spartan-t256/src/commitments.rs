use super::group::{GroupElement, VartimeMultiscalarMul};
use super::scalar::Scalar;
use digest::XofReader;
use digest::{ExtendableOutput, Input};
use halo2curves::t256::T256;
use halo2curves::CurveExt;
use sha3::Shake256;
use crate::group::{GROUP_BASEPOINT_COMPRESSED, AsBytesDev};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]  
pub struct MultiCommitGens {
  pub n: usize,
  pub G: Vec<GroupElement>,
  pub h: GroupElement,
}

impl MultiCommitGens {
  pub fn new(n: usize, label: &[u8]) -> Self {
    let mut shake = Shake256::default();
    shake.input(label);
    shake.input(GROUP_BASEPOINT_COMPRESSED.as_bytes());

    let mut reader = shake.xof_result();
    let mut gens: Vec<GroupElement> = Vec::new();
    let mut uniform_bytes = [0u8; 64];

    let hasher = T256::hash_to_curve("domain_prefix");
    
    for _ in 0..n + 1 {
      reader.read(&mut uniform_bytes);
      let point = hasher(&uniform_bytes);
      gens.push(GroupElement(point));
    }

    MultiCommitGens {
      n,
      G: gens[..n].to_vec(),
      h: gens[n],
    }
  }

  pub fn clone(&self) -> MultiCommitGens {
    MultiCommitGens {
      n: self.n,
      h: self.h,
      G: self.G.clone(),
    }
  }

  pub fn scale(&self, s: &Scalar) -> MultiCommitGens {
    MultiCommitGens {
      n: self.n,
      h: self.h,
      G: (0..self.n).map(|i| s * self.G[i]).collect(),
    }
  }

  pub fn split_at(&self, mid: usize) -> (MultiCommitGens, MultiCommitGens) {
    let (G1, G2) = self.G.split_at(mid);

    (
      MultiCommitGens {
        n: G1.len(),
        G: G1.to_vec(),
        h: self.h,
      },
      MultiCommitGens {
        n: G2.len(),
        G: G2.to_vec(),
        h: self.h,
      },
    )
  }
}

pub trait Commitments {
  fn commit(&self, blind: &Scalar, gens_n: &MultiCommitGens) -> GroupElement;
}

impl Commitments for Scalar {
  fn commit(&self, blind: &Scalar, gens_n: &MultiCommitGens) -> GroupElement {
    assert_eq!(gens_n.n, 1);
    GroupElement::vartime_multiscalar_mul(&[*self, *blind], &[gens_n.G[0], gens_n.h])
  }
}

impl Commitments for Vec<Scalar> {
  fn commit(&self, blind: &Scalar, gens_n: &MultiCommitGens) -> GroupElement {
    assert_eq!(gens_n.n, self.len());
    GroupElement::vartime_multiscalar_mul(self, &gens_n.G) + blind * gens_n.h
  }
}

impl Commitments for [Scalar] {
  fn commit(&self, blind: &Scalar, gens_n: &MultiCommitGens) -> GroupElement {
    assert_eq!(gens_n.n, self.len());
    GroupElement::vartime_multiscalar_mul(self, &gens_n.G) + blind * gens_n.h
  }
}
