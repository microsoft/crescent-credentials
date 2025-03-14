use super::group::{GroupElement, VartimeMultiscalarMul};//, GROUP_BASEPOINT_COMPRESSED};
use super::scalar::Scalar;
use digest::XofReader;
use digest::{ExtendableOutput, Input};
use sha3::Shake256;

use circ_fields::t256::hash_to_curve::create_curvebased_hasher;
use circ_fields::t256::curves::BASEPOINT_COMPRESSED;
use ark_ec::hashing::HashToCurve;
// use circ_fields::t256::Projective;
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
    // shake.input(GROUP_BASEPOINT_COMPRESSED);
    shake.input(BASEPOINT_COMPRESSED);

    let mut reader = shake.xof_result();
    let mut gens: Vec<GroupElement> = Vec::new();
    let mut uniform_bytes = [0u8; 64];
    let hasher = create_curvebased_hasher(&[]);
    for _ in 0..n + 1 {
      reader.read(&mut uniform_bytes);
      let result_affine = hasher.hash(&uniform_bytes).unwrap();
      gens.push(GroupElement::from_affine(result_affine));
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
