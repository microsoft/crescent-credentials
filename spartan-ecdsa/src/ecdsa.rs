use crate::ecc::AllocatedPoint;
use bellpepper::gadgets::num::AllocatedNum;
use bellpepper_core::{ConstraintSystem, SynthesisError};
use ff::{PrimeField, PrimeFieldBits};

pub struct Signature<Scalar>
where
  Scalar: PrimeField,
{
  r: AllocatedNum<Scalar>,
  s_inv: AllocatedNum<Scalar>, // we re-arrange the verification equation to prove knowledge of 1/s rather than s
}

impl<Scalar> Signature<Scalar>
where
  Scalar: PrimeField + PrimeFieldBits,
{
  /// Allocate signature
  pub fn alloc<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    signature: Option<(Scalar, Scalar)>,
  ) -> Result<Self, SynthesisError> {
    let r = AllocatedNum::alloc(cs.namespace(|| "r"), || Ok(signature.unwrap().0))?;

    let s_inv = AllocatedNum::alloc(cs.namespace(|| "s"), || Ok(signature.unwrap().1))?;

    Ok(Self { r, s_inv })
  }

  /// Verify the signature
  pub fn verify<CS: ConstraintSystem<Scalar>>(
    &self,
    mut cs: CS,
    g: &AllocatedPoint<Scalar>,  // group generator
    pk: &AllocatedPoint<Scalar>, // public key
    h: &AllocatedNum<Scalar>,    // message digest
  ) -> Result<(), SynthesisError> {
    // We need to compute R \gets s_inv * (r*P + h*G) and check R.x =? r
    // We will do this in five steps
    // (1) compute r*PK
    let rpk = pk.scalar_mul(cs.namespace(|| "r*PK"), &self.r)?;

    // (2) compute h*G
    let hg = g.scalar_mul(cs.namespace(|| "h*G"), h)?;

    // (3) compute h*P + r*G
    let sum = rpk.add(cs.namespace(|| "h*P + r*G"), &hg)?;

    // (4) compute s_inv * sum
    let ssum = sum.scalar_mul(cs.namespace(|| "s * sum"), &self.s_inv)?;

    // (5) check ssum.x = r
    cs.enforce(
      || "check ssum.x = r",
      |lc| lc + ssum.x.get_variable(),
      |lc| lc + CS::one(),
      |lc| lc + self.r.get_variable(),
    );

    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use bellpepper_core::{test_cs::TestConstraintSystem, Comparable, ConstraintSystem};
  use halo2curves::secp256k1::Fp as Scalar;

  fn array_from_slice(data: &[u8]) -> [u8; 32] {
    let mut arr = [0; 32];
    arr.copy_from_slice(&data[0..32]);
    arr
  }

  fn hex_to_ff(hex: &str) -> Scalar {
    let v = hex::decode(hex)
      .unwrap()
      .iter()
      .copied()
      .rev()
      .collect::<Vec<u8>>();
    Scalar::from_repr(array_from_slice(&v)).unwrap()
  }

  #[test]
  fn test_ecdsa() {
    // test vector 1
    test_ecdsa_with(
      // message hash h
      "3F891FDA3704F0368DAB65FA81EBE616F4AA2A0854995DA4DC0B59D2CADBD64F",
      // generator g
      (
        "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
      ),
      // public key pk
      (
        "3AF1E1EFA4D1E1AD5CB9E3967E98E901DAFCD37C44CF0BFB6C216997F5EE51DF",
        "E4ACAC3E6F139E0C7DB2BD736824F51392BDA176965A1C59EB9C3C5FF9E85D7A",
      ),
      // signature (r, s_inv)
      (
        "A5C7B7756D34D8AAF6AA68F0B71644F0BEF90D8BFD126CE951B6060498345089",
        "d6e6d8e2b519d1955cf6452e05cb89143ea752a222d38f3492b7b51b83625700",
      ),
    );

    // test vector 2
    test_ecdsa_with(
      // message hash h
      "ae1ab30ce075f12cadb7f66ed3c8fc0b0b203ac206f381c6e2bdc1498402bcea",
      // generator g
      (
        "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
      ),
      // public key pk
      (
        "bb8552f9f4b5ea4159ebfe9a42f8cc5b209e8cedd3a2d0e36f1b7db39fb45693",
        "b4169332e1f00c8a10aa18806235295d2596f00d13ea2921b5a20c89acebc822",
      ),
      // signature (r, s_inv)
      (
        "c6fbbdb372303f3b65cbfcf16ff7fc4dbf6acd921e40c93db8207a860db41850",
        "b02d639cb9d6143c6363e5a716c0761df817b116d1853ce528a03d64e08846b6",
      ),
    );
  }

  fn test_ecdsa_with(
    h_str: &str,
    g_str: (&str, &str),
    pk_str: (&str, &str),
    sig_str: (&str, &str),
  ) {
    let mut cs = TestConstraintSystem::<Scalar>::new();
    let h = AllocatedNum::alloc(cs.namespace(|| "h"), || Ok(hex_to_ff(h_str))).unwrap();
    let g = AllocatedPoint::alloc(
      cs.namespace(|| "g"),
      Some((hex_to_ff(g_str.0), hex_to_ff(g_str.1), false)),
    )
    .unwrap();
    let pk = AllocatedPoint::alloc(
      cs.namespace(|| "pk"),
      Some((hex_to_ff(pk_str.0), hex_to_ff(pk_str.1), false)),
    )
    .unwrap();
    let sig = Signature::alloc(
      cs.namespace(|| "sig"),
      Some((hex_to_ff(sig_str.0), hex_to_ff(sig_str.1))),
    )
    .unwrap();

    sig.verify(cs.namespace(|| "verify"), &g, &pk, &h).unwrap();

    assert_eq!(cs.num_constraints(), 8027);
    assert_eq!(cs.aux().len(), 8010);
    assert!(cs.is_satisfied());
  }
}
