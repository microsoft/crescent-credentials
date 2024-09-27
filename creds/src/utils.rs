use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::thread_rng;
use merlin::Transcript;
use num_bigint::BigUint;
use sha2::{Digest, Sha512};
use std::fs::OpenOptions;
use ark_std::{io::BufWriter, io::BufReader, fs::File};


#[macro_export]
macro_rules! return_error {
    ($msg:expr) => {
        return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, $msg)))
    };
}

pub fn bigint_from_str(s: &str) -> num_bigint::BigUint {
    num_bigint::BigUint::parse_bytes(s.as_bytes(), 10).unwrap()
}

pub fn add_to_transcript<T: CanonicalSerialize>(
    transcript: &mut Transcript,
    label: &'static [u8],
    message: &T,
) {
    let mut bytes = Vec::new();
    message.serialize_compressed(&mut bytes).unwrap();
    transcript.append_message(label, &bytes);

    // Uncomment this to help debug; shows what prover and verifier are hashing
    //println!("challenge hash includes {} : {}", std::str::from_utf8(label).expect("Invalid UTF-8"), hex::encode(bytes));
}

// This function should only be used to derive points when `input` is a public value.
// Since hashing to Bn254 is not supported in arkworks, we use a basic hunt-and-peck implementation
// that will work with any curve.  Timing side channels are not a problem when hashing public inputs.
pub fn hash_to_curve_vartime<G>(input: &str) -> G::Affine
where
    G: CurveGroup,
{
    let mut counter = 0;
    loop {
        let input_iter = format!("{}||{}", input, counter);
        let mut hasher = Sha512::new();
        hasher.update(input_iter);
        let digest = hasher.finalize();

        let point = G::Affine::from_random_bytes(&digest);
        if point.is_some() {
            return point.unwrap();
        }
        counter = counter + 1;
    }
}

pub fn biguint_to_scalar<F: PrimeField>(a: &BigUint) -> F {
    let a_bigint = F::BigInt::try_from(a.clone()).unwrap();
    let a_scalar = F::from_bigint(a_bigint).unwrap();

    a_scalar
}

pub fn random_vec<F: PrimeField>(n: usize) -> Vec<F> {
    let mut rng = thread_rng();
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(F::rand(&mut rng));
    }

    v
}

#[inline]
pub fn direct_msm<G: CurveGroup>(bases: &[G::Affine], scalars: &[G::ScalarField]) -> G {
    assert_eq!(bases.len(), scalars.len());

    let mut res = G::zero();
    for (base, scalar) in bases.iter().zip(scalars) {
        res += (*base) * scalar;
    }
    res
}

#[inline]
pub fn msm_select<G: CurveGroup>(bases: &[G::Affine], scalars: &[G::ScalarField]) -> G {
    assert_eq!(bases.len(), scalars.len());

    // TODO: I added this layer of indirection because the arkworks MSM code has high variability
    // and often appears to take much longer than the equivalent number of scalar multiplications. 
    // For small number of bases (say n=2-5), we can probably do better much better with a handwritten 
    // implementation. n=2, the Pedersen case, should probably have a dedicated implementation since it's
    // very common.  For now we always call the arkworks msm code
    if bases.len() > 2 {
        G::msm(bases, scalars).unwrap()
    }
    else {
        direct_msm(bases, scalars)
    }
}

pub fn write_to_file<T>(obj : &T, path: &str)
where 
    T: CanonicalSerialize
{
    let f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .unwrap();
    let buf_writer = BufWriter::new(f);
    obj.serialize_uncompressed(buf_writer).unwrap();
}

pub fn new_from_file<T>(path: &str) -> T 
where
    T: CanonicalDeserialize
{
    let f = File::open(path).unwrap();
    let buf_reader = BufReader::new(f);
    let state = T::deserialize_uncompressed_unchecked(buf_reader).unwrap();

    state
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_bn254::Bn254;
    use ark_ec::pairing::Pairing;
    use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
    use ark_std::{end_timer, start_timer};

    fn test_hash_to_curve_vartime_with<E: Pairing, P1: SWCurveConfig, P2: SWCurveConfig>()
    where
        E: Pairing<G1Affine = Affine<P1>> + Pairing<G2Affine = Affine<P2>>,
    {
        let timer = start_timer!(|| "Time to generate three points");
        for i in 1..4 {
            let point = hash_to_curve_vartime::<E::G1>(&format!("test string {}", i));
            assert!(point.is_on_curve());
            println!("point_{} in G1 = {:?}", i, point);
        }
        end_timer!(timer);
    }

    #[test]
    fn test_hash_to_curve_vartime() {
        println!("Testing hash_to_curve with BN254");
        test_hash_to_curve_vartime_with::<Bn254, ark_bn254::g1::Config, ark_bn254::g2::Config>();
        println!("Testing hash_to_curve with BLS12-381");
        test_hash_to_curve_vartime_with::<
            Bls12_381,
            ark_bls12_381::g1::Config,
            ark_bls12_381::g2::Config,
        >();
    }
}
