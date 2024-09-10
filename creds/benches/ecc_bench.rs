use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};
use ark_ec::{pairing::Pairing, CurveGroup};
use ark_bn254::{Bn254, Fr};
use ark_ec::VariableBaseMSM;
use ark_std::{rand::SeedableRng, UniformRand};
use crescent::utils::msm_select;



pub fn ecc_bn254_benchmark(c: &mut Criterion) {
    const MSM_LEN : usize = 12;
    let rng = &mut ark_std::rand::rngs::StdRng::seed_from_u64(0u64);
    let rand_g1 = <Bn254 as Pairing>::G1::rand(rng);
    let rand_g2 = <Bn254 as Pairing>::G2::rand(rng);

    let mut bases = vec![];
    let mut bases2 = vec![];
    let mut scalars = vec![];
    for _ in 0..MSM_LEN {
        bases.push(<Bn254 as Pairing>::G1::rand(rng).into_affine());
        bases2.push(<Bn254 as Pairing>::G2::rand(rng).into_affine());
        scalars.push(Fr::rand(rng));
    }

    // G1
    c.bench_function(&format!("Bn254 G1 scalar mul time"), |b| {
        b.iter(|| {
            let _res = bases[0] * scalars[0];
        })
    });    

    c.bench_function(&format!("Bn254 G1 MSM of length {}", 2), |b| {
        b.iter(|| {
            let _res = <Bn254 as Pairing>::G1::msm(&[bases[0], bases[1]], &[scalars[0], scalars[1]]);
        })
    });
    c.bench_function(&format!("Bn254 G1 MSM_select of length {}", 2), |b| {
        b.iter(|| {
            let _res : <Bn254 as Pairing>::G1 = msm_select(&[bases[0], bases[1]], &[scalars[0], scalars[1]]);
        })
    });    

    let len = 10;
    c.bench_function(&format!("Bn254 G1 MSM of length {}", len), |b| {
        b.iter(|| {
            let _res = <Bn254 as Pairing>::G1::msm(&bases[0..len], &scalars[0..len]);
        })
    });
    c.bench_function(&format!("Bn254 G1 MSM_select of length {}", len), |b| {
        b.iter(|| {
            let _res : <Bn254 as Pairing>::G1 = msm_select(&bases[0..len], &scalars[0..len]);
        })
    });

    
    // G2
    c.bench_function(&format!("Bn254 G2 scalar mul time"), |b| {
        b.iter(|| {
            let _res = bases2[0] * scalars[0];
        })
    });    

    c.bench_function(&format!("Bn254 G2 MSM of length {}", MSM_LEN), |b| {
        b.iter(|| {
            let _res = <Bn254 as Pairing>::G2::msm(&bases2, &scalars.as_slice());
        })
    });

    c.bench_function(&format!("Bn254 G2 MSM of length {}", 2), |b| {
        b.iter(|| {
            let _res = <Bn254 as Pairing>::G2::msm(&[bases2[0], bases2[1]], &[scalars[0], scalars[1]]);
        })
    });
    c.bench_function(&format!("Bn254 G2 MSM_select of length {}", 2), |b| {
        b.iter(|| {
            let _res : <Bn254 as Pairing>::G2 = msm_select(&[bases2[0], bases2[1]], &[scalars[0], scalars[1]]);
        })
    });     

    // Pairing
    c.bench_function("Bn254 pairing", |b| {
        b.iter(|| {
            let _pairing = Bn254::pairing(rand_g1, rand_g2);
        })
    });    




    // BBS estimates with BN 254 params
    // https://github.com/mattrglobal/node-bbs-signatures
    // Estimate the proof costs using appendix A of https://eprint.iacr.org/2023/275.pdf
    // TODO: An actual BBS implementation that we can compare against: https://github.com/mattrglobal/pairing_crypto
    //       (but it uses BLS12-381)
    /*
    let f = 32;  // size of a G1 scalar field
    let g1 = f;  // size of a G1 element
    let _g2 = 2*f;  
    let sig_size_bytes = g1 + 2*f;
    println!("Signature size: {} bytes", sig_size_bytes);

    let no_of_hidden_messages = 10;
    let proof_size_bytes = 3*g1 + (3 + no_of_hidden_messages)*f;
    println!("Number of hidden attributes = {}", no_of_hidden_messages);
    println!("Proof size: {} bytes", proof_size_bytes);

    let sm_time = 0.05;
    let msm_time = 0.34;  // msm of size 2 + no_of_hidden_messages
    let prover_time = 2.0*sm_time + msm_time;
    println!("Prover time estimate: {} ms", prover_time);

    let pairing_time = 0.55;
    let verifier_time = 2.0*pairing_time + msm_time + sm_time;
    println!("Verifier time estimate: {} ms", verifier_time);
    */
    
}

criterion_group!{
    name = benches;
    // This can be any expression that returns a `Criterion` object.
    config = Criterion::default().significance_level(0.1).sample_size(5000).measurement_time(Duration::from_secs(10)).warm_up_time(Duration::from_secs(5));
    targets = ecc_bn254_benchmark
}

criterion_main!(benches);
