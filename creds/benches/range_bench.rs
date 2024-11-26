// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::time::Duration;
use criterion::{criterion_group, criterion_main, Criterion};
use crescent::{dlog::DLogPoK, rangeproof::{RangeProof, RangeProofPK}, CrescentPairing, CrescentFr};
use ark_ff::PrimeField;
use ark_ec::AffineRepr;
use rayon::ThreadPoolBuilder;

type G1 = <CrescentPairing as ark_ec::pairing::Pairing>::G1;

pub fn range_proof_benchmark(c: &mut Criterion) {

    const N_BITS : usize = 32;
    let token_exp_int = ark_ff::BigInt::from(1754434613 as u32);
    let token_exp = CrescentFr::from_bigint(token_exp_int).unwrap();

    let (range_pk, range_vk) = RangeProofPK::<CrescentPairing>::setup(N_BITS);

    let cur_time = CrescentFr::from(1754434613 - 5);
    let bases = DLogPoK::<G1>::derive_pedersen_bases();
    let mut com_exp = DLogPoK::pedersen_commit(&token_exp, &bases);
    com_exp.m -= cur_time;
    com_exp.c -= com_exp.bases[0] * cur_time;
    
    // force the range proof to run in single-threaded mode
    let pool = ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .expect("Failed to create thread pool");

    let mut range_proof = RangeProof::default();

    c.bench_function(&format!("RangeProof prover time, {}-bit secret", N_BITS), |b| {
        b.iter(|| {

            // Use the custom thread pool for parallel operations
            pool.install(|| {
                range_proof = RangeProof::prove_n_bits(&com_exp, N_BITS, &range_pk.powers);
            });

        })
    });

    let mut ped_com_exp = com_exp.c;
    ped_com_exp -= com_exp.bases[0] * cur_time;

    let bases_proj = [com_exp.bases[0].into_group(), com_exp.bases[1].into_group()];
    
    c.bench_function(&format!("RangeProof verifier time, {}-bit secret", N_BITS), |b| {
        b.iter(|| {    
            range_proof.verify_n_bits(&ped_com_exp, &bases_proj, N_BITS, &range_vk);
        })
    });
 
}

criterion_group!{
    name = benches;
    // This can be any expression that returns a `Criterion` object.
    config = Criterion::default().significance_level(0.05).sample_size(100).measurement_time(Duration::from_secs(50)).warm_up_time(Duration::from_secs(5));
    targets = range_proof_benchmark
}

criterion_main!(benches);
