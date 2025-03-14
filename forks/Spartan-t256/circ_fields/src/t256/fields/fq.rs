#![allow(non_local_definitions)]

use ark_ff::fields::{Fp256, MontBackend, MontConfig};

#[derive(MontConfig)]
#[modulus = "115792089210356248762697446949407573530594504085698471288169790229257723883799"]
#[generator = "3"]
/// FqConfig
pub struct FqConfig;
/// Base field
pub type Fq = Fp256<MontBackend<FqConfig, 4>>;
