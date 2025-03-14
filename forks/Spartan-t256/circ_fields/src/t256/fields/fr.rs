#![allow(non_local_definitions)]

use ark_ff::fields::{Fp256, MontBackend, MontConfig};

#[derive(MontConfig)]
#[modulus = "115792089210356248762697446949407573530086143415290314195533631308867097853951"]
#[generator = "1"]
/// FrConfig
pub struct FrConfig;
/// Scalar field
pub type Fr = Fp256<MontBackend<FrConfig, 4>>;