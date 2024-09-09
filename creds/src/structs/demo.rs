use ark_bn254::Bn254 as ECPairing;
//use ark_bls12_381::Bls12_381 as ECPairing;
use ark_circom::CircomBuilder;
use serde::{Deserialize, Serialize};

use crate::utils::bigint_from_str;

use super::ProverInput;

#[derive(Serialize, Deserialize)]
pub struct DemoInputsJSON {
    message: Vec<String>,
    signature: Vec<String>,
    modulus: Vec<String>,
    exp_assert_not_expired_current_ts: String,
    message_padded_bytes: String,
    period_idx: String,
    exp_l: String,
    exp_r: String,
    email_l: String,
    email_r: String,
}

impl ProverInput for DemoInputsJSON {
    fn new(path: &str) -> Self {
        let prover_inputs: DemoInputsJSON =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        // start parsing the prover inputs

        prover_inputs
    }

    fn push_inputs(&self, builder: &mut CircomBuilder<ECPairing>) {
        for value in self.message.clone() {
            builder.push_input("message", bigint_from_str(&value));
        }

        for value in self.signature.clone() {
            builder.push_input("signature", bigint_from_str(&value));
        }

        for value in self.modulus.clone() {
            builder.push_input("modulus", bigint_from_str(&value));
        }

        builder.push_input(
            "exp_assert_not_expired_current_ts",
            bigint_from_str(&self.exp_assert_not_expired_current_ts),
        );
        builder.push_input(
            "message_padded_bytes",
            bigint_from_str(&self.message_padded_bytes),
        );
        builder.push_input("period_idx", bigint_from_str(&self.period_idx));
        builder.push_input("exp_l", bigint_from_str(&self.exp_l));
        builder.push_input("exp_r", bigint_from_str(&self.exp_r));
        builder.push_input("email_l", bigint_from_str(&self.email_l));
        builder.push_input("email_r", bigint_from_str(&self.email_r));
        builder.push_input("dummy", 99);
    }
}
