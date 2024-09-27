use crate::utils::bigint_from_str;
use ark_bn254::Bn254 as ECPairing;
//use ark_bls12_381::Bls12_381 as ECPairing;
use ark_circom::CircomBuilder;
use num_bigint::BigUint;
use serde_json::{Map, Value};
use std::{collections::BTreeMap, io::ErrorKind};
pub mod demo;
pub mod named_domain;

pub trait ProverInput {
    fn new(path: &str) -> Self;
    fn push_inputs(&self, builder: &mut CircomBuilder<ECPairing>);
}

#[derive(Clone, Debug, Default)]
pub struct GenericInputsJSON {
    pub prover_inputs: Map<String, Value>,
}

/// Groth16 IO locations
#[derive(Clone, Debug, Default)]
pub struct IOLocations {
    pub public_io_locations: BTreeMap<String, usize>,
}

/// An enum indication the type of each public io
#[derive(Clone, Debug, PartialEq)]
pub enum PublicIOType {
    Revealed,
    Hidden,
    Committed,
}

impl IOLocations {
    pub fn new(path: &str) -> Self {
        // main_clean.sym has rows of the form name,location
        // read the csv's from this file and store the value in a BTreeMap
        let mut public_io_locations = BTreeMap::default();
        let sym_file = std::fs::read_to_string(path).unwrap();
        for line in sym_file.lines() {
            let parts: Vec<&str> = line.split(",").collect();
            if parts.len() == 2 {
                let name = parts[0].to_string();
                let location = parts[1].parse::<usize>().unwrap();
                public_io_locations.insert(name, location);
            } else {
                panic!(
                    "Line {} in io_locations.sym is not formatted correctly! Found {} parts.",
                    line,
                    parts.len()
                );
            }
        }

        Self {
            public_io_locations,
        }
    }

    pub fn get_io_location(&self, key: &str) -> Result<usize, std::io::Error> {
        match self.public_io_locations.get(key) {
            Some(location) => Ok(*location),
            None => Err(std::io::Error::new(
                ErrorKind::Other,
                "Key not found in public_io_locations",
            )),
        }
    }
}

impl ProverInput for GenericInputsJSON {
    fn new(path: &str) -> Self {
        let prover_inputs = serde_json::from_str::<Value>(&std::fs::read_to_string(path).unwrap())
            .unwrap()
            .as_object()
            .unwrap()
            .clone();

        Self { prover_inputs }
    }

    // This implementation just pushes whatever inputs are in the JSON file directly to the builder,
    // without first storing it in a struct. This is useful when the inputs file changes,
    // we don't need a code change.
    fn push_inputs(&self, builder: &mut CircomBuilder<ECPairing>) {
        for (key, value) in &self.prover_inputs {
            match value {
                serde_json::Value::String(s) => {
                    builder.push_input(key, bigint_from_str(&s));
                }
                serde_json::Value::Array(arr) => {
                    for v in arr.iter() {
                        if let serde_json::Value::String(s) = v {
                            builder.push_input(key, bigint_from_str(s));
                        } else if let serde_json::Value::Array(nested_arr) = v {
                            for v2 in nested_arr.iter() {
                                if let serde_json::Value::String(s) = v2 {
                                    builder.push_input(key, bigint_from_str(s));
                                } else {
                                    panic!("invalid input; value in nested array is not of type String");
                                }
                            }
                        } else {
                            panic!("invalid input (1)");
                        }
                    }
                }
                _ => panic!("invalid input (2)"),
            };
        }
    }
}

impl GenericInputsJSON {
    pub fn get(&self, key: &str) -> Result<BigUint, std::io::Error> {
        match &self.prover_inputs[key] {
            serde_json::Value::String(s) => {
                return Ok(bigint_from_str(&s));
            }
            _ => {
                return Err(std::io::Error::new(
                    ErrorKind::Other,
                    "Key not found or is not a string",
                ));
            }
        }
    }
    pub fn get_array(&self, key: &str) -> Result<Vec<BigUint>, std::io::Error> {
        match &self.prover_inputs[key] {
            serde_json::Value::Array(a) => {
                let mut vec = Vec::<BigUint>::new();
                for elt in a.iter() {
                    if let serde_json::Value::String(s) = elt {
                        vec.push(bigint_from_str(s));
                    }
                }
                return Ok(vec);
            }
            _ => {
                return Err(std::io::Error::new(
                    ErrorKind::Other,
                    "Key not found or is not an array",
                ));
            }
        }
    }
}

pub struct ProverAuxInputs {
    inputs: Value,
}

impl ProverAuxInputs {
    pub fn new_from_file(path: &str) -> Self {
        let json_data = &std::fs::read_to_string(path);
        if json_data.is_err() {
            println!(
                "Failed to read prover auxiliary inputs from file: '{}'\n{:?}",
                path, json_data
            );
            panic!("Exiting");
        }
        let prover_inputs = serde_json::from_str(&json_data.as_ref().unwrap());
        if prover_inputs.is_err() {
            println!(
                "Failed to parse prover auxiliary inputs from file: '{}'\n{:?}",
                path, prover_inputs
            );
            panic!("Exiting");
        }
        let prover_inputs: Value = prover_inputs.unwrap();

        Self {
            inputs: prover_inputs.clone(),
        }
    }

    pub fn ensure_has_inputs(&self, keys: Vec<String>) -> bool {
        for key in keys {
            if self.inputs[&key] == "" {
                println!("ProveAuxInputs, missing value for key: {}", key);
                return false;
            }
        }
        return true;
    }

    pub fn get(&self, key: &str) -> String {
        match &self.inputs[&key] {
            serde_json::Value::String(s) => {
                return s.clone();
            }
            _ => {
                panic!();
            }
        }
    }
}

// TODO: Need to generate this from crescent
// Example prover aux file for the es256k-nohash example (test_vectors/es256k-spartan/prover_aux.json)
// {
//     "digest" : "AE1AB30CE075F12CADB7F66ED3C8FC0B0B203AC206F381C6E2BDC1498402BCEA",
//     "signature_r" : "C6FBBDB372303F3B65CBFCF16FF7FC4DBF6ACD921E40C93DB8207A860DB41850",
//     "signature_s" : "0C61995E52329CBC955A8B7891F461D8C5D1DD965E353BDF5214A1BAC9284AB2",
//     "pk_x" : "BB8552F9F4B5EA4159EBFE9A42F8CC5B209E8CEDD3A2D0E36F1B7DB39FB45693",
//     "pk_y" : "B4169332E1F00C8A10AA18806235295D2596F00D13EA2921B5A20C89ACEBC822"
// }
