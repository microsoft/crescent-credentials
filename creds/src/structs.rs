// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::utils::bigint_from_str;
use ark_bn254::Bn254 as ECPairing;
use num_bigint::BigUint;
use num_traits::FromPrimitive;
use serde_json::{Map, Value};
use std::{collections::BTreeMap, io::ErrorKind};

#[cfg(not(feature = "wasm"))]
use ark_circom::CircomBuilder;

#[cfg(not(feature = "wasm"))]
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
        let sym_file = std::fs::read_to_string(path).unwrap();
        Self::new_from_str(&sym_file)
    }

    pub fn new_from_str(io_data: &str) -> Self {
        let mut public_io_locations = BTreeMap::default();        
        for line in io_data.lines() {
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

    pub fn get_public_key_indices(&self) -> Vec<usize> {
        let mut indices = vec![];
        for key in self.public_io_locations.keys() {
            if key.starts_with("modulus") || key.starts_with("pubkey") {
                indices.push(*self.public_io_locations.get(key).unwrap() - 1);
            }
        }
        indices.sort();
        
        indices
    }

    pub fn get_all_names(&self) -> Vec<String> {
        let mut keys = vec![];
        for key in self.public_io_locations.keys() {
           keys.push(key.clone());
        }        

        keys
    }
}

#[cfg(not(feature = "wasm"))]
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
                    builder.push_input(key, bigint_from_str(s));
                }
                serde_json::Value::Array(arr) => {
                    for v in arr.iter() {
                        if let serde_json::Value::String(s) = v {
                            builder.push_input(key, bigint_from_str(s));
                        } 
                        else if let serde_json::Value::Number(n) = v {
                            builder.push_input(key, BigUint::from_u64(n.as_u64().unwrap()).unwrap());
                        }                            
                        else if let serde_json::Value::Array(nested_arr) = v {
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
                serde_json::Value::Number(n) => {
                    builder.push_input(key, BigUint::from_u64(n.as_u64().unwrap()).unwrap());                    
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
                Ok(bigint_from_str(s))
            }
            _ => {
                Err(std::io::Error::new(
                    ErrorKind::Other,
                    "Key not found or is not a string",
                ))
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
                Ok(vec)
            }
            _ => {
                Err(std::io::Error::new(
                    ErrorKind::Other,
                    "Key not found or is not an array",
                ))
            }
        }
    }
}

