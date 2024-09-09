// Copied and modified from https://github.com/nalinbhardwaj/Nova-Scotia/blob/main/src/circom/reader.rs.
use crate::G;
use anyhow::bail;
use ff::{
    derive::byteorder::{LittleEndian, ReadBytesExt},
    PrimeField,
};
use spartan2::{traits::Group};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufReader, Read},
    path::Path,
    process::Command,
    str,
};

use crate::{
    circuit::{R1CS, R1CSDimension},
    file::{from_reader, read_field},
};

pub fn generate_witness_from_wasm_with_input_file<Fr: PrimeField>(
    witness_wasm: &Path,
    witness_input_file: &Path,
    witness_output: &Path,
    quiet: bool,
) -> Vec<Fr> {
    // Extract the directory of witness_wasm.
    let witness_wasm_dir = witness_wasm.parent().unwrap();
    let witness_js = witness_wasm_dir.join("generate_witness.js");
    let output = Command::new("node")
        .arg(witness_js)
        .arg(witness_wasm)
        .arg(witness_input_file)
        .arg(witness_output)
        .output()
        .expect("failed to execute process");
    if !quiet || !output.status.success() {
        if output.status.success() {
            println!("Witness generation succeeded with status: {}", output.status);
        }
        else {
            println!("\nWitness generation FAILED with status: {}", output.status);
        }
        println!("Command was: '{} {} {}'", witness_wasm.to_str().unwrap(), &witness_input_file.to_str().unwrap(), witness_output.to_str().unwrap());
        if !output.stdout.is_empty() || !output.stderr.is_empty() {
            print!("stdout: {}", str::from_utf8(&output.stdout).unwrap());
            print!("stderr: {}", str::from_utf8(&output.stderr).unwrap());
        }
    }
    load_witness_from_bin_file(witness_output)
}

pub(crate) fn generate_witness_from_bin_with_input_file<Fr: PrimeField>(
    witness_bin: &Path,
    witness_input_file: &Path,
    witness_output: &Path,
    quiet: bool,
) -> Vec<Fr> {
    let output = Command::new(witness_bin)
        .arg(witness_input_file)
        .arg(witness_output)
        .output()
        .expect("failed to execute process");
    if !quiet || !output.status.success() {
        if output.status.success() {
            println!("Witness generation succeeded with status: {}", output.status);
        }
        else {
            println!("\nWitness generation FAILED with status: {}", output.status);
        }
        println!("Command was: '{} {} {}'", witness_bin.to_str().unwrap(), &witness_input_file.to_str().unwrap(), witness_output.to_str().unwrap());
        if !output.stdout.is_empty() || !output.stderr.is_empty() {
            print!("stdout: {}", str::from_utf8(&output.stdout).unwrap());
            print!("stderr: {}", str::from_utf8(&output.stderr).unwrap());
        }
    }
    load_witness_from_bin_file(witness_output)
}

/// load witness from bin file by filename
pub fn load_witness_from_bin_file<Fr: PrimeField>(filename: &Path) -> Vec<Fr> {
    let reader = OpenOptions::new()
        .read(true)
        .open(filename)
        .expect("unable to open.");
    load_witness_from_bin_reader::<Fr, BufReader<File>>(BufReader::new(reader))
        .expect("read witness failed")
}

/// load witness from u8 array by a reader
pub(crate) fn load_witness_from_bin_reader<Fr: PrimeField, R: Read>(
    mut reader: R,
) -> Result<Vec<Fr>, anyhow::Error> {
    let mut wtns_header = [0u8; 4];
    reader.read_exact(&mut wtns_header)?;
    if wtns_header != [119, 116, 110, 115] {
        // ruby -e 'p "wtns".bytes' => [119, 116, 110, 115]
        bail!("invalid file header");
    }
    let version = reader.read_u32::<LittleEndian>()?;
    // println!("wtns version {}", version);
    if version > 2 {
        bail!("unsupported file version");
    }
    let num_sections = reader.read_u32::<LittleEndian>()?;
    if num_sections != 2 {
        bail!("invalid num sections");
    }
    // read the first section
    let sec_type = reader.read_u32::<LittleEndian>()?;
    if sec_type != 1 {
        bail!("invalid section type");
    }
    let sec_size = reader.read_u64::<LittleEndian>()?;
    if sec_size != 4 + 32 + 4 {
        bail!("invalid section len")
    }
    let field_size = reader.read_u32::<LittleEndian>()?;
    if field_size != 32 {
        bail!("invalid field byte size");
    }
    let mut prime = vec![0u8; field_size as usize];
    reader.read_exact(&mut prime)?;

    let witness_len = reader.read_u32::<LittleEndian>()?;
    // println!("witness len {}", witness_len);
    let sec_type = reader.read_u32::<LittleEndian>()?;
    if sec_type != 2 {
        bail!("invalid section type");
    }
    let sec_size = reader.read_u64::<LittleEndian>()?;
    if sec_size != (witness_len * field_size) as u64 {
        bail!("invalid witness section size {}", sec_size);
    }
    let mut result = Vec::with_capacity(witness_len as usize);
    for _ in 0..witness_len {
        result.push(read_field::<&mut R, Fr>(&mut reader)?);
    }
    Ok(result)
}

#[cfg(not(target_family = "wasm"))]
/// load r1cs file
pub fn load_r1cs(filename: &Path) -> R1CS<<G as Group>::Scalar> {
    let reader = OpenOptions::new()
        .read(true)
        .open(filename)
        .expect("unable to open.");
    let file = from_reader(BufReader::new(reader), false).expect("unable to read.");
    let num_inputs = (1 + file.header.n_pub_in + file.header.n_pub_out) as usize;
    let num_variables = file.header.n_wires as usize;
    let num_aux = num_variables - num_inputs;
    R1CS {
        num_aux,
        num_inputs,
        num_variables,
        constraints: file.constraints,
    }
}

pub fn load_r1cs_dimension(filename: &Path) -> R1CSDimension {
    let reader = OpenOptions::new()
        .read(true)
        .open(filename)
        .expect("unable to open.");
    let file = from_reader(BufReader::new(reader), true).expect("unable to read.");
    let num_inputs = (1 + file.header.n_pub_in + file.header.n_pub_out) as usize;
    let num_variables = file.header.n_wires as usize;
    let num_aux = num_variables - num_inputs;
    R1CSDimension {
        num_inputs,
        num_aux,
        num_variables,
    }
}

#[cfg(target_family = "wasm")]
pub use crate::circom::wasm::load_r1cs;

pub(crate) fn load_input_from_json_file<Fr: PrimeField>(filename: &Path) -> Vec<Fr> {
    let file = fs::File::open(filename).expect("file open failed");
    let reader = BufReader::new(file);

    let file_contents: serde_json::Value =
        serde_json::from_reader(reader).expect("json parse failed");
    let mut io = Vec::new();
    
    // Convert values to field elements
    for (_key, value) in file_contents.as_object().unwrap() {
        match value {
            serde_json::Value::String(s) => {
                let value = Fr::from_str_vartime(s).expect("parse input failed");
                io.push(value);
            }
            serde_json::Value::Array(arr) => {
                for v in arr.iter() {
                    if let serde_json::Value::String(s) = v {
                        let value = Fr::from_str_vartime(s).expect("parse input failed");
                        io.push(value);
                    } else if let serde_json::Value::Array(nested_arr) = v{
                        for v2 in nested_arr.iter() {
                            if let serde_json::Value::String(s) = v2 {
                                let value = Fr::from_str_vartime(s).expect("parse input failed");
                                io.push(value);
                            }
                            else {
                                panic!("invalid input; value in nested array is not of type String");
                            }
                        }
                    }
                    else {
                        panic!("invalid input");
                    }
                }
            }
            _ => panic!("invalid input"),
        };
    }

    io
}