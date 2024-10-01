use ark_bn254::{Bn254 as ECPairing, Fr};
//use ark_bls12_381::Bls12_381 as ECPairing;
use ark_circom::{CircomBuilder, CircomConfig};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::Groth16;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_std::{end_timer, rand::thread_rng, start_timer};
use crescent::rangeproof::{RangeProofPK, RangeProofVK};
use crescent::structs::{PublicIOType, IOLocations};
use crescent::prep_inputs::unpack_int_to_string_unquoted;
use crescent::{
    groth16rand::ClientState,
    structs::{GenericInputsJSON, ProverInput},
};

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{fs, env};
use crescent::utils::{new_from_file, write_to_file};
use crescent::CachePaths;
use crescent::prep_inputs::{parse_config, prepare_prover_inputs};

// Run this file with the command:
// cargo run --release --features print-trace --example demo rs256 -- --nocapture

fn main() {
    let mut args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        args = vec!["".to_string(), "demo".to_string()];
    }
    println!("\nUsing circuit and inputs from test-vectors/{}", args[1]);
    let base_path = format!("{}/test-vectors/{}/", env!("CARGO_MANIFEST_DIR"), args[1]);

    let mut use_cache = false;
    let cache_path = format!("{}cache/", base_path);
    if fs::metadata(&cache_path).is_ok() {
        println!("Using cached proof data");
        use_cache = true;
    }
    let paths = CachePaths::new(PathBuf::from(base_path.clone()));
    let jwt = fs::read_to_string(&paths.jwt).expect(&format!("Unable to read JWT file from {}", paths.jwt));
    let issuer_pem = fs::read_to_string(&paths.issuer_pem).expect(&format!("Unable to read issuer public key PEM from {} ", paths.issuer_pem));
    let config_str = fs::read_to_string(&paths.config).expect(&format!("Unable to read config from {} ", paths.config));
    let config = parse_config(config_str).expect("Failed to parse config");
    let (prover_inputs_json, _prover_aux_json, _public_ios_json) = 
         prepare_prover_inputs(&config, &jwt, &issuer_pem).expect("Failed to prepare prover inputs");   

    let io_locations_path = format!("{}io_locations.sym", base_path);
    let io_locations = IOLocations::new(&io_locations_path);

    let mut client_state;
    let pvk;
    let vk;
    let range_pk : RangeProofPK::<ECPairing>;
    let range_vk : RangeProofVK::<ECPairing>;
    if use_cache {
        // TODO: if loading from cache fails; delete the /cache dir
        let load_timer = start_timer!(|| "Loading client state");
        client_state =
            ClientState::<ECPairing>::new_from_file(&format!("{}client_state.bin", &cache_path));
        end_timer!(load_timer);

        vk = client_state.vk.clone();
        pvk = client_state.pvk.clone();

        range_pk = new_from_file(&format!("{}range_pk.bin", &cache_path));
        range_vk = new_from_file(&format!("{}range_vk.bin", &cache_path));

        // TODO: loading the groth16 params takes 12 seconds. We need logic to do this only if necessary
        // let load_timer = start_timer!(||"Loading Groth16 params");
        // let f = File::open(&format!("{}groth16_params.bin", &cache_path)).unwrap();
        // let buf_reader = BufReader::new(f);
        // params = ProvingKey::deserialize_uncompressed_unchecked(buf_reader).unwrap(); // Groth16 params
        // end_timer!(load_timer);
    } else {
        let circom_timer = start_timer!(|| "Circom Reading");
        let cfg = CircomConfig::<ECPairing>::new(
            &format!("{}main.wasm", base_path),
            &format!("{}main_c.r1cs", base_path),
        )
        .unwrap();
        let mut builder = CircomBuilder::new(cfg);
        //prover_inputs.push_inputs(&mut builder);

        let circom = builder.setup();
        end_timer!(circom_timer);

        let mut rng = thread_rng();
        let params =
            Groth16::<ECPairing>::generate_random_parameters_with_reduction(circom, &mut rng)
                .unwrap();

        let build_timer = start_timer!(|| "Building");
        let circom = builder.build().unwrap();
        end_timer!(build_timer);

        let inputs = circom.get_public_inputs().unwrap();

        let proof = Groth16::<ECPairing>::prove(&params, circom, &mut rng).unwrap();

        vk = params.vk.clone();
        pvk = Groth16::<ECPairing>::process_vk(&params.vk).unwrap();

        let verify_timer = start_timer!(|| "Groth16 verify");
        let verified =
            Groth16::<ECPairing>::verify_with_processed_vk(&pvk, &inputs, &proof).unwrap();
        assert!(verified);
        end_timer!(verify_timer);

        client_state = ClientState::<ECPairing>::new(
            inputs.clone(),
            proof.clone(),
            params.vk.clone(),
            pvk.clone(),
        );

        let (p, v) = RangeProofPK::<ECPairing>::setup(32);
        range_pk = p;   // Compiler doesn't see that range_pk, vk are initialized if part of a tuple on the prev. line
        range_vk = v;

        println!("Serializing state to {}", cache_path);
        fs::create_dir(&cache_path).unwrap();

        client_state.write_to_file(&format!("{}client_state.bin", &cache_path));
        write_to_file(&range_pk, &format!("{}range_pk.bin", &cache_path));
        write_to_file(&range_vk, &format!("{}range_vk.bin", &cache_path));

        let params_file = format!("{}groth16_params.bin", &cache_path);
        write_to_file(&params, &params_file);

    }

    let exp_value_pos = io_locations.get_io_location("exp_value").unwrap();
    let email_value_pos = io_locations.get_io_location("email_value").unwrap();
    let mut io_types = vec![PublicIOType::Revealed; client_state.inputs.len()];
    io_types[exp_value_pos - 1] = PublicIOType::Committed;
    io_types[email_value_pos - 1] = PublicIOType::Revealed;

    let mut revealed_inputs = client_state.inputs.clone();
    revealed_inputs.remove(exp_value_pos - 1);

    let cur_time = Fr::from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    );

    let now = std::time::Instant::now();
    let groth_showing = client_state.show_groth16(&io_types);

    let mut com_exp_value = client_state.committed_input_openings[0].clone();
    com_exp_value.m -= cur_time;
    com_exp_value.c -= com_exp_value.bases[0] * cur_time;
    let show_range = client_state.show_range(&com_exp_value, 32, &range_pk);
    println!("Proving time: {:?}", now.elapsed());

    let now = std::time::Instant::now();
    groth_showing.verify(&vk, &pvk, &io_types, &revealed_inputs);

    let mut ped_com_exp_value = groth_showing.commited_inputs[0].clone();
    ped_com_exp_value -= pvk.vk.gamma_abc_g1[exp_value_pos] * cur_time;
    show_range.verify(
        &ped_com_exp_value,
        32,
        &range_vk,
        &io_locations,
        &pvk,
        "exp_value",
    );
    println!("Verification time: {:?}", now.elapsed());

    // TODO: it's currently hacky how the verifier knows which revealed inputs correspond 
    // to what.  In this example we have to subtract 2 (rather than 1) from email_value pos to account for
    // the committed attribute.  When we refactor revealed inputs and the modulus IOs we can address this.
    let domain = unpack_int_to_string_unquoted( &revealed_inputs[email_value_pos - 2].into_bigint()).unwrap();
    println!("Token is valid, Prover revealed email domain: {}", domain);    

    let mut groth_showing_bytes = Vec::new();
    groth_showing
        .serialize_compressed(&mut groth_showing_bytes)
        .unwrap();
    println!("Show proof size: {} bytes", groth_showing_bytes.len());

    let mut show_range_bytes = Vec::new();
    show_range
        .serialize_compressed(&mut show_range_bytes)
        .unwrap();
    println!("Range proof size: {} bytes", show_range_bytes.len());
    

}
