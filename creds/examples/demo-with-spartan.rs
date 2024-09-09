use ark_bn254::{Bn254 as ECPairing, Fr};
//use ark_bls12_381::Bls12_381 as ECPairing;
use ark_circom::{CircomBuilder, CircomConfig};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_std::io::BufWriter;
use jwt_ac::rangeproof::RangeProofPK;
use ark_std::{end_timer, rand::thread_rng, start_timer};
use jwt_ac::{
    groth16rand::ClientState,
    structs::{GenericInputsJSON, IOLocations, ProverAuxInputs, ProverInput},
};
use spartan_ecdsa::{ECDSAParams, ECDSAProof, NamedCurve};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{
    env,
    fs::{self, OpenOptions},
};

// cargo run --release --features print-trace --example demo-with-spartan es256k-spartan -- --nocapture

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

    let prover_inputs_path = format!("{}prover_inputs.json", base_path);
    let prover_inputs = GenericInputsJSON::new(&prover_inputs_path);

    let io_locations_path = format!("{}io_locations.sym", base_path);
    let io_locations = IOLocations::new(&io_locations_path);

    let prover_aux_inputs_path = format!("{}prover_aux.json", base_path);
    let prover_aux_inputs = ProverAuxInputs::new_from_file(&prover_aux_inputs_path);

    let mut client_state;
    let spartan_prover_key: Vec<u8>;
    let spartan_verifier_key: Vec<u8>;
    if use_cache {
        // TODO: if loading from cache fails; delete the /cache dir
        let load_timer = start_timer!(|| "Loading client state");
        client_state =
            ClientState::<ECPairing>::new_from_file(&format!("{}client_state.bin", &cache_path));
        end_timer!(load_timer);

        // TODO: loading the groth16 params takes 12 seconds. We need logic to do this only if necessary
        // let load_timer = start_timer!(||"Loading Groth16 params");
        // let f = File::open(&format!("{}groth16_params.bin", &cache_path)).unwrap();
        // let buf_reader = BufReader::new(f);
        // params = ProvingKey::deserialize_uncompressed_unchecked(buf_reader).unwrap(); // Groth16 params
        // end_timer!(load_timer);

        let load_timer = start_timer!(|| "Loading Spartan prover and verifier keys");
        spartan_prover_key = std::fs::read(&format!("{}spartan_pk.bin", &cache_path)).unwrap();
        spartan_verifier_key = std::fs::read(&format!("{}spartan_vk.bin", &cache_path)).unwrap();
        end_timer!(load_timer);
    } else {
        let circom_timer = start_timer!(|| "Circom Reading");
        let cfg = CircomConfig::<ECPairing>::new(
            &format!("{}main.wasm", base_path),
            &format!("{}main_c.r1cs", base_path),
        )
        .unwrap();
        let mut builder = CircomBuilder::new(cfg);
        prover_inputs.push_inputs(&mut builder);

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
        println!("Public inputs: {:?}", inputs);

        let proof = Groth16::<ECPairing>::prove(&params, circom, &mut rng).unwrap();

        let pvk = Groth16::<ECPairing>::process_vk(&params.vk).unwrap();

        let verify_timer = start_timer!(|| "Groth16 verify");
        let verified =
            Groth16::<ECPairing>::verify_with_processed_vk(&pvk, &inputs, &proof).unwrap();
        assert!(verified);
        end_timer!(verify_timer);

        let ecdsa_params = ECDSAParams::new(NamedCurve::Secp256k1, NamedCurve::Bn254);
        (spartan_prover_key, spartan_verifier_key) = ECDSAProof::setup(&ecdsa_params);

        client_state = ClientState::<ECPairing>::new(
            inputs.clone(),
            proof.clone(),
            params.vk.clone(),
            pvk.clone(),
        );

        println!("Serializing state to {}", cache_path);
        fs::create_dir(&cache_path).unwrap();
        client_state.write_to_file(&format!("{}client_state.bin", &cache_path));

        let params_file = format!("{}groth16_params.bin", &cache_path);
        let f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(params_file)
            .unwrap();
        let buf_writer = BufWriter::new(f);
        params.serialize_uncompressed(buf_writer).unwrap();

        std::fs::write(
            &format!("{}spartan_pk.bin", &cache_path),
            &spartan_prover_key,
        )
        .unwrap();
        std::fs::write(
            &format!("{}spartan_vk.bin", &cache_path),
            &spartan_verifier_key,
        )
        .unwrap();
    }

    let (range_pk, range_vk) = RangeProofPK::<ECPairing>::setup(32);

    //*** Prover  ***
    println!("");
    let prover_timer = start_timer!(||"Prover's time to create presentation proof");
    let digest248_pos = io_locations.get_io_location("digest_248").unwrap();
    let exp_value_pos = io_locations.get_io_location("exp_value").unwrap();

    // Default to all hidden:
    let mut io_types = vec![jwt_ac::structs::PublicIOType::Hidden; client_state.inputs.len()]; 
    // The digest is committed, for the spartan-ecdsa sub-prover:
    io_types[digest248_pos - 1] = jwt_ac::structs::PublicIOType::Committed;
    // Also the token expiry is committed, for the RP sub-prover: (TODO: add RP)
    io_types[exp_value_pos - 1] = jwt_ac::structs::PublicIOType::Committed;
    // For now we refer to digest commitment as the first committed attribute, 
    // the exp_value is the 2nd. TODO: this will be changed once we use a hashmap to refer to these by name
    let digest_commitment_index = 0;
    let exp_value_commitment_index = 1;

    let groth_showing = client_state.show_groth16(&io_types);
    let mut revealed_inputs = client_state.inputs.clone();
    revealed_inputs.remove(exp_value_pos - 1);
    revealed_inputs.remove(digest248_pos - 1);

    let ecdsa_showing = client_state.show_ecdsa(
        &prover_aux_inputs,
        &spartan_prover_key,
        digest_commitment_index
    );

    // Prover Range proof
    let rp_prover_timer = start_timer!(||"Prover time to create range proof");
    let cur_time = Fr::from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    );

    let mut com_exp_value = client_state.committed_input_openings[exp_value_commitment_index].clone();
    com_exp_value.m -= cur_time;
    com_exp_value.c -= com_exp_value.bases[0] * cur_time;
    let show_range = client_state.show_range(&com_exp_value, 32, &range_pk);
    
    end_timer!(rp_prover_timer);
    end_timer!(prover_timer);

    //*** Verifier  ***
    println!("");
    let verifier_timer = start_timer!(||"Verifier's time to check presentation proof");    

    groth_showing.verify(&client_state.vk, &client_state.pvk, &io_types, &revealed_inputs);        

    ecdsa_showing.verify(
        &client_state.pvk,
        &spartan_verifier_key,
        &prover_aux_inputs.get("pk_x"),
        &prover_aux_inputs.get("pk_y"),
        digest_commitment_index
    );    
    let rp_verifier_timer = start_timer!(||"Verifier time to check range proof");
    let mut ped_com_exp_value = groth_showing.commited_inputs[exp_value_commitment_index].clone();
    ped_com_exp_value -= client_state.pvk.vk.gamma_abc_g1[exp_value_pos] * cur_time;
    show_range.verify(
        &ped_com_exp_value,
        32,
        &range_vk,
        &io_locations,
        &client_state.pvk,
        "exp_value",
    );    

    end_timer!(rp_verifier_timer);
    end_timer!(verifier_timer);

    let mut groth_showing_bytes = Vec::new();
    groth_showing
        .serialize_compressed(&mut groth_showing_bytes)
        .unwrap();
    println!("Show proof size: {} bytes", groth_showing_bytes.len());

    let mut ecdsa_showing_bytes = Vec::new();
    ecdsa_showing
        .serialize_compressed(&mut ecdsa_showing_bytes)
        .unwrap();
    println!(
        "Spartan ECDSA proof size: {} bytes",
        ecdsa_showing_bytes.len()
    );

    let mut show_range_bytes = Vec::new();
    show_range
        .serialize_compressed(&mut show_range_bytes)
        .unwrap();
    println!("Range proof size: {} bytes", show_range_bytes.len());    

    let mut vk_bytes = Vec::new();
    client_state.vk
        .serialize_compressed(&mut vk_bytes)
        .unwrap();
    println!("Groth16 verifier key size: {} bytes", vk_bytes.len());       

    let mut range_vk_bytes = Vec::new();
    range_vk
        .serialize_compressed(&mut range_vk_bytes)
        .unwrap();
    println!("Range proof verifier key size: {} bytes", range_vk_bytes.len());        

}
