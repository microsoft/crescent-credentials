use ark_bn254::{Bn254 as ECPairing, Fr};
use ark_circom::{CircomBuilder, CircomConfig};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_std::io::BufWriter;
use ark_std::{end_timer, rand::thread_rng, start_timer};
use jwt_ac::rangeproof::RangeProofPK;
use jwt_ac::structs::{IOLocations, PublicIOType};
use jwt_ac::{
    groth16rand::ClientState,
    structs::{GenericInputsJSON, ProverInput},
};

use std::time::{SystemTime, UNIX_EPOCH};
use std::{
    env,
    fs::{self, OpenOptions},
};

// cargo run --features print-trace --example demo-sd sd -- --nocapture

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

    let mut client_state;
    let pvk;
    let vk;
    if use_cache {
        // TODO: if loading from cache fails; delete the /cache dir
        let load_timer = start_timer!(|| "Loading client state");
        client_state =
            ClientState::<ECPairing>::new_from_file(&format!("{}client_state.bin", &cache_path));
        end_timer!(load_timer);

        vk = client_state.vk.clone();
        pvk = client_state.pvk.clone();

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
    }

    // Range proof. TODO: Load setup params from file if it exists
    let (range_pk, range_vk) = RangeProofPK::<ECPairing>::setup(32);

    //*** Prover  ***
    println!("");
    let prover_timer = start_timer!(||"Prover's time to create presentation proof");    

    let exp_value_pos = io_locations.get_io_location("exp_value").unwrap();
    println!("num inputs: {}", client_state.inputs.len());
    println!("Keys = {:?}", io_locations.public_io_locations.keys());
    // Set all to Hidden by default
    let mut io_types = vec![jwt_ac::structs::PublicIOType::Hidden; client_state.inputs.len()];
    // Set exp to Committed so the range prover can use it
    io_types[exp_value_pos - 1] = jwt_ac::structs::PublicIOType::Committed;
    // Set the modulus values to public (TODO: need to use the public_IOs.json file instead of hardcoding)
    for i in 0..17 {
        let modulus_i_pos = io_locations.get_io_location(&format!("modulus[{}]", i)).expect("Didn't find RSA modulus in IOs. Expected RSA-2048, with the public modulus encoded as 17 limbs");
        io_types[modulus_i_pos - 1] = PublicIOType::Revealed;
    }
    // Reveal claims 1 and 6
    let claim1_value_pos = io_locations.get_io_location("claim01_value").unwrap();
    let claim6_value_pos = io_locations.get_io_location("claim06_value").unwrap();
    io_types[claim1_value_pos - 1] = PublicIOType::Revealed;
    io_types[claim6_value_pos - 1] = PublicIOType::Revealed;
    
    let mut revealed_inputs = vec![];
    for i in 0..client_state.inputs.len() {
        if io_types[i] == PublicIOType::Revealed {
            revealed_inputs.push(client_state.inputs[i]);
        }
    }

    let now = std::time::Instant::now();
    let groth_showing = client_state.show_groth16(&io_types);
    println!("Groth16 Proving time: {:?}", now.elapsed());   

    // Prover Range proof
    let rp_prover_timer = start_timer!(||"Prover time to create range proof");
    let cur_time = Fr::from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    );

    let mut com_exp_value = client_state.committed_input_openings[0].clone();
    com_exp_value.m -= cur_time;
    com_exp_value.c -= com_exp_value.bases[0] * cur_time;
    
    let show_range = client_state.show_range(&com_exp_value, 32, &range_pk);

    end_timer!(rp_prover_timer);
    end_timer!(prover_timer);

    println!("Proving time: {:?}", now.elapsed());  

    //*** Verifier  ***
    println!("");
    let verifier_timer = start_timer!(||"Verifier's time to check presentation proof");       
    
    let now = std::time::Instant::now();
    groth_showing.verify(&vk, &pvk, &io_types, &revealed_inputs);   
    println!("Groth16 Verify time: {:?}", now.elapsed());         

    let rp_verifier_timer = start_timer!(||"Verifier time to check range proof");
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

    end_timer!(rp_verifier_timer);
    end_timer!(verifier_timer);

    // Output sizes
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
