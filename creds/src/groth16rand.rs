// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::{
    dlog::{DLogPoK, PedersenOpening},
    rangeproof::{RangeProof, RangeProofPK, RangeProofVK},
    structs::{IOLocations, PublicIOType},
    utils::msm_select
};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, Group, VariableBaseMSM};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    end_timer,
    fs::File,
    io::{BufReader, BufWriter},
    rand::thread_rng,
    start_timer, UniformRand, Zero,
};
use rayon::ThreadPoolBuilder;
use std::fs::OpenOptions;


// The (mutatable) state of the client. This struct will have methods that generate showings
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ClientState<E: Pairing> {
    pub inputs: Vec<E::ScalarField>, // public inputs parsed into field elements.
    pub aux: Option<String>, // Auxiliary data required by the prover
    pub proof: Proof<E>,
    pub vk: VerifyingKey<E>,
    pub pvk: PreparedVerifyingKey<E>,
    input_com_randomness: Option<E::ScalarField>,
    pub committed_input_openings: Vec<PedersenOpening<E::G1>>, //TODO: make this into a hashmap
    pub credtype : String,
    pub config_str: String
}

/// An unlinkable showing of a valid groth16 proof satisfying a particular NP relation
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ShowGroth16<E: Pairing> {
    pub rand_proof: Proof<E>,
    pub com_hidden_inputs: E::G1,
    pub pok_inputs: DLogPoK<E::G1>,
    pub commited_inputs: Vec<E::G1>,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ShowRange<E: Pairing> {
    pub range_proof: RangeProof<E>,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ShowECDSA<E: Pairing> {
    pub spartan_proof: Vec<u8>,
    pub digest_commitment: Vec<u8>,
    pub dl_proof: DLogPoK<E::G1>,
}

impl<E: Pairing> ClientState<E> {
    pub fn new(
        inputs: Vec<E::ScalarField>,
        aux: Option<String>,
        proof: Proof<E>,
        vk: VerifyingKey<E>,
        pvk: PreparedVerifyingKey<E>,
        config_str: String
    ) -> Self {
        Self {
            inputs,
            proof,
            aux,
            vk,
            pvk,
            input_com_randomness: None,
            committed_input_openings: Vec::new(),
            credtype : "jwt".to_string(), 
            config_str
        }
    }

    pub fn new_from_file(path: &str) -> Self {
        let f = File::open(path).unwrap();
        let buf_reader = BufReader::new(f);
        
        ClientState::<E>::deserialize_uncompressed_unchecked(buf_reader).unwrap()
    }

    pub fn write_to_file(&self, file: &str) {
        let f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(file)
            .unwrap();
        let buf_writer = BufWriter::new(f);

        self.serialize_uncompressed(buf_writer).unwrap();
    }

    pub fn show_groth16(&mut self, context: Option<&[u8]>, io_types: &[PublicIOType]) -> ShowGroth16<E> 
    where
        <E as Pairing>::G1: CurveGroup + VariableBaseMSM,  
    {
        let groth16_timer = start_timer!(||"Create Groth16 showing proof");
        debug_assert_eq!(self.inputs.len(), io_types.len());

        let mut rng = thread_rng();
        let rerand_timer = start_timer!(||"Re-randomize proof");
        let mut rand_proof = Groth16::<E>::rerandomize_proof(&self.vk, &self.proof, &mut rng);
        end_timer!(rerand_timer);

        let mut committed_input_openings: Vec<PedersenOpening<E::G1>> = Vec::new();

        let mut y = Vec::new();
        let mut bases: Vec<Vec<<E as Pairing>::G1>> = Vec::new();
        let mut scalars = Vec::new();

        let mut hidden_input_bases = vec![];
        let mut hidden_input_scalars = vec![];

        let mut acc_r = E::ScalarField::zero(); // accumulate the randomness used for committed inputs and subtract from proof.c
        for i in 0..io_types.len() {
            match io_types[i] {
                PublicIOType::Revealed => (), //ignore if input is revealed as it needs to be aggregated by the verifier
                PublicIOType::Hidden => {
                    hidden_input_bases.push(self.pvk.vk.gamma_abc_g1[i + 1]);
                    hidden_input_scalars.push(self.inputs[i]);
                }
                PublicIOType::Committed => {
                    let r = E::ScalarField::rand(&mut rng);
                    acc_r += r;

                    let c : E::G1 = msm_select(&[self.vk.delta_g1, self.pvk.vk.gamma_abc_g1[i + 1]], &[r, self.inputs[i]]);

                    let ped_bases = vec![
                        self.pvk.vk.gamma_abc_g1[i + 1],
                        self.vk.delta_g1,
                    ];

                    bases.push(ped_bases.iter().map(|x| (*x).into()).collect());
                    scalars.push(vec![self.inputs[i], r]);
                    y.push(c);

                    committed_input_openings.push(PedersenOpening {
                        bases: ped_bases,
                        c,
                        r,
                        m: self.inputs[i],
                    });
                }
            }
        }

        self.committed_input_openings = committed_input_openings.clone();

        let z = E::ScalarField::rand(&mut rng);
        hidden_input_scalars.push(z);
        hidden_input_bases.push(self.vk.delta_g1);

        let com_hidden_inputs: E::G1 = msm_select(&hidden_input_bases, &hidden_input_scalars);
        self.input_com_randomness = Some(z);

        scalars.push(hidden_input_scalars);
        bases.push(hidden_input_bases.iter().map(|x| x.into_group()).collect());
        y.push(com_hidden_inputs);

        rand_proof.c =
            (rand_proof.c.into_group() + E::G1::generator() * (-(acc_r + z))).into_affine();

        // Generate a proof of knowledge of private inputs (input1, input2, ..., input_n, z) such that
        // com_l = l1^input1 l2^input2 ... ln^input_n g^z
        // optimized to ignore public inputs

        let pok_inputs = DLogPoK::<E::G1>::prove(context, &y, &bases, &scalars, None);
        
        end_timer!(groth16_timer);

        ShowGroth16 {
            rand_proof,
            com_hidden_inputs,
            pok_inputs,
            commited_inputs: committed_input_openings
                .iter()
                .map(|x| x.c)
                .collect(),
        }
    }

    /// Prove that a certain input to the groth16 proof is in [0,2^n)
    /// Takes as input
    /// 1. label of the input
    /// 2. n: the number of bits
    pub fn show_range(
        &self,
        ped_open: &PedersenOpening<E::G1>,
        n: usize,
        range_pk: &RangeProofPK<E>,
    ) -> ShowRange<E> {
        // force the range proof to run in single-threaded mode
        let pool = ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .expect("Failed to create thread pool");

        // prove that input is in [0, 2^n)
        let mut range_proof = RangeProof::default();
        assert!(n < 64);
        let bound = <E as Pairing>::ScalarField::from(1u64 << n);
        assert!(ped_open.m < bound);

        // Use the custom thread pool for parallel operations
        pool.install(|| {
            range_proof = RangeProof::prove_n_bits(ped_open, n, &range_pk.powers);
        });

        ShowRange { range_proof }
    }


}



impl<E: Pairing> ShowGroth16<E> {
    pub fn verify(
        &self,
        vk: &VerifyingKey<E>,
        pvk: &PreparedVerifyingKey<E>,
        context: Option<&[u8]>,
        io_types: &[PublicIOType],
        public_inputs: &[E::ScalarField],
    ) -> bool
    where
        E: Pairing,
        E::G1 : CurveGroup + VariableBaseMSM,      
    {
        let groth16_timer = start_timer!(||"Verify Groth16 show proof");
        let mut com_inputs = self.com_hidden_inputs + pvk.vk.gamma_abc_g1[0];

        let mut public_input_index = 0;
        let mut committed_input_index = 0;
        let mut hidden_input_bases = vec![];

        let mut bases: Vec<Vec<<E as Pairing>::G1>> = Vec::new();
        let mut y = self.commited_inputs.clone();

        let mut revealed_input_bases = vec![];
        let mut revealed_input_scalars = vec![];

        for i in 0..io_types.len() {
            match io_types[i] {
                PublicIOType::Revealed => {
                    revealed_input_bases.push(pvk.vk.gamma_abc_g1[i + 1]);
                    revealed_input_scalars.push(public_inputs[public_input_index]);
                    public_input_index += 1;
                }
                PublicIOType::Hidden => {
                    hidden_input_bases.push(pvk.vk.gamma_abc_g1[i + 1].into());
                }
                PublicIOType::Committed => {
                    com_inputs += self.commited_inputs[committed_input_index];
                    committed_input_index += 1;

                    bases.push(vec![
                        pvk.vk.gamma_abc_g1[i + 1].into(),
                        vk.delta_g1.into(),
                    ]);
                }
            }
        }
        com_inputs += msm_select::<E::G1>(&revealed_input_bases, &revealed_input_scalars);
        hidden_input_bases.push(vk.delta_g1.into());

        bases.push(hidden_input_bases);
        y.push(self.com_hidden_inputs);

        let t = start_timer!(||"Groth16 verify proof with prepared inputs");
        let groth16_result = Groth16::<E>::verify_proof_with_prepared_inputs(
            pvk,
            &self.rand_proof,
            &com_inputs
        );
        let groth16_valid = match groth16_result {
            Ok(b) => b, 
            Err(e) => {
                println!("Failed to verify Groth16 proof with error: {:?}", e);
                false
            }
        };
        end_timer!(t);

        let dlog_pok_valid = self.pok_inputs.verify(context, &bases, &y, None);
        
        end_timer!(groth16_timer);

        groth16_valid && dlog_pok_valid

    }
}

impl<E: Pairing> ShowRange<E> {
    pub fn verify(
        &self,
        ped_com: &E::G1,
        n: usize,
        range_vk: &RangeProofVK<E>,
        io_locations: &IOLocations,
        pvk: &PreparedVerifyingKey<E>,
        input_label: &str,
    ) -> bool {
        let input_pos = io_locations.get_io_location(input_label).unwrap();
        let bases = [
            pvk.vk.gamma_abc_g1[input_pos].into(),
            pvk.vk.delta_g1.into(),
        ];
        
        self.range_proof.verify_n_bits(ped_com, &bases, n, range_vk)
    }
}
