use crate::{
    dlog::{DLogPoK, PedersenOpening},
    rangeproof::{RangeProof, RangeProofPK, RangeProofVK},
    structs::{IOLocations, ProverAuxInputs, PublicIOType},
    utils::{add_to_transcript, biguint_to_scalar, msm_select},
};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, Group, VariableBaseMSM};
use ark_ff::{BigInt, PrimeField};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    end_timer,
    fs::File,
    io::{BufReader, BufWriter},
    rand::thread_rng,
    start_timer, UniformRand, Zero,
};
use merlin::Transcript;
use num_bigint::BigUint;
use rayon::ThreadPoolBuilder;
use spartan_ecdsa::{ECDSAParams, ECDSAProof, NamedCurve};
use std::fs::OpenOptions;
use std::ops::AddAssign;


// The (mutatable) state of the client. This struct will have methods that generate showings
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ClientState<E: Pairing> {
    pub inputs: Vec<E::ScalarField>, // public inputs parsed into field elements.
    pub proof: Proof<E>,
    pub vk: VerifyingKey<E>,
    pub pvk: PreparedVerifyingKey<E>,
    input_com_randomness: Option<E::ScalarField>,
    pub committed_input_openings: Vec<PedersenOpening<E::G1>>, //TODO: make this into a hashmap
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
        proof: Proof<E>,
        vk: VerifyingKey<E>,
        pvk: PreparedVerifyingKey<E>,
    ) -> Self {
        Self {
            inputs,
            proof,
            vk,
            pvk,
            input_com_randomness: None,
            committed_input_openings: Vec::new(),
        }
    }

    pub fn new_from_file(path: &str) -> Self {
        let f = File::open(path).unwrap();
        let buf_reader = BufReader::new(f);

        let state = ClientState::<E>::deserialize_uncompressed_unchecked(buf_reader).unwrap();

        state
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

    pub fn show_groth16(&mut self, io_types: &Vec<PublicIOType>) -> ShowGroth16<E> 
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
                    hidden_input_bases.push(self.pvk.vk.gamma_abc_g1[i + 1].into());
                    hidden_input_scalars.push(self.inputs[i]);
                }
                PublicIOType::Committed => {
                    let r = E::ScalarField::rand(&mut rng);
                    acc_r += r;

                    let c : E::G1 = msm_select(&[self.vk.delta_g1, self.pvk.vk.gamma_abc_g1[i + 1]], &[r, self.inputs[i]]);

                    let ped_bases = vec![
                        self.pvk.vk.gamma_abc_g1[i + 1].clone(),
                        self.vk.delta_g1.clone(),
                    ];

                    bases.push(ped_bases.iter().map(|x| x.clone().into()).collect());
                    scalars.push(vec![self.inputs[i], r]);
                    y.push(c.clone());

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
        hidden_input_bases.push(self.vk.delta_g1.into());

        let com_hidden_inputs: E::G1 = msm_select(&hidden_input_bases, &hidden_input_scalars);
        self.input_com_randomness = Some(z);

        scalars.push(hidden_input_scalars);
        bases.push(hidden_input_bases.iter().map(|x| x.into_group()).collect());    // TODO: can we avoid?
        y.push(com_hidden_inputs.clone());

        rand_proof.c =
            (rand_proof.c.into_group() + E::G1::generator() * (-(acc_r + z))).into_affine();

        // Generate a proof of knowledge of private inputs (input1, input2, ..., input_n, z) such that
        // com_l = l1^input1 l2^input2 ... ln^input_n g^z
        // optimized to ignore public inputs

        let pok_inputs = DLogPoK::<E::G1>::prove(&y, &bases, &scalars, None);
        
        end_timer!(groth16_timer);

        ShowGroth16 {
            rand_proof,
            com_hidden_inputs,
            pok_inputs,
            commited_inputs: committed_input_openings
                .iter()
                .map(|x| x.c.clone())
                .collect(),
        }
    }

    // TODO: can/should we add some context here?
    pub(crate) fn derive_commitment_challenge(com1: &E::G1, com2: &E::G1) -> String {
        let mut ts: Transcript = Transcript::new(b"Challenge for commitment in NIZK adapter");
        add_to_transcript(&mut ts, b"com1", com1);
        add_to_transcript(&mut ts, b"com2", com2);
        let mut c_bytes = [0u8; 30]; // 248 bit challenge
        ts.challenge_bytes(&[0u8], &mut c_bytes);
        hex::encode(c_bytes)
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
        let bound = <E as Pairing>::ScalarField::try_from((1u64 << n) as u64).unwrap();
        assert!(ped_open.m < bound);

        // Use the custom thread pool for parallel operations
        pool.install(|| {
            range_proof = RangeProof::prove_n_bits(ped_open, n, &range_pk.powers);
        });

        ShowRange { range_proof }
    }

    /// Show knowledge of an ecdsa signature using a spartan proof
    pub fn show_ecdsa(
        &self,
        prover_aux_inputs: &ProverAuxInputs,
        spartan_prover_key: &Vec<u8>,
        digest_commitment_index: usize
    ) -> ShowECDSA<E> 
        where <E::G1 as Group>::ScalarField : PrimeField
    {
        type G1Scalar<E> = <<E as Pairing>::G1 as Group>::ScalarField;
        let ecdsa_timer = start_timer!(|| "Prove committed digest is ECDSA-signed");

        // Create the proof for the ECDSA signature
        assert!(prover_aux_inputs.ensure_has_inputs(vec![
            "digest".to_string(),
            "signature_r".to_string(),
            "signature_s".to_string(),
            "pk_x".to_string(),
            "pk_y".to_string()
        ]));
        let digest = prover_aux_inputs.get("digest");
        let pk_x = prover_aux_inputs.get("pk_x");
        let pk_y = prover_aux_inputs.get("pk_y");
        let r = prover_aux_inputs.get("signature_r");
        let s = prover_aux_inputs.get("signature_s");

        let digest_pedersen = &self.committed_input_openings[digest_commitment_index];        

        let params = ECDSAParams::new(NamedCurve::Secp256k1, NamedCurve::Bn254); // TODO: the BN curve should be from a central config
        let commitment_opening = ECDSAProof::commit_digest_part1(&params, &digest);
        let mask = ECDSAProof::get_mask(&commitment_opening);
        let mask = biguint_to_scalar(&BigUint::from_bytes_le(&mask));

        let mask_commitment = DLogPoK::pedersen_commit(&mask, &digest_pedersen.bases);
        let challenge = Self::derive_commitment_challenge(&mask_commitment.c, &digest_pedersen.c);
        let (commitment, commitment_opening) =
            ECDSAProof::commit_digest_part2(&params, commitment_opening, &challenge);
        let spartan_proof = ECDSAProof::prove(
            &params,
            &spartan_prover_key,
            &digest,
            &pk_x,
            &pk_y,
            &r,
            &s,
            &challenge,
            &commitment_opening,
        );
        // We need to prove that the digest_commitment is well-formed with a sigma proof
        // The input commitment digest_pedersen commits to an IO value h such that c = h*challenge + H(h, k)
        let digest_commitment = biguint_to_scalar::<G1Scalar<E>>(&BigUint::from_bytes_le(&commitment));
        let h = digest_pedersen.m;

        // Sanity check: ensure h and digest are equal
        let digest_scalar = <G1Scalar<E>>::from_be_bytes_mod_order(&hex::decode(&digest[0..62]).unwrap());
        assert_eq!(h, digest_scalar);

        // Create the sigma proof
        let dl_proof = DLogPoK::<E::G1>::prove_for_ecdsa(
            &mask_commitment,
            &digest_pedersen,
            &digest_commitment,
            &challenge,
        );

        end_timer!(ecdsa_timer);

        ShowECDSA {
            dl_proof,
            spartan_proof,
            digest_commitment: commitment,
        }
    }
}

impl<E: Pairing> ShowECDSA<E> {
    pub fn verify(
        &self,
        //vk: &VerifyingKey<E>,
        pvk: &PreparedVerifyingKey<E>,
        spartan_verifier_key: &Vec<u8>,
        pk_x: &str,
        pk_y: &str,
        digest_commitment_index: usize
    ) 
        where <E::G1 as Group>::ScalarField : PrimeField
    {
        type G1Scalar<E> = <<E as Pairing>::G1 as Group>::ScalarField;     
        let verify_timer = start_timer!(|| "Verify credential with external ECDSA proof");

        // Check the sigma proof
        let digest_commitment = biguint_to_scalar::<G1Scalar<E>>(&BigUint::from_bytes_le(&self.digest_commitment));

        let challenge = ClientState::<E>::derive_commitment_challenge(
            &self.dl_proof.extra_values.as_ref().unwrap().z,
            &self.dl_proof.extra_values.as_ref().unwrap().l_prime,
        );

        // TODO: can we avoid this conversion between G1 and G1Affine and later unconversion in verify_for_ecdsa
        let pedersen_bases = vec![
            pvk.vk.gamma_abc_g1[digest_commitment_index + 1].clone().into_group(),      
            pvk.vk.delta_g1.clone().into_group(),
        ];

        let result = self.dl_proof.verify_for_ecdsa(
            &pedersen_bases,
            &digest_commitment,
            &challenge,
        );

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);

        // Check the ECDSA proof
        let params = ECDSAParams::new(NamedCurve::Secp256k1, NamedCurve::Bn254);
        let is_valid = ECDSAProof::verify(
            &params,
            spartan_verifier_key,
            pk_x,
            pk_y,
            &self.spartan_proof,
            &challenge,
            &self.digest_commitment,
        );
        assert!(is_valid);

        end_timer!(verify_timer);
    }
}

impl<E: Pairing> ShowGroth16<E> {
    pub fn verify(
        &self,
        vk: &VerifyingKey<E>,
        pvk: &PreparedVerifyingKey<E>,
        io_types: &Vec<PublicIOType>,
        public_inputs: &Vec<E::ScalarField>,
    ) 
    where
        E: Pairing,
        E::G1 : CurveGroup + VariableBaseMSM,      
    {
        let groth16_timer = start_timer!(||"Verify Groth16 show proof");
        let mut com_inputs = self.com_hidden_inputs.clone() + pvk.vk.gamma_abc_g1[0];

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
                        pvk.vk.gamma_abc_g1[i + 1].clone().into(),
                        vk.delta_g1.clone().into(),
                    ]);
                }
            }
        }
        com_inputs += msm_select::<E::G1>(&revealed_input_bases, &revealed_input_scalars);
        hidden_input_bases.push(vk.delta_g1.into());

        bases.push(hidden_input_bases);
        y.push(self.com_hidden_inputs);

        let t = start_timer!(||"Groth16 verify proof with prepared inputs");
        assert!(Groth16::<E>::verify_proof_with_prepared_inputs(
            pvk,
            &self.rand_proof,
            &com_inputs
        )
        .unwrap());
        end_timer!(t);

        let is_valid = self.pok_inputs.verify(&bases, &y, None).unwrap();
        
        end_timer!(groth16_timer);

        assert!(is_valid);
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
    ) {
        let input_pos = io_locations.get_io_location(input_label).unwrap();
        let bases = [
            pvk.vk.gamma_abc_g1[input_pos].into(),
            pvk.vk.delta_g1.into(),
        ];
        self.range_proof.verify_n_bits(ped_com, &bases, n, range_vk);
    }
}