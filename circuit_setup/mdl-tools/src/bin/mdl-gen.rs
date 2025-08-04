// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// This program generates a mDL file using the provided inputs.
// TODO: add config file to read validity info (currently, valid for 1 year from current time)
//
// Usage:
//    mdl-gen -c <claims> -d <device_priv_key> -k <issuer_private_key> -x <issuer_x5chain> -o <mdl>
// where
//    <claims> is a JSON file containing the claims to be included in the mDL
//    <device_priv_key> is the device private key, in PEM format 
//    <issuer_private_key> is the issuer's private key, in PEM format
//    <issuer_x5chain> is the issuer's X.509 certificate chain, in PEM format
//    <mdl> is the output file for the mDL, in CBOR format
//
// Notes:
//    - The claims JSON file should contain two keys: "org.iso.18013.5.1" and "org.iso.18013.5.1.aamva"
//    - The device key can be generated using the ../scripts/gen_mdl_device_key.sh script
//    - The issuer key and cert chain can be generated using the ../scripts/gen_x509_cert_chain.sh script
//    - To test: cargo run --bin mdl-gen -- -c ../inputs/mdl1/claims.json -d ../inputs/mdl1/device.prv
//                                          -k ../inputs/mdl1/issuer.prv -x ../inputs/mdl1/issuer_certs.pem
//                                          -o ../generated_files/mdl1/mdl.cbor

use std::collections::BTreeMap;

use clap::Parser;
use elliptic_curve::sec1::ToEncodedPoint;
use isomdl::definitions::namespaces::org_iso_18013_5_1::OrgIso1801351;
use isomdl::definitions::namespaces::org_iso_18013_5_1_aamva::OrgIso1801351Aamva;
use isomdl::definitions::traits::{FromJson, ToNamespaceMap};
use isomdl::definitions::x509::X5Chain;
use isomdl::definitions::{CoseKey, DeviceKeyInfo, DigestAlgorithm, EC2Curve, ValidityInfo, EC2Y};
use isomdl::issuance::mdoc::{Builder, Mdoc};
use isomdl::cbor;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;
use p256::SecretKey;
use time::OffsetDateTime;

static MDL_DOCTYPE: &str = "org.iso.18013.5.1.mDL";
static ISO_MDL_NAMESPACE: &str = "org.iso.18013.5.1";
static AAMVA_MDL_NAMESPACE: &str = "org.iso.18013.5.1.aamva";

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// JSON file containing the mDL ISO claims
    #[arg(short = 'c', long= "claims")]
    claims: String,

    /// Device's private key (PEM format)
    #[arg(short = 'd', long = "device_priv_key")]
    device_priv_key: String,

    /// Issuer's private key (PEM format)
    #[arg(short = 'k', long = "issuer_private_key")]
    issuer_private_key: String,

    /// Issuer's X509 certificate chain (PEM format)
    #[arg(short = 'x', long = "issuer_x5chain")]
    issuer_x5chain: String,

    /// Output file for the mDL (CBOR format)
    #[arg(short = 'o', long = "output")]
    mdl: String,
}

fn mdoc_builder(claims: String, device_priv_key: String) -> Builder {
    // Parse the claims.json content into a serde_json::Value
    let parsed: serde_json::Value = serde_json::from_str(&claims).unwrap();

    // Handle the ISO MDL namespace
    let isomdl_claims = parsed.get(ISO_MDL_NAMESPACE)
        .ok_or_else(|| format!("Missing key: {ISO_MDL_NAMESPACE}"))
        .unwrap();
    let isomdl_data = OrgIso1801351::from_json(isomdl_claims)
        .unwrap()
        .to_ns_map();
    
    // Handle the optional AAMVA namespace
    let aamva_data_opt = parsed.get(AAMVA_MDL_NAMESPACE).map(|claims| {
        OrgIso1801351Aamva::from_json(claims)
            .unwrap()
            .to_ns_map()
    });

    // Build the namespaces mapping
    
    let mut namespaces = BTreeMap::new();
    namespaces.insert(ISO_MDL_NAMESPACE.to_string(), isomdl_data);
    if let Some(aamva_data) = aamva_data_opt {
        namespaces.insert(AAMVA_MDL_NAMESPACE.to_string(), aamva_data);
    }

    // TODO: should read these values from a config file
    let now = OffsetDateTime::now_utc();
    let validity_info = ValidityInfo {
        signed: now,
        valid_from: now,
        valid_until: now + time::Duration::days(365),
        expected_update: None,
    };

    let digest_algorithm = DigestAlgorithm::SHA256;

    let priv_key = SecretKey::from_pkcs8_pem(device_priv_key.as_str()).unwrap();
    let pub_key = priv_key.public_key();
    let ec = pub_key.to_encoded_point(false);
    let x = ec.x().unwrap().to_vec();
    let y = EC2Y::Value(ec.y().unwrap().to_vec());
    let device_key = CoseKey::EC2 {
        crv: EC2Curve::P256,
        x,
        y,
    };

    let device_key_info = DeviceKeyInfo {
        device_key,
        key_authorizations: None,
        key_info: None,
    };

    Mdoc::builder()
        .doc_type(MDL_DOCTYPE.to_string())
        .namespaces(namespaces)
        .validity_info(validity_info)
        .digest_algorithm(digest_algorithm)
        .device_key_info(device_key_info)
        .enable_decoy_digests(false)
}

fn generate_mdl(claims: String, device_pub_key: String, private_key_pem: String, x5chain_pem: String) -> Vec<u8> {
    let mdoc_builder = mdoc_builder(claims, device_pub_key);

    let pem_blocks = pem::parse_many(x5chain_pem.as_bytes()).unwrap();
    let mut builder = X5Chain::builder();
    for block in pem_blocks {
        // If the builder accepts DER, pass block.contents; otherwise, you could
        // pass the PEM block as bytes if using with_pem_certificate.
        builder = builder.with_der_certificate(&block.contents).unwrap();
    }
    let x5chain = builder
        .build()
        .unwrap();
    let signer: SigningKey = SecretKey::from_pkcs8_pem(private_key_pem.as_str())
        .expect("failed to parse pem")
        .into();

    let mdoc = mdoc_builder
        .issue::<SigningKey, Signature>(x5chain, signer)
        .expect("failed to issue mdoc");

    // serialize the mdoc to a CBOR byte array
    cbor::to_vec(&mdoc).unwrap()
}

fn main() {
    // Parse command-line arguments
    let args = Args::parse();

    // Read the claims JSON file
    let claims_data = std::fs::read_to_string(&args.claims)
        .expect("Failed to read claims file");

    let device_priv_key_data = std::fs::read_to_string(&args.device_priv_key)
        .expect("Failed to read device public key file");

    // Read the issuer's private key file
    let issuer_private_key_data = std::fs::read_to_string(&args.issuer_private_key)
        .expect("Failed to read issuer private key file");

    // Read the issuer's certificate file
    let issuer_x5chain_data = std::fs::read_to_string(&args.issuer_x5chain)
        .expect("Failed to read issuer certificate chain file");

    // Generate the mDL
    let mdl_data = generate_mdl(claims_data, device_priv_key_data, issuer_private_key_data, issuer_x5chain_data);

    // Write the mDL to the output file
    std::fs::write(&args.mdl, mdl_data)
        .expect("Failed to write output mDL file");
    println!("mDL written to {}", args.mdl);
}
