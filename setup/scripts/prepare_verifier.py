#!/usr/bin/python3

import jwcrypto.jwk as jwk
import sys, os
import json
import hashlib

from crescent_helper import *

##### Helper functions #########
def usage():
    print("Python3 script to prepare inputs for verifier")
    print("Usage:")
    print("\t./" + os.path.basename(sys.argv[0]) + " <config file> <issuer pub key PEM file> <public io file>")
    print("Example:")
    print("\tpython3 " + os.path.basename(sys.argv[0]) + " ../../config.json ../../sample_tokens/aad.pub  ../../inputs/public_io.json > ../../inputs/verifier_input.json")


def prepare_special_inputs(config):
    keys = list(config.keys())
    for name in keys:
        if name in CRESCENT_CONFIG_KEYS:
            continue
        if config[name].get("predicates") is not None:
            for predicate in config[name]["predicates"]:
                predicate_name = predicate["name"]
                pred_var_name = camel_to_snake(predicate_name)

                # Print special input for some predicates.
                if predicate.get("special_inputs") is not None:
                    for k, v in predicate["special_inputs"].items():
                        k_name = name + "_" + pred_var_name + "_" + k
                        if isinstance(v, list):
                            print_json_array(k_name, v)
                        elif isinstance(v, dict):
                            if v["value"] is not None:
                                if v["max_length"] is not None:
                                    val = v["value"]
                                    max_length = v["max_length"]
                                    arr = to_utf8_integers(val)
                                    arr.extend([0 for _ in range(max(0, max_length-len(arr)))])
                                    print_json_array(k_name, arr)
                        else:
                            print_json_value(k_name, v)

######## Main ###########

if len(sys.argv) != 4 : 
    usage()
    sys.exit(-1)

with open(sys.argv[1], "r") as f:
    config = json.load(f)

if not check_config(config):
    print("Invalid configuration file, exiting")
    sys.exit(-1)

# Load the issuer's public key
with open(sys.argv[2], "rb") as f:
    pub_key_pem = f.read()

pub_key = jwk.JWK.from_pem(pub_key_pem)
print_debug("Read issuer public key: \n" + str(pub_key_pem) + "\n")

print("{")

# Issuer Public key
if config['alg'] == 'RS256' :
    n = pub_key.export(as_dict=True)["n"]
    limbs = b64_to_circom_limbs(n, CIRCOM_RS256_LIMB_BITS)
    print_json_array("modulus", limbs, no_leading_comma=True)
elif config['alg'] == 'ES256K' :
    x_limbs = b64_to_circom_limbs(pub_key.x, CIRCOM_ES256K_LIMB_BITS)
    print_json_array("pubkey_x", x_limbs, no_leading_comma=True)
    y_limbs = b64_to_circom_limbs(pub_key.y, CIRCOM_ES256K_LIMB_BITS)
    print_json_array("pubkey_y", y_limbs)   

if config['reveal_all_claims'] :
    # Load the public inputs
    with (open(sys.argv[3], "rb")) as f:
        public_io = json.load(f)    
    # Hash message and output the digest as bits for the circuit
    prepad_m = public_io["prepad_m"]
    sha256hash = hashlib.sha256(bytes(prepad_m))
    digest_hex_str = sha256hash.hexdigest()
    digest_bits = hex_string_to_binary_array(digest_hex_str, 256)
    print_json_array("digest", digest_bits)

# Print predicate-related inputs
prepare_special_inputs(config)

print("\n}")