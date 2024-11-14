# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

#!/usr/bin/python3

import python_jwt as jwt, jwcrypto.jwk as jwk
from jwcrypto.common import base64url_decode, base64url_encode
import sys, os
import json
import hashlib

from crescent_helper import *

##### Helper functions #########
def usage():
    print("Python3 script to prepare inputs for prover")
    print("Usage:")
    print("\t./" + os.path.basename(sys.argv[0]) + " <config file> <issuer pub key PEM file> <jwt file> <public IO output file> ")
    print("Example:")
    print("\tpython3 " + os.path.basename(sys.argv[0]) + "../../inputs/config.json ../../sample_tokens/aad.pub ../../sample_tokens/aad.jwt ../generated_files/demo/public_io.json > ../../inputs/demo.json")

def find_value_interval(msg,  claim, typ):
    # find name in msg
    l = msg.find(claim)
    if l == -1:
        sys.exit(-1)

    value_start = l + len(claim)
    # typ: 0 for string, 1 for number, 2 for bool, 3 for null, 4 for array, 5 for object
    match typ:
        case 0:
            r = msg.find('"', value_start + 1) + 1
        case 1:
            for i in range(value_start, len(msg)):
                if msg[i] not in "0123456789":
                    r = i
                    break
        case 2:
            for i in range (value_start, len(msg)):
                if msg[i] not in "truefalse":
                    r = i
                    break
        case 3:
            r = value_start + 4
        case 4:
            nested_level = 0
            for i in range(value_start, len(msg)):
                if msg[i] == '[':
                    nested_level += 1
                elif msg[i] == ']':
                    nested_level -= 1
                    if nested_level == 0:
                        r = i + 1
                        break
        case 5:
            nested_level = 0
            for i in range(value_start, len(msg)):
                if msg[i] == '{':
                    nested_level += 1
                elif msg[i] == '}':
                    nested_level -= 1
                    if nested_level == 0:
                        r = i + 1
                        break
            
    return l, r

def get_domain(s):
    at_index = s.find('@')
    if at_index == -1:
        print_debug("ERROR: no @ symbol found in input to get_domain()")
        exit(-1)
    domain = s[at_index + 1:]
    return domain

def is_minified(msg):
    # Check for extra spaces, e.g., 
    #     "exp" : 123456789
    # is not sufficiently minified, but 
    #     "exp":123456789
    # is minified.  Our circom circuit currently does not support extra space(s).
    match_pos = msg.find('": ')
    if match_pos != -1 :
        print_debug("ERROR: is_minified found '\" : ' at position {}".format(match_pos))
        print_debug("Full JSON is |{}|".format(msg))
        return False
    
    return True


def prepare_prover_inputs(msg, config, msg_json):
    msg = msg.decode('utf-8')

    print_debug("== Prover inputs from predicates ==")
    
    if not is_minified(msg): 
        print_debug("ERROR: JSON is not minified, Circom circuit will fail, exiting.")
        exit(-1)

    keys = list(config.keys())
    claims = []
    
    for i in range(0, len(keys)):
        if keys[i] in CRESCENT_CONFIG_KEYS:
            continue

        assert(msg_json.get(keys[i]) is not None)

        name = keys[i]
        typ_string = config[name].get("type")
        if typ_string is None:
            print("Missing 'type' field in config file for claim '{}'".format(name))
            sys.exit(-1)
        typ = claim_type_as_int(typ_string)                 
        claim = '"' + keys[i] + '":'
        claims.append(claim)
        claim_l, claim_r = find_value_interval(msg, claim, typ)

        name_l = name + "_l"
        name_r = name + "_r"

        print_debug("+", msg[claim_l:claim_r], "typ:", typ)
        print_json_value(name_l, claim_l)
        print_json_value(name_r, claim_r)

        if config[name].get("reveal") is not None and config[name].get("reveal") is True:            
            if typ_string == "number":
                print_json_value(name + "_value", msg_json[name])
            elif typ_string == "string":
                # pack string to field element, use same packing function as in circuit
                print_debug("max_claim_byte_len for {}: {}".format(name, config[name].get("max_claim_byte_len")))
                domain_only = (config[name].get("reveal_domain_only") is not None and config[name].get("reveal_domain_only") == True)
                if domain_only :
                    domain = get_domain(msg_json[name])
                    print_debug("Packing domain string: '{}'".format(domain))
                    print_json_value(name + "_value", pack_string_to_int_unquoted(domain, config[name].get("max_claim_byte_len")))
                else:
                    print_json_value(name + "_value", pack_string_to_int(msg_json[name], config[name].get("max_claim_byte_len")))

            else:
                print_debug("Error: can only reveal number types and string types as a single field element for now. See also `reveal_bytes`.")
                sys.exit(-1)                

               
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
                                    print_debug("WARNING: There's a special input type of json object with no max_length field.")
                            else:
                                print_debug("WARNING: There's a special input type of json object with no value field.")
                        else:
                            print_json_value(k_name, v)


    print_debug("Claims:", claims)
    print_debug("Claims number:", len(claims))
    print_debug("Claim template total length:", sum([len(c) for c in claims]))

def sha256_padding(prepad_m):
    # Apply SHA256 padding to message field
    msg_length_bits = len(prepad_m) * 8 
    padded_m = prepad_m + [128]
    while (len(padded_m) + 4)*8 % 512 != 0 :        # The 4 bytes is counting the 32 bits to represent msg_length (added below)
        padded_m = padded_m + [0]

    msg_len_for_padding = []
    x = msg_length_bits.to_bytes(4, byteorder='big')
    for c in range(0,len(x)):
        msg_len_for_padding.append(int(x[c]))
    padded_m = padded_m + msg_len_for_padding
    return padded_m

# This function creates zero-padding to go between the JSON header and payload
# in order to match what the Circom base64 decoder outputs.
# If the header must include padding "=" or "==" to be a multiple of four for base64
# decoding, then the decoding circuit outputs 0's for these padding characters.
# (Software decoders don't have this output, but it's quite awkward to do in a circuit)
def base_64_decoded_header_padding(header_len):
    if header_len % 4 == 0:
        return b''
    if header_len % 4 == 1:
        raise Exception("Invalid period_idx, the base64 encoding of the header is invalid")
    if header_len % 4 == 2:
        return b'00'
    if header_len % 4 == 3:
        return b'0'
        


######## Main ###########

if len(sys.argv) != 5 : 
    usage()
    sys.exit(-1)

# Load the config file
with open(sys.argv[1], "r") as f:
    config = json.load(f)

if not check_config(config):
    print("Invalid configuration file, exiting")
    sys.exit(-1)


prover_aux_data = {}
public_IOs = {}

# Load the issuer's public key
with open(sys.argv[2], "rb") as f:
    pub_key_pem = f.read()

pub_key = jwk.JWK.from_pem(pub_key_pem)
print_debug("Read issuer public key: \n" + str(pub_key_pem) + "\n")

# Load the JWT
with open(sys.argv[3], encoding='utf-8', mode="r") as f:
    jwt_b64 = f.read()

if jwt_b64[-1] == '\n' :
    jwt_b64 = jwt_b64[0:len(jwt_b64)-1]

print_debug("Read JWT: \n|" + str(jwt_b64) + "|\n")

# We can get the header and claims as dictionaries before verifying the signature, if needed
header, claims = jwt.process_jwt(jwt_b64)

# print_debug("JWT header: \n")
# for k in header: print_debug(k + " : " + header[k])
# print_debug("\nJWT claims: \n")
# for k in claims: print_debug(k + " : " + str(claims[k]))

print_debug("\nGoing to verify signature\n")
try:
    header, claims = jwt.verify_jwt(jwt_b64, pub_key, CRESCENT_SUPPORTED_ALGS, checks_optional=False)
    print_debug("Signature verifies")
except Exception as err:
    print_debug("Signature verification returned error:" + str(err))
print_debug()

c = jwt_b64.split('.')
if len(c) != 3:
    print_debug("Invalid JWT; did not split into 3 parts (header.claims.signature)")
    sys.exit(-1)
    
h = base64url_decode(str(c[0]))
p = base64url_decode(str(c[1]))
s = base64url_decode(str(c[2]))
print_debug("h = |{}|\np = |{}|\nh+p=|{}|".format(h,p, h+p))
print_debug("JWT as JSON:")
print_debug("header: ")
json_prettyprint(h)
print_debug("payload: ")
json_prettyprint(p)

header_bytes = c[0]
payload_bytes = c[1]
signature_bytes = c[2]

# Convert header and payload to UTF-8 integers in base-10 (e.g., 'e' -> 101, 'y' -> 121, ...)
header_utf8 = to_utf8_integers(header_bytes)
header_utf8.append(ord('.'))
payload_utf8 = to_utf8_integers(payload_bytes)

prepad_m = header_utf8 + payload_utf8
padded_m = sha256_padding(prepad_m)

msg_len_after_SHA2_padding = len(padded_m)

if msg_len_after_SHA2_padding > config['max_jwt_len']:
    print_debug("Error: JWT too large.  Current token JSON header + payload is {} bytes ({} bytes after SHA256 padding), but maximum length supported is {} bytes.".format(len(header_utf8 + payload_utf8), msg_len_after_SHA2_padding, base64_decoded_size(config['max_jwt_len'])))
    print_debug("The config file value `max_jwt_len` would have to be increased to {} bytes (currently config['max_jwt_len'] = {})".format(len(header_utf8+payload_utf8)+64, config['max_jwt_len']))
    sys.exit(-1)

while (len(padded_m) < config['max_jwt_len']):    # Additional zero padding for Circom program
    padded_m = padded_m + [0]

sha256hash = hashlib.sha256(bytes(prepad_m))
digest_hex_str = sha256hash.hexdigest()
digest_bits = hex_string_to_binary_array(digest_hex_str, 256)
digest_b64 = base64url_encode(sha256hash.digest())
digest_limbs = digest_to_limbs(digest_hex_str)
if config['defer_sig_ver']:
    prover_aux_data["digest"] = digest_hex_str.upper().strip();
    print_debug("digest: ", digest_hex_str.upper().strip())

# Begin output of prover's input file (to stdout)
print("{")
print_json_array("message", padded_m, no_leading_comma=True)

# Next field is the signature
if config['alg'] == 'RS256' :
    limbs = b64_to_circom_limbs(signature_bytes, CIRCOM_RS256_LIMB_BITS)
    print_json_array("signature", limbs)
elif config['alg'] == 'ES256K':
    # See https://www.rfc-editor.org/rfc/rfc7515#appendix-A.3.1 for ECDSA encoding details in JWTs, the signature is R||S
    # this code assumes |R|==|S|
    siglen = len(signature_bytes)
    assert(siglen % 2  == 0)
    r_bytes = signature_bytes[0 : int(siglen/2)]
    s_bytes = signature_bytes[int(siglen/2) : siglen ]
    assert(r_bytes + s_bytes == signature_bytes)
    r_limbs = b64_to_circom_limbs(r_bytes, CIRCOM_ES256K_LIMB_BITS)
    s_limbs = b64_to_circom_limbs(s_bytes, CIRCOM_ES256K_LIMB_BITS)
    if not config['defer_sig_ver']:
        print_json_array("signature_r", r_limbs)
        print_json_array("signature_s", s_limbs)
    else:
        decoded_sig = base64url_decode(signature_bytes)
        decoded_len = len(decoded_sig)
        sig_r = decoded_sig[0 : int(decoded_len/2)]
        sig_s = decoded_sig[int(decoded_len/2) : decoded_len]
        prover_aux_data['signature_r'] = sig_r.hex().upper()
        prover_aux_data['signature_s'] = sig_s.hex().upper()
        print_debug("signature_r = ", sig_r.hex().upper())
        print_debug("signature_s = ", sig_s.hex().upper())    

# Next the issuer's public key
if config['alg'] == 'RS256' :
    # Next field is the modulus
    n = pub_key.export(as_dict=True)["n"]
    limbs = b64_to_circom_limbs(n, CIRCOM_RS256_LIMB_BITS)
    print_json_array("modulus", limbs)
    public_IOs['modulus'] = limbs
elif config['alg'] == 'ES256K' :
    x_limbs = b64_to_circom_limbs(pub_key.x, CIRCOM_ES256K_LIMB_BITS)
    y_limbs = b64_to_circom_limbs(pub_key.y, CIRCOM_ES256K_LIMB_BITS)
    public_IOs['pubkey_x'] = x_limbs
    public_IOs['pubkey_y'] = y_limbs    
    if not config['defer_sig_ver']:
        print_json_array("pubkey_x", x_limbs)    
        print_json_array("pubkey_y", y_limbs)
    else:
        print_debug("pk_x = ", base64url_decode(pub_key.x).hex().upper())
        print_debug("pk_y = ", base64url_decode(pub_key.y).hex().upper())
        prover_aux_data['pk_x'] = base64url_decode(pub_key.x).hex().upper()
        prover_aux_data['pk_y'] = base64url_decode(pub_key.y).hex().upper()

if config['defer_sig_ver']:
    # Next field is the digest of the message
    #print_json_array("digest", digest_bits)
    print_json_value("digest_248", digest_limbs[0])
    print_debug("digest_byte = ", digest_limbs[1])

print_json_value("message_padded_bytes", msg_len_after_SHA2_padding)
print_debug("number of SHA blocks to hash: " + str(msg_len_after_SHA2_padding // 64))

period_idx = len(header_utf8) - 1                 # Index of the period between header and payload (zero-based indexing)
print_json_value("period_idx", period_idx)
header_pad = base_64_decoded_header_padding(period_idx)
prepare_prover_inputs(h + header_pad + p, config, json.loads(p))
print("\n}")

if config['reveal_all_claims'] :
    public_IOs['prepad_m'] = prepad_m

# Write out public IOs and prover aux data. Always create a file, even if they're empty

if len(public_IOs.keys()) == 0:
    public_IOs["_placeholder"] = "empty file"
if len(prover_aux_data.keys()) == 0:
    prover_aux_data["_placeholder"] = "empty file"

with open(sys.argv[4], "w") as json_file:
    json.dump(public_IOs, json_file, indent=4)
    
output_path = os.path.dirname(sys.argv[4])
with open( output_path + "/prover_aux.json", 'w') as json_file:
    json.dump(prover_aux_data, json_file, indent=4)