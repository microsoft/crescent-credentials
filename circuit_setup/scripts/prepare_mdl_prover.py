# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

#!/usr/bin/python3

from jwcrypto.common import base64url_encode
import sys, os
import json
import hashlib

from pymdoccbor.mdoc.verifier import MdocCbor
import cbor2
from ecdsa.keys import VerifyingKey, BadSignatureError
from hashlib import sha256
from cryptography.hazmat.primitives import serialization
from pprint import pprint
import binascii
from datetime import date, datetime, timezone, timedelta

from crescent_helper import *

ISSUER_TIMEZONE = timezone(-timedelta(hours=8)) # US west coast / PST

##### Helper functions #########
def usage():
    print("Python3 script to prepare inputs for prover and extract issuer key")
    print("Usage:")
    print("\t./" + os.path.basename(sys.argv[0]) + " <config file> <mDL cred file> <prover input file> <issuer key>")
    print("Example:")
    print("\tpython3 " + os.path.basename(sys.argv[0]) + " ../inputs/mdl1/config.json ../inputs/mdl1/cred.txt  ../generated_files/mdl1/prover_inputs.json ../generated_files/issuer.pub")
    print("The inputs are <config file> and <mDL cred file>")
    print("The outputs are <prover input file> and <issuer key>")



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


def load_mdoc(mdl_cred_file):
    with open(mdl_cred_file, 'r') as file:
        ISSUED_MDOC = file.read()

    mdoc = MdocCbor()
    mdoc.loads(ISSUED_MDOC)
    if not mdoc.verify():
        print("mdoc.verify() failed")

    return mdoc.documents[0]

def load_issuer_public_key(mdoc):

    # Extract the issuer cert and public key
    issuer_cert = mdoc.issuersigned.issuer_auth.x509_certificates[0]
    #issuer_cert_pem = issuer_cert.public_bytes(serialization.Encoding.PEM)
    issuer_key_pem = issuer_cert.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return issuer_key_pem

def load_tbs_data(mdoc):
    payload = mdoc.issuersigned.issuer_auth.object.payload
    protected_hdr_encoded = mdoc.issuersigned.issuer_auth.object.phdr_encoded

    # The data to be signed is formatted as a the COSE_Sign1 message
    # The empty value is the unprotected header
    sig_structure = ['Signature1', 
                    protected_hdr_encoded, 
                    b'',
                    payload]
    tbs_data = cbor2.dumps(sig_structure)

    return tbs_data

def load_signature(mdoc):
    return mdoc.issuersigned.issuer_auth.object.signature

def find_value_digest_info(mdoc, name):
    # For each of the signed "valueDigests" in the payload, the credential contains unsigned element values and randomness 
    # Each valueDigest is SHA256(Encode(randomness||value)), Encode() is discussed below
    element_randoms = {}
    element_values = {}
    element_digest_ids = {}
    for item in mdoc.issuersigned.namespaces['org.iso.18013.5.1']:
        item_parsed = cbor2.loads(item.value)
        id = item_parsed['elementIdentifier']
        element_randoms[id] = item_parsed['random']
        element_values[id] = item_parsed['elementValue']
        element_digest_ids[id] = item_parsed['digestID']

    # Recompute the value digests from the values and salts we have
    if element_values[name] is None:
        print("Error: Value digest with name {} was not found".format(name))
        sys.exit(-1)
    
    # Encode() the data to be hashed
    hash_input = {
        'digestID': element_digest_ids[name],
        'random': element_randoms[name],
        'elementIdentifier': name,
        'elementValue': element_values[name]
    }

    formatted_hash_input = cbor2.dumps(cbor2.CBORTag(24, value=cbor2.dumps(hash_input)))
    recomputed_value_digest = sha256(formatted_hash_input).digest()
    # Check that the recomputed value digest matches the one in the signed part of the mdoc
    signed_value_digest = mdoc.issuersigned.issuer_auth.payload_as_dict['valueDigests']['org.iso.18013.5.1'][element_digest_ids[name]]
    if recomputed_value_digest != signed_value_digest:
        print("Digest mismatch")
        print("Recomputed: {}".format(binascii.hexlify(recomputed_value_digest).decode('utf-8')))
        print("Signed    : {}".format(binascii.hexlify(signed_value_digest).decode('utf-8') ))
    else:
        print("Digest: {}".format(binascii.hexlify(recomputed_value_digest).decode('utf-8')))

    # Now we need an encoded version of the digest, that we can match against the CBOR-encoded cred
    # The format is:
    # unsigned(digestID)
    # 58 20  bytes(32)
    # (32-byte SHA-256 digest)
    cbored_digest = "{:02x}{}{}".format(element_digest_ids[name], "5820", binascii.hexlify(recomputed_value_digest).decode('utf-8'))

    # find the (l,r) position of cbored_digest in the tbsData
    tbs_data = load_tbs_data(mdoc)
    tbs_data_text = str(binascii.hexlify(tbs_data))
    encoded_l = tbs_data_text.find(cbored_digest)/2 - 1
    encoded_r = encoded_l + len(cbored_digest)/2

    info = {}
    info['value'] = element_values[name]
    info['id'] = element_digest_ids[name]
    info['digest'] = recomputed_value_digest
    info['preimage'] = formatted_hash_input
    info['encoded_l'] = int(encoded_l)
    info['encoded_r'] = int(encoded_r)

    return(info)

def ymd_to_timestamp(ymd, is_bytes=False, has_time=False):
    if is_bytes:
        ymd = binascii.unhexlify(ymd).decode('utf-8')
    format_string = "%Y-%m-%d"
    if has_time:
        format_string = "%Y-%m-%dT%H:%M:%SZ"
    dt = datetime.strptime(ymd, format_string)
    # Our circuit ignores time of day so we set them to zero. And set the issuer's TZ
    dt = dt.replace(hour=0, minute=0, second=0, tzinfo=ISSUER_TIMEZONE)
    return(int(dt.timestamp()))

def ymd_to_daystamp(ymd, is_bytes=False, has_time=False):
    # Compute the number of days between Jan 1, year 0000 and input "YYYY-MM-DD"
    # The implementation of the Date class' toordinal() function is here: 
    # https://github.com/python/cpython/blob/54b5e4da8a4c6ae527ab238fcd6b9ba0a3ed0fc7/Lib/datetime.py#L63
    (year, month, day) = ymd.split("-")
    year = int(year)
    month = int(month)
    day = int(day)
    d = date(year, month, day)
    return(d.toordinal())


######## Main ###########

if len(sys.argv) != 5: 
    usage()
    sys.exit(-1)

# Load the config file
with open(sys.argv[1], "r") as f:
    config = json.load(f)

if not check_config(config):
    print("Invalid configuration file, exiting")
    sys.exit(-1)

if config['credtype'] != 'mdl':
    print('Error: only mDL credentials are supported by this script; config.json must have "credtype":"mdl"')
    sys.exit(-1)

prover_inputs = {}
prover_aux_data = {}
public_IOs = {}

# Read and parse the mDL credential
mdoc = load_mdoc(sys.argv[2])

# Load the issuer's public key
issuer_key_pem = load_issuer_public_key(mdoc)

# Load the data that is signed in the mDL credential
tbs_data = load_tbs_data(mdoc)
tbs_data_ints = bytes_to_ints(tbs_data)
print("len(tbs_data_ints) = {}".format(len(tbs_data_ints)))

# Convert header and payload to UTF-8 integers in base-10 (e.g., 'e' -> 101, 'y' -> 121, ...)
padded_m = sha256_padding(tbs_data_ints)

msg_len_after_SHA2_padding = len(padded_m)
print_debug("msg_len_after_SHA2_padding: {}".format(msg_len_after_SHA2_padding))

if msg_len_after_SHA2_padding > config['max_cred_len']:
    print_debug("Error: mDL too large.  Current mDL header + payload is {} bytes ({} bytes after SHA256 padding), but maximum length supported is {} bytes.".format(len(tbs_data), msg_len_after_SHA2_padding, base64_decoded_size(config['max_cred_len'])))
    print_debug("The config file value `max_cred_len` would have to be increased to {} bytes (currently config['max_cred_len'] = {})".format(len(tbs_data)+64, config['max_cred_len']))
    sys.exit(-1)

while (len(padded_m) < config['max_cred_len']):    # Additional zero padding for Circom program
    padded_m = padded_m + [0]

sha256hash = hashlib.sha256(bytes(tbs_data))
digest_hex_str = sha256hash.hexdigest()
digest_bits = hex_string_to_binary_array(digest_hex_str, 256)
digest_b64 = base64url_encode(sha256hash.digest())
digest_limbs = digest_to_limbs(digest_hex_str)

### validUntil ###
valid_until_prefix = "6a76616c6964556e74696cc074" # 6a: text(10), 7661...696c: "validUntil", c0: date, 74: text(20)
tbs_data_text = str(binascii.hexlify(tbs_data))
valid_until_pos = tbs_data_text.find(valid_until_prefix) + len(valid_until_prefix)
valid_until_data = tbs_data_text[valid_until_pos: valid_until_pos + 40]
valid_until_unix_timestamp = ymd_to_timestamp(valid_until_data, is_bytes=True, has_time=True)
print("valid_until_unix_timestamp: {}".format(valid_until_unix_timestamp))

### Date of Birth ###
dob_info = find_value_digest_info(mdoc, 'birth_date')

# Begin output of prover's inputs
prover_inputs['message'] = padded_m
prover_inputs['valid_until_value'] = valid_until_unix_timestamp
prover_inputs['valid_until_prefix_l'] = int(tbs_data_text.find(valid_until_prefix)/2 - 1)
prover_inputs['valid_until_prefix_r'] = prover_inputs['valid_until_prefix_l'] + int(len(valid_until_prefix)/2)

prover_inputs['dob_value'] = ymd_to_daystamp(dob_info['value'].value)
prover_inputs['dob_id'] = dob_info['id']
prover_inputs['dob_preimage'] = sha256_padding(bytes_to_ints(dob_info['preimage']))
prover_inputs['dob_encoded_l'] = dob_info['encoded_l']
prover_inputs['dob_encoded_r'] = dob_info['encoded_r']

if len(prover_inputs['dob_preimage']) != 128:
    print("ERROR: DOB preimage len = {}".format(len(prover_inputs['dob_preimage'])))
    print("Length 128 is hardcoded in circom circuit")
    sys.exit(-1)

# Next field is the signature
signature_bytes = load_signature(mdoc)
issuer_vk = None
if config['alg'] == 'ES256' :   
    try:
        # Use the ECDSA implementation directly to double check the extracted data is signed correctly
        issuer_vk = VerifyingKey.from_pem(issuer_key_pem)
        issuer_vk.verify(signature=signature_bytes, data=tbs_data, hashfunc=sha256)
        print_debug("Extracted signature and data verify")
    except BadSignatureError:
        print_debug("Failed to verify signature with extracted data")
else :
    print_debug("Signature algorithm not supported")
    exit(-1)

if config['alg'] == 'ES256':
    # See https://www.rfc-editor.org/rfc/rfc7515#appendix-A.3.1 for ECDSA encoding details, the signature is R||S
    # this code assumes |R|==|S|
    siglen = len(signature_bytes)
    assert(siglen % 2  == 0)
    r_bytes = signature_bytes[0 : int(siglen/2)]
    s_bytes = signature_bytes[int(siglen/2) : siglen ]
    assert(r_bytes + s_bytes == signature_bytes)
    r_limbs = bytes_to_circom_limbs(r_bytes, CIRCOM_ES256_LIMB_BITS)
    s_limbs = bytes_to_circom_limbs(s_bytes, CIRCOM_ES256_LIMB_BITS)
    prover_inputs['signature_r'] = r_limbs
    prover_inputs['signature_s'] = s_limbs
    #print_debug("signature_r = ", r_bytes.hex().upper())
    #print_debug("signature_s = ", s_bytes.hex().upper())   
else :
    print_debug("Signature algorithm not supported")
    exit(-1)

# Next the issuer's public key
if config['alg'] == 'ES256' :
    issuer_key_x =  issuer_vk.pubkey.point.to_affine().x().to_bytes(length=32, byteorder='big')
    issuer_key_y =  issuer_vk.pubkey.point.to_affine().y().to_bytes(length=32, byteorder='big')
    x_limbs = bytes_to_circom_limbs(issuer_key_x, CIRCOM_ES256_LIMB_BITS)
    y_limbs = bytes_to_circom_limbs(issuer_key_y, CIRCOM_ES256_LIMB_BITS)
    public_IOs['pubkey_x'] = x_limbs
    public_IOs['pubkey_y'] = y_limbs    
    prover_inputs['pubkey_x'] = x_limbs
    prover_inputs['pubkey_y'] = y_limbs
else :
    print_debug("Signature algorithm not supported")
    exit(-1)    

prover_inputs['message_padded_bytes'] = msg_len_after_SHA2_padding
print_debug("number of SHA blocks to hash: " + str(msg_len_after_SHA2_padding // 64))

# Write out prover inputs, public IOs, prover aux data. Always create a file, even if they're empty

# FIXME: public_IOs and prover_aux_data are not written to file
if len(public_IOs.keys()) == 0:
    public_IOs["_placeholder"] = "empty file"
if len(prover_aux_data.keys()) == 0:
    prover_aux_data["_placeholder"] = "empty file"

with open(sys.argv[3], "w") as json_file:
    json.dump(prover_inputs, json_file, indent=4)


with open(sys.argv[4], "w") as issuer_key_file:
    issuer_key_file.write(issuer_key_pem.decode('utf-8'))



# Generate some tables for the circuit
# dby = []
# is_leap = []
# for year in range(1900, 2031):
#     dby.append(_days_before_year(year))
#     is_leap.append(int(_is_leap(year)))
# print("signal days_before_year[{}] <== {};".format(len(dby), dby))
# print("signal is_leap[{}] <== {};".format(len(is_leap), is_leap))
