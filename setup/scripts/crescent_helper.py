################################################
# crescent_helper.py - Crescent helper python module.
################################################

import sys
from jwcrypto.common import base64url_decode
import json, math, string

##### Constants ######
MAX_FIELD_BYTE_LEN = 31        # Maximum length for each field in AAD token.
CIRCOM_RS256_LIMB_BITS = 121
CIRCOM_ES256K_LIMB_BITS = 64 
CIRCOM_ES256_LIMB_BITS = 43     # Required by the ecdsa-p256 circuit we use
CRESCENT_CONFIG_KEYS = ['alg', 'credtype', 'reveal_all_claims', 'defer_sig_ver', 'max_jwt_len']     # fields in config.json that are for crescent configuration and do not refer to claims in the token
CRESCENT_SUPPORTED_ALGS = ['RS256', 'ES256', 'ES256K']     # Signature algorithms used to sign JWT/mDL


##### Module functions ######

def json_prettyprint(s):
    print_debug(json.dumps(json.loads(s), indent=4))

def print_json_value(label, value, no_leading_comma=False):
    
    if no_leading_comma:
        print("\n  \""+label+"\": \""+str(value)+"\"", end='')
    else:
        print(",\n  \""+label+"\": \""+str(value)+"\"", end='')

def print_debug(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def camel_to_snake(str):
    res = [str[0].lower()]
    for c in str[1:]:
        if c in ('ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
            res.append('_')
            res.append(c.lower())
        else:
            res.append(c)
     
    return ''.join(res)

# typ: 0 for string, 1 for number, 2 for bool, 3 for null, 4 for array, 5 for object
def claim_type_as_int(type):
     print_debug("claim_type_as_int got input: " + type)
     if type == "string":
         return 0
     elif type == "number":
         return 1
     elif type == "bool":
         return 2
     elif type == "null":
         return 3
     elif type == "array":
         return 4
     elif type == "object":
         return 5

def bytes_to_ints(input_bytes):
    ints = []
    for c in input_bytes:
        ints.append(c)
    return ints

def to_utf8_integers(input_bytes):
    utf8 = []
    for c in input_bytes :
        utf8.append(ord(c))
    return utf8

def digest_to_limbs(digest_hex):
    # This is a special limb format used by the adapter we use to export the 
    # digest from the Groth16 proof to Spartan
    digest_bytes = bytes.fromhex(digest_hex)
    n = int.from_bytes(digest_bytes[0:31], byteorder='big', signed=False)
    b = int.from_bytes(digest_bytes[31:32], byteorder='big', signed=False)
    return [n,b]

def pack_string_to_int(s, n_bytes):
    # must match function "RevealClaimValue" in match_claim.circom
    # so we add quotes to the string TODO: maybe reveal the unquoted claim value instead?
    #First convert s to bytes and pad with zeros
    s_bytes = bytearray("\"" + s + "\"", 'utf-8')
    if len(s_bytes) > n_bytes:
        print("String to large to convert to integer of n_bytes = {}".format(n_bytes))
        sys.exit(-1)
    s_bytes.extend([0x00]*(n_bytes - len(s_bytes)))
    n = 0
    for i in range(0, len(s_bytes)):
        n = n + s_bytes[i] * pow(256, i)
    return n

def pack_string_to_int_unquoted(s, n_bytes):
    s_bytes = bytearray(s, 'utf-8')
    if len(s_bytes) > n_bytes:
        print("String to large to convert to integer of n_bytes = {}".format(n_bytes))
        sys.exit(-1)
    s_bytes.extend([0x00]*(n_bytes - len(s_bytes)))
    n = 0
    for i in range(0, len(s_bytes)):
        n = n + s_bytes[i] * pow(256, i)
    return n

def is_printable(byte_array):
    for c in byte_array:
        if not (chr(c) in string.printable):
            return False
    return True

def unpack_int_to_string(s_int, n_bytes):
    # must match function "RevealClaimValue" in match_claim.circom
    # so we add quotes to the string TODO: maybe reveal the unquoted claim value instead?
    #First convert s to bytes and pad with zeros
    s_bytes = bytearray("", 'utf-8')
    l = math.ceil(math.log(s_int)/math.log(256))
    for i in range(0, l):
        b = s_int % 256
        s_int = s_int//256
        s_bytes.extend([b])
    if  not is_printable(s_bytes):
        print_debug("Warning: unpack_int_to_string contains unprintable characters (utf-8)")

    return s_bytes.decode('utf-8')

def bytes_to_circom_limbs(n_bytes, limb_size):
    n = int.from_bytes(n_bytes, byteorder='big', signed=False)
    num_limbs = math.ceil( (n.bit_length() + limb_size - 1) // limb_size)
    limbs = []
    msk = (1 << limb_size) - 1
    for i in range(0, num_limbs):
        limb = (n >> i*limb_size) & msk
        limbs.append(limb)
    return limbs

def b64_to_circom_limbs(n_b64, limb_size):
    n_bytes = base64url_decode(n_b64)
    return bytes_to_circom_limbs(n_bytes, limb_size)

def print_json_array(label, values, no_leading_comma=False):
    if no_leading_comma:
        print("\n")
    else:
        print(",\n")

    print("  \""+label+"\": [")
    for c in values[0:len(values)-1]:
        print("  \"" + str(c) + "\",")
    print("  \"" + str(values[-1]) + "\"")
    print("]", end='')

def hex_string_to_binary_array(hex_str, bits):
    return [int(b) for b in (bin(int(hex_str, 16))[2:]).zfill(bits)]

def check_config(config):
    # Check that the config file has required fields
    if 'alg' not in config:
        print_debug("Error: 'alg' field is missing from config file")
        return False
    if config['alg'] not in CRESCENT_SUPPORTED_ALGS:
        print_debug("Error: algorithm {} is not supported".format(config['alg']))
        return False
        
    # Set defaults
    if 'reveal_all_claims' not in config:
        config['reveal_all_claims'] = False
    else:
        if type(config['reveal_all_claims']) != bool:
            print_debug("Error: field 'reveal_all_claims' must be of type bool")
            return False
        
    if 'defer_sig_ver' not in config:
        config['defer_sig_ver'] = False
    else:
        if type(config['defer_sig_ver']) != bool:
            print_debug("Error: field 'defer_sig_ver' must be of type bool")
            return False

    if 'credtype' not in config:
        config['credtype'] = 'jwt'
        
    if 'max_jwt_len' not in config:
        config['max_jwt_len'] = 2048  # Maximum length of JWT, excluding the
                                      # signature part.  The length in bytes of the header 
                                      # and payload, base64url encoded. Must be a multiple of 64.
    else:
        if type(config['max_jwt_len']) != int:
            print_debug("Error: config field 'max_jwt_len' must be an integer")
            return False
        max_jwt_len = config['max_jwt_len']
        if max_jwt_len % 64 != 0:
            print_debug("Error: 'max_jwt_len' must be a multiple of 64. Found {}, try {}".format(max_jwt_len, (64 - (max_jwt_len % 64)) + max_jwt_len ))
            return False
        
    # Additional checks
    if config['defer_sig_ver']:
        if config['alg'] != 'ES256K':
            print_debug("Error: the 'defer_sig_ver' option is only valid with the ES256K algorithm")
            return False


    # For all the config entries about claims (e.g, "email", "exp", etc.) make sure that if the claim 
    # is to be revealed, that max_claim_byte_len is set
    for key in config.keys():
        if key not in CRESCENT_CONFIG_KEYS:
            if config[key].get("reveal"):
                if config[key].get("max_claim_byte_len") is None:
                    print_debug("Error: claim '", key, "' has reveal flag set but is missing 'max_claim_byte_len'")
                    return False

    return True

def base64_decoded_size(encoded_len):
    return ((encoded_len + 3) // 4) * 3
def base64_encoded_size(decoded_len):
    return ((decoded_len + 2) // 3) * 4
