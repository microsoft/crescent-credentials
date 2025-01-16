# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

#!/usr/bin/python3

import sys, os
import json

from crescent_helper import *

##### Helper functions #########

def usage():
    print("Python3 script to prepare setup (used by run_setup.sh)")
    print("Usage:")
    print("\t./" + os.path.basename(sys.argv[0]) + " <config file> <circom output file>")

def main_circom_header(config):

    template_filename = ''
    if config['alg'] == 'RS256':
        template_filename = "circuits/main_header_rs256.circom.template"
    elif config['alg'] == 'ES256K':
        template_filename = "circuits/main_header_es256k.circom.template"
    else :
        print("Error: Unsupported algorithm")
        sys.exit(-1)

    res = ''
    with open(template_filename, "r") as f:
        res = f.read()
    return res

def prepare_circom(config, circom_output_file):

    print_debug("== Prepare circom circuit ==")
    
    keys = list(config.keys())
    claims = []
    public_inputs = []
    if config['alg'] == 'RS256':
        public_inputs.append("modulus")
    if config['alg'] == 'ES256K':
        #public_inputs += ["pubkey_x, pubkey_y"]
        print("skipping adding ECC pub key to public inputs")
    if config['defer_sig_ver']:
        public_inputs.append("digest_248")

    with open(circom_output_file, "w") as f:
        f.write(main_circom_header(config))
        for i in range(0, len(keys)):
            name = keys[i]
            if name in CRESCENT_CONFIG_KEYS:
                continue

            typ_string = config[name].get("type")
            if typ_string is None:
                print("Missing 'type' field in config file for claim '{}'".format(name))
                sys.exit(-1)

            typ = claim_type_as_int(typ_string)
            claim = '"' + keys[i] + '":'
            claims.append(claim)
            claim_template = list(claim.encode('utf-8'))
            f.write('''
    log("=== {name} ===");
    var {name}[{claim_template_len}] = {claim_template};
    signal input {name}_l;
    signal input {name}_r;
    component match_{name}_name = MatchClaimName(max_json_bytes, {claim_template_len});
    match_{name}_name.name <== {name};
    match_{name}_name.json_bytes <== jwt_bytes;
    match_{name}_name.l <== {name}_l;
    match_{name}_name.r <== {name}_r;
    match_{name}_name.object_nested_level <== object_nested_level;
'''.format(name = name, claim_template_len = len(claim_template), claim_template = str(claim_template)))

### begin reveal bytes (currently unused)            
            if config[name].get("reveal_bytes") is not None and config[name]["reveal_bytes"] == True:
                if config[name].get("max_claim_byte_len") is not None:
                    if (config[name]["max_claim_byte_len"] % MAX_FIELD_BYTE_LEN) != 0:
                        print("max_claim_byte_len must be a multiple of MAX_FIELD_BYTE_LEN")
                        sys.exit(-1)

                    f.write('''
    var {}_max_claim_byte_len = {};
                            '''.format(name, config[name]["max_claim_byte_len"]))
                else:
                    f.write('''
    var {}_max_claim_byte_len = max_json_bytes;
                            '''.format(name))
                
                is_number = 0
                if typ == 1:
                    is_number = 1
                f.write('''
    component reveal_bytes_{name} = RevealClaimValueBytes(max_json_bytes, {name}_max_claim_byte_len, field_byte_len, {is_number});
    reveal_bytes_{name}.json_bytes <== jwt_bytes;
    reveal_bytes_{name}.l <== match_{name}_name.value_l;
    reveal_bytes_{name}.r <== match_{name}_name.value_r;
                        
    signal output {name}_value[{name}_max_claim_byte_len];
    signal output {name}_value_len;
    for (var i = 0; i < {name}_max_claim_byte_len; i++) 
        {name}_value[i] <== reveal_bytes_{name}.value[i];
    {name}_value_len <== reveal_bytes_{name}.value_len;
'''.format(name = name, is_number = is_number))
### end reveal bytes

### begin reveal unhashed                 
            elif claim_reveal_unhashed(config[name]): 
                if config[name].get("max_claim_byte_len") is not None:
                    if (config[name]["max_claim_byte_len"] % MAX_FIELD_BYTE_LEN) != 0:
                        print("max_claim_byte_len must be a multiple of MAX_FIELD_BYTE_LEN")
                        sys.exit(-1)
                    public_inputs.append(name + "_value")
                    f.write('''
    var {}_max_claim_byte_len = {};
                            '''.format(name, config[name]["max_claim_byte_len"]))
                else:
                    print("max_claim_byte_len must be set")
                    sys.exit(-1)
                
                reveal_function = "RevealClaimValue"
                dom_only = config[name].get("reveal_domain_only");
                if  dom_only is not None and dom_only == True:
                    reveal_function = "RevealDomainOnly"

                is_number = 0
                if typ == 1:
                    is_number = 1
                f.write('''
    component reveal_{name} = {reveal_function}(max_json_bytes, {name}_max_claim_byte_len, field_byte_len, {is_number});
    reveal_{name}.json_bytes <== jwt_bytes;
    reveal_{name}.l <== match_{name}_name.value_l;
    reveal_{name}.r <== match_{name}_name.value_r;
                        
    signal input {name}_value;
    log("{name}_value = ", {name}_value);
    log("reveal_{name}.value = ", reveal_{name}.value);                        
    {name}_value === reveal_{name}.value;

'''.format(name = name, reveal_function = reveal_function, is_number = is_number))                
###  end reveal unhashed

###  begin reveal hashed          
            elif claim_reveal_hashed(config[name]):
                f.write('''var {}_max_claim_byte_len = {};'''.format(name, config[name]["max_claim_byte_len"]))
                
                is_number = 0
                if typ == 1:
                    is_number = 1
                
                f.write('''
    component hash_reveal_{name} = HashRevealClaimValue(max_json_bytes, {name}_max_claim_byte_len, field_byte_len, {is_number});
    hash_reveal_{name}.json_bytes <== jwt_bytes;
    hash_reveal_{name}.l <== match_{name}_name.value_l;
    hash_reveal_{name}.r <== match_{name}_name.value_r;
                        
    signal output {name}_digest;
    {name}_digest <== hash_reveal_{name}.digest;
'''.format(name = name, is_number = is_number))
### end reveal hashed

            else:
                f.write('''
    component validate_{name} = ValidateClaimValue(max_json_bytes, {typ});
    validate_{name}.json_bytes <== jwt_bytes;
    validate_{name}.l <== match_{name}_name.value_l;
    validate_{name}.r <== match_{name}_name.value_r;
'''.format(name = name, typ = typ))
                
            if config[name].get("predicates") is not None:

                for predicate in config[name]["predicates"]:
                    predicate_name = predicate["name"]
                    pred_var_name = camel_to_snake(predicate_name)

                    # Print special input for some predicates.
                    circom_special_inputs = []
                    if predicate.get("special_inputs") is not None:
                        for k, v in predicate["special_inputs"].items():    
                            k_name = name + "_" + pred_var_name + "_" + k
                            k_dim = ""
                            if dict == type(v):
                                if v["max_length"] is not None:
                                    k_dim = "["+ str(v["max_length"]) +"]"
                            circom_special_inputs.append((k, k_name))
                            public_inputs.append(k_name)

                            f.write('''
    signal input {input};
'''.format(input = k_name+k_dim))
                    
                    f.write('''
    component {name}_{pred_var_name} = {predicate_name}(max_json_bytes);
    {name}_{pred_var_name}.json_bytes <== jwt_bytes;
    {name}_{pred_var_name}.range_indicator <== validate_{name}.range_indicator;
'''.format(name = name, pred_var_name = pred_var_name, predicate_name = predicate_name))
                    
                    for input in circom_special_inputs:
                        f.write('''
    {name}_{pred_var_name}.{var} <== {in_signal};
'''.format(name = name, pred_var_name = pred_var_name, var = input[0], in_signal = input[1]))

        f.write("}\n")
        # Print the main statement in circom.
        limb_size = 0
        n_limbs = 0
        if config['alg'] == "ES256K":
            limb_size = CIRCOM_ES256K_LIMB_BITS
            n_limbs = 4
        elif config['alg'] == "RS256":
            limb_size = CIRCOM_RS256_LIMB_BITS
            n_limbs = 17
        main_input = "{ public [" + ", ".join(public_inputs) + " ] }"
        f.write('''
component main {main_input} = Main({max_msg_len}, {max_json_len}, {max_field_byte_len}, {limb_size}, {n_limbs});
'''.format(main_input = main_input, max_msg_len = config['max_jwt_len'], max_json_len = base64_decoded_size(config['max_jwt_len']), max_field_byte_len = MAX_FIELD_BYTE_LEN, limb_size=limb_size, n_limbs=n_limbs))


    print_debug("Claims:", claims)
    print_debug("Claims number:", len(claims))
    print_debug("Claim template total length:", sum([len(c) for c in claims]))

######## Main ###########

if len(sys.argv) != 3 : 
    usage()
    sys.exit(-1)

# Load the config file
with open(sys.argv[1], "r") as f:
    config = json.load(f)

if not check_config(config):
    print("Invalid configuration file, exiting")
    sys.exit(-1)    

prepare_circom(config, sys.argv[2])
