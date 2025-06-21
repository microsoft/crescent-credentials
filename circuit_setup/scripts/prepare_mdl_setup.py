# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

#!/usr/bin/env python3

import os, sys, json, cbor2
from crescent_helper import *

# ----------------------------------------------------------------------
def usage():
    exe = os.path.basename(sys.argv[0])
    print(f"Usage: ./{exe}  <config.json>  <out.circom>")

def circom_header(cfg):
    if cfg.get("alg") != "ES256":
        print("Unsupported alg:", cfg.get("alg")); sys.exit(-1)
    with open("circuits-mdl/main_header_es256.circom.template") as f:
        return f.read()

def get_cbor_encoded_name_identifier(name: str):
    encoded_bytes = cbor2.dumps(name)
    return list(encoded_bytes), len(encoded_bytes)

# ======================================================================
#  generator
# ======================================================================

def generate_circuit(cfg: dict, out_path: str) -> None:

    print_debug("== generate generic mDL circuit ==")

    attrs = [k for k in cfg if k not in CRESCENT_CONFIG_KEYS]

    public_inputs = ["pubkey_hash", "valid_until_value", "device_key_0_value", "device_key_1_value"]

    with open(out_path, "w") as f:

        # ---------- static header --------------------------
        f.write(circom_header(cfg))

        f.write(f"""
    // ------------------------------------------------------------
    // The following code handle the attribute disclosure. For each, we need the following inputs:
    //   - attribute_value: the value of the attribute; for date types, this in an integer (days since year 0000)
    //   - attribute_id: the id of the attribute (currently limited to 1 byte)
    //   - attribute_preimage: the sha256-padded preimage of the mDL IssuerSignedItem formatted as follows:
    //     * 'digestID': 
    //     * 'random': random salt
    //     * 'elementIdentifier': CBOR encoded string of the attribute name,
    //     * 'elementValue': the attribute value
""")
        for name in attrs:

            # read config
            attr_type = cfg[name].get("type")
            reveal = cfg[name].get("reveal")
            reveal_digest = cfg[name].get("reveal_digest")
            max_claim_byte_len = cfg[name].get("max_claim_byte_len")
            name_identifier, name_identifier_len = get_cbor_encoded_name_identifier(name)
            name_preimage_len = 128 # don't hardcode; calculate from max_claim_byte_len?

            if ((reveal is None) or (reveal == "false")) and ((reveal_digest is None) or (reveal_digest == "false")):
                print(f"Claim {name} is not revealed; not currently supported")
                sys.exit(-1)

            print(f"Writing circuit code for {name} ({attr_type})")                        

            # add attribute to the public inputs
            if name not in public_inputs and reveal:
                public_inputs.append(f"{name}_value")

            f.write(f"""
    // ------------------------------------------------------------
    //  {name}
    // ------------------------------------------------------------
    var {name}_preimage_len = {name_preimage_len};
""")
            if reveal:
                f.write(f"""
    signal input {name}_value;

""")                
            f.write(f"""
    signal input {name}_id;
    signal input {name}_preimage[{name}_preimage_len];
    signal input {name}_identifier_l; // The start position of the {name} identifier in the preimage

    signal input {name}_encoded_l; // The start position in the cred where the hashed {name} occurs
    signal input {name}_encoded_r; // The end position FIXME: do we need this? for our 1-byte digestID, it's always going to be l + 35

    var {name}_identifier[{name_identifier_len}] = {name_identifier};

    component {name}_identifier_indicator = IntervalIndicator({name}_preimage_len);
    {name}_identifier_indicator.l <== {name}_identifier_l;
    {name}_identifier_indicator.r <== {name}_identifier_l + {name_identifier_len};

    component match_{name}_identifier = MatchSubstring({name}_preimage_len, {name_identifier_len}, {MAX_FIELD_BYTE_LEN});
    match_{name}_identifier.msg <== {name}_preimage;
    match_{name}_identifier.substr <== {name}_identifier;
    match_{name}_identifier.range_indicator <== {name}_identifier_indicator.indicator;
    match_{name}_identifier.l <== {name}_identifier_indicator.l;
    match_{name}_identifier.r <== {name}_identifier_indicator.r;

    component {name}_hash_bytes = SHA256(128);
    {name}_hash_bytes.msg <== {name}_preimage;
    // Extract the actual length from the sha-256 padding
    {name}_hash_bytes.real_byte_len <== ({name}_preimage[126] * 256 + {name}_preimage[127]) / 8;

    signal encoded_{name}_digest[35]; // FIXME: don't hardcode 35
    encoded_{name}_digest[0] <== {name}_id; 
    encoded_{name}_digest[1] <== 88;   // == 0x58
    encoded_{name}_digest[2] <== 32;   // == 0x20
    for(var i = 0; i < 32; i++ ) {{
        encoded_{name}_digest[i + 3] <== {name}_hash_bytes.hash[i];
    }}
    component {name}_indicator = IntervalIndicator(max_msg_bytes);
    {name}_indicator.l <== {name}_encoded_l;
    {name}_indicator.r <== {name}_encoded_r;

    component match_{name} = MatchSubstring(max_msg_bytes, 35, {MAX_FIELD_BYTE_LEN});
    match_{name}.msg <== message;
    match_{name}.substr <== encoded_{name}_digest;
    match_{name}.range_indicator <== {name}_indicator.indicator;
    match_{name}.l <== {name}_indicator.l;
    match_{name}.r <== {name}_indicator.r;
""")
            if attr_type == "date":
                f.write(f"""
    // parse out the date as YYYY-MM-DD and confirm it equals {name}_value

    // last 10 characters are 'YYYY-MM-DD', 32 bytes of SHA padding, so year starts at position 85 = 127 - 32 - 10
    signal {name}_year <== ({name}_preimage[85]-48)*1000 + ({name}_preimage[86]-48)*100 + ({name}_preimage[87]-48)*10 + ({name}_preimage[88]-48);
    signal {name}_month <== ({name}_preimage[90]-48)*10 + ({name}_preimage[91]-48); 
    signal {name}_day <== ({name}_preimage[93]-48)*10 + ({name}_preimage[94]-48);
    log("{name}: ", {name}_year,"-",{name}_month,"-",{name}_day);

    // Convert y-m-d to "daystamp" (number of days since year 0)
    component {name}_ds = Daystamp();
    {name}_ds.year <== {name}_year;
    {name}_ds.month <== {name}_month;
    {name}_ds.day <== {name}_day;

    log("{name}_ds.out =", {name}_ds.out);
    {name}_ds.out === {name}_value;
""")
            elif attr_type == "string":
                f.write(f"""
    signal input {name}_value_l; // The start position in preimage of the {name} value
    signal input {name}_value_r; // The end position in preimage of the {name} value
""")
                if reveal:
                    f.write(f"""
    component reveal_{name} = RevealClaimValue({name}_preimage_len, {max_claim_byte_len}, {MAX_FIELD_BYTE_LEN}, 0);
    reveal_{name}.json_bytes <== {name}_preimage;
    reveal_{name}.l <== {name}_value_l;
    reveal_{name}.r <== {name}_value_r;

    log("{name}_value = ", {name}_value);
    log("reveal_{name}.value = ", reveal_{name}.value);
    {name}_value === reveal_{name}.value;
""")
                elif reveal_digest:
                    f.write(f"""
    component hash_reveal_{name} = HashRevealClaimValue({name}_preimage_len, {max_claim_byte_len}, {MAX_FIELD_BYTE_LEN}, 0);
    hash_reveal_{name}.json_bytes <== {name}_preimage;
    hash_reveal_{name}.l <== {name}_value_l;
    hash_reveal_{name}.r <== {name}_value_r;
    // log each byte of the preimage value between l and r
    for (var i = {name}_value_l; i < {name}_value_r; i++) {{
        log("{name}_preimage[", i, "] = ", {name}_preimage[i]);
    }}
    signal output {name}_digest;
    {name}_digest <== hash_reveal_{name}.digest;
    log("{name}_digest = ", {name}_digest);
    
""")
                else:
                    print(f"Claim {name} is not revealed; not currently supported")
                    sys.exit(-1)
    # FIXME: add support for numbers?
        # ---------- final component -----------------------
        pub_list = ", ".join(public_inputs)
        f.write(f"""
}}

component main {{ public [{pub_list}] }} =
    Main({cfg['max_cred_len']},          // max mDL length
         {MAX_FIELD_BYTE_LEN});
""")

# ======================================================================
#  main
# ======================================================================

if __name__ == "__main__":
    if len(sys.argv) != 3:
        usage(); sys.exit(-1)

    cfg_path, out_path = sys.argv[1:]

    with open(cfg_path) as fp:
        cfg = json.load(fp)

    if not check_config(cfg):
        print("Invalid configuration - exiting"); sys.exit(-1)

    generate_circuit(cfg, out_path)
    print(f"[+] wrote {out_path}")