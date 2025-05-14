# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

#!/usr/bin/env python3

import os, sys, json
from crescent_helper import *

# mDL attributes

# TODO: generate this programmatically
mDL_attributes = {
    "birth_date": {
        "cbor_str": "[106, 98, 105, 114, 116, 104, 95, 100, 97, 116, 101]",
        "cbor_str_len": 11
    },
    "resident_state": {
        "cbor_str": "[110, 114, 101, 115, 105, 100, 101, 110, 116, 95, 115, 116, 97, 116, 101]",
        "cbor_str_len": 15
    }
}

# ----------------------------------------------------------------------
def usage():
    exe = os.path.basename(sys.argv[0])
    print(f"Usage: ./{exe}  <config.json>  <out.circom>")

def circom_header(cfg):
    if cfg.get("alg") != "ES256":
        print("Unsupported alg:", cfg.get("alg")); sys.exit(-1)
    with open("circuits-mdl/main_header_es256.circom.template") as f:
        return f.read()

# ======================================================================
#  generator
# ======================================================================

def generate_circuit(cfg: dict, out_path: str) -> None:

    print_debug("== generate generic mDL circuit ==")

    attrs = [k for k in cfg if k not in CRESCENT_CONFIG_KEYS]

    public_inputs = [] # ["pubkey_x", "pubkey_y"] FIXME: add these back
    # add other public signals below if you want them exported FIXME
    # public_inputs.append("threshold_days")  # example

    with open(out_path, "w") as f:

        # ---------- static header --------------------------
        f.write(circom_header(cfg))

        f.write(f"""
    // ------------------------------------------------------------
    // The following code handle the attribute disclosure. For each, we need the following inputs:
    //   - attribute_value: the value of the attribute; for date types, this in an integer (days since year 0000)
    //   - attribute_id: the id of the attribute (currently limited to 1 byte)
    //   - attribute_preimage: the sha256-padded preimage of the mDL IssuerSignedItem formatted as follows:
    //    'digestID': 
    //    'random': random salt
    //    'elementIdentifier': CBOR encoded string of the attribute name,
    //    'elementValue': the attribute value
    // Then we check TODO
    // FIXME: support <attr>_id > 23 (which would be encoded in 2+ bytes)
""")
        for name in attrs:

            # read config
            attr_type = cfg[name].get("type")
            reveal = cfg[name].get("reveal")
            max_claim_byte_len = cfg[name].get("max_claim_byte_len")
            name_identifier = mDL_attributes[name]["cbor_str"]
            name_identifier_len = mDL_attributes[name]["cbor_str_len"]
            name_preimage_len = 128 # don't hardcode; calculate from max_claim_byte_len?

            if (reveal is None) or (reveal == "false"):
                # FIXME: is that ok? maybe we need to handle the attribute, but not make it part of the public inputs?
                print(f"Skipping {name} (not revealed)"); continue

            print(f"Writing circuit code for {name} ({attr_type})")                        

            # add attribute to the public inputs
            if name not in public_inputs:
                public_inputs.append(f"{name}_value")

            f.write(f"""
    // ------------------------------------------------------------
    //  {name}
    // ------------------------------------------------------------
    var {name}_preimage_len = {name_preimage_len}; // FIXME: hardcoded for now
    signal input {name}_value;
    signal input {name}_id;
    signal input {name}_preimage[{name}_preimage_len]; // FIXME: not all attributes are 128 bytes long!
    signal input {name}_identifier_l;     // The position of the {name} indicator in the preimage

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

    component {name}_sha_bytes = Sha256Bytes({name}_preimage_len);
    {name}_sha_bytes.in_padded <== {name}_preimage;
    {name}_sha_bytes.in_len_padded_bytes <== {name_preimage_len};

    component {name}_hash_bytes = DigestToBytes();
    {name}_hash_bytes.in <== {name}_sha_bytes.out;

    signal encoded_{name}_digest[35]; // FIXME: don't hardcode 35
    encoded_{name}_digest[0] <== {name}_id; 
    encoded_{name}_digest[1] <== 88;   // == 0x58
    encoded_{name}_digest[2] <== 32;   // == 0x20
    for(var i = 0; i < 32; i++ ) {{
        encoded_{name}_digest[i + 3] <== {name}_hash_bytes.out[i];
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

    component reveal_{name} = RevealClaimValue({name}_preimage_len, {max_claim_byte_len}, {MAX_FIELD_BYTE_LEN}, 0);
    reveal_{name}.json_bytes <== {name}_preimage;
    reveal_{name}.l <== {name}_value_l;
    reveal_{name}.r <== {name}_value_r;

    log("{name}_value = ", {name}_value);
    log("reveal_{name}.value = ", reveal_{name}.value);
    {name}_value === reveal_{name}.value;
""")

        # ---------- final component -----------------------
        pub_list = ", ".join(public_inputs)
        f.write(f"""
}}

component main {{ public [{pub_list}] }} =
    Main({cfg['max_cred_len']},          // max mDL length
         {MAX_FIELD_BYTE_LEN},
         {CIRCOM_P256_LIMB_BITS},
         {CIRCOM_P256_N_LIMBS});
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