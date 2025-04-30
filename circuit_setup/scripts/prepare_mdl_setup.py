# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

#!/usr/bin/env python3

import os, sys, json
from crescent_helper import *

########################################################################
# Helper functions
########################################################################

def usage():
    print(f"Usage: ./{os.path.basename(sys.argv[0])} <config file> <circom output file>")

def main_circom_header(cfg):
    if cfg["alg"] == "ES256":
        tmpl = "circuits-mdl/main_header_es256.circom.template"
    else:
        print("Unsupported alg for mDL:", cfg["alg"]); sys.exit(-1)
    with open(tmpl) as f: return f.read()

# TODO: remove this function (temp function until we implement the proper behavior)
def main_circom_birth_date():
    with open("circuits-mdl/main_birth_date.circom.template") as f:
        return f.read()

########################################################################
# Core generation logic
########################################################################

def prepare_circom(cfg, out_file):

    # 1 Birth-date-only fast path ...............................
    user_keys = [k for k in cfg.keys() if k not in CRESCENT_CONFIG_KEYS]

    # 2 Dynamic generation (step 2) .............................
    print_debug("== Prepare mDL circom ==")

    with open(out_file, "w") as f:
        f.write(main_circom_header(cfg))

        for name in user_keys:
            if name == "birth_date":
                f.write(main_circom_birth_date())
                continue

        # ---- final component ------------------------------------
        f.write(f"""
}}

component main {{ public [pubkey_x, pubkey_y, valid_until_value, dob_value] }} = Main(1792, 1792, {MAX_FIELD_BYTE_LEN}, 43, 6);
""")

######## Main ###########

if len(sys.argv) != 3: usage(); sys.exit(-1)

with open(sys.argv[1]) as fp:
    config = json.load(fp)

if not check_config(config):
    print("Invalid config, exiting"); sys.exit(-1)

prepare_circom(config, sys.argv[2])
