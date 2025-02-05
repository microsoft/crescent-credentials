# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

#!/usr/bin/bash

#set -x
set -e

CURVE=bn128

# Argument NAME is the name of one of the subdirectories in inputs
NAME=$1

if [[ "$NAME" = "" ]] ;
then
    echo "Usage: $0 <name of directory in inputs>"
    echo "Must be run from scripts/"
    echo "E.g.: $0 rs256" 
    exit -1
fi

# assume we're in scripts dir
cd ..
ROOT_DIR=`pwd`

OUTPUTS_DIR=${ROOT_DIR}/generated_files/$NAME
CIRCOM_DIR=${OUTPUTS_DIR}/circom
INPUTS_DIR=${ROOT_DIR}/inputs/$NAME
COPY_DEST=${ROOT_DIR}/../creds/test-vectors/$NAME
LOG_FILE=${OUTPUTS_DIR}/${NAME}.log

if [ ! -f ${INPUTS_DIR}/config.json ]; then
    echo "${INPUTS_DIR}/config.json is not found, aborting"
    exit -1 
fi

CREDTYPE_REGEX="\"credtype\": \"([a-z]+)\""
if [[ `cat ${INPUTS_DIR}/config.json` =~ $CREDTYPE_REGEX ]]; then
    CREDTYPE="${BASH_REMATCH[1]}"
    echo "Credential type read from config.json: $CREDTYPE"
else
    CREDTYPE="jwt"
    echo "Credential type not found in config.json, assuming JWT"
fi

if [ $CREDTYPE == 'mdl' ]; then 
    CIRCOM_SRC_DIR="${ROOT_DIR}/circuits-mdl"
else
    CIRCOM_SRC_DIR="${ROOT_DIR}/circuits"
fi


# Create the output directory if not there.
mkdir $OUTPUTS_DIR 2>/dev/null || true
mkdir $CIRCOM_DIR 2>/dev/null  || true

touch ${LOG_FILE}

# For JWTs, we create sample issuer keys and a token
ALG_REGEX="\"alg\": \"([A-Z0-9]+)\""
if [ ${CREDTYPE} == 'jwt' ] && ([ ! -f ${INPUTS_DIR}/issuer.pub ] || [ ! -f ${INPUTS_DIR}/issuer.prv ] || [ ! -f ${INPUTS_DIR}/token.jwt ]); then
    rm ${INPUTS_DIR}/issuer.pub ${INPUTS_DIR}/issuer.prv ${INPUTS_DIR}/token.jwt 2>/dev/null && true 

    if [[ `cat ${INPUTS_DIR}/config.json` =~ $ALG_REGEX ]]; then
        ALG="${BASH_REMATCH[1]}"
        echo "Creating sample keys and token for algorithm $ALG"
    fi
    python3 scripts/jwk_gen.py ${ALG} ${INPUTS_DIR}/issuer.prv ${INPUTS_DIR}/issuer.pub
    python3 scripts/jwt_sign.py ${INPUTS_DIR}/claims.json ${INPUTS_DIR}/issuer.prv  ${INPUTS_DIR}/token.jwt
fi

# Check that circomlib is present
if [ ! -f ${CIRCOM_SRC_DIR}/circomlib/README.md ]; then
    echo "Circomlib not found.  Run 'git submodule update --init --recursive' to get it."
    exit -1 
fi

echo "- Generating ${NAME}_main.circom..."

# Generate the circom main file.  
if [ ${CREDTYPE} != 'mdl' ]; then
    python3 scripts/prepare_setup.py ${INPUTS_DIR}/config.json ${CIRCOM_DIR}/main.circom
fi

echo "- Compiling main.circom..."
echo -e "\n=== circom output start ===" >> ${LOG_FILE}


# Copy the circom files we need to the instance's circom folder.
cp -r -L ${CIRCOM_SRC_DIR}/* ${CIRCOM_DIR}/

# Compile the circom circuit.  First check if the hash of the circom files has changed, only re-compile if so. To force a re-build remove circom_files.sha256
cd $CIRCOM_DIR
echo "Using Circom WASM witness generation" >> ${LOG_FILE}
circom main.circom --r1cs --wasm --O2 --sym --prime ${CURVE} | awk -v start=2 -v end=9 'NR>=start && NR<=end' >> ${LOG_FILE}
mv main.r1cs main_c.r1cs
mv main_c.r1cs ${OUTPUTS_DIR}

cd ${ROOT_DIR}

echo "=== circom output end ===" >> ${LOG_FILE}

# Read the number of public inputs from $NAME.log
# there is a line of the form "public inputs: NUM_PUBLIC_INPUTS". parse out NUM_PUBLIC_INPUTS into a variable
NUM_PUBLIC_INPUTS=$(grep -m 1 "public inputs:" "$LOG_FILE" | awk '{print $3}')
NUM_PUBLIC_OUTPUTS=$(grep -m 1 "public outputs:" "$LOG_FILE" | awk '{print $3}')
NUM_PUBLIC_IOS=$(($NUM_PUBLIC_INPUTS + $NUM_PUBLIC_OUTPUTS))

# clean up the main.sym file as follows. Each entry is of the form #s, #w, #c, name as described in https://docs.circom.io/circom-language/formats/sym/
awk -v max="$NUM_PUBLIC_IOS" -F ',' '$2 != -1 && $2 <= max {split($4, parts, "."); printf "%s,%s\n", parts[2], $2}' "${CIRCOM_DIR}/main.sym" > "${CIRCOM_DIR}/io_locations.sym"

if [ ${CREDTYPE} == 'mdl' ]; then 
    # Create the prover inputs (do it here, rather than in Rust like we do for JWTs; since the CBOR/mDL parsing code is in python) TODO: in future we should re-write it in rust
    PROVER_INPUTS_FILE=${OUTPUTS_DIR}/prover_inputs.json
    CRED_FILE=${INPUTS_DIR}/cred.txt
    CONFIG_FILE=${INPUTS_DIR}/config.json
    ISSUER_KEY_FILE=${OUTPUTS_DIR}/issuer.pub
    cd scripts/
    python3 prepare_mdl_prover.py ${CONFIG_FILE} ${CRED_FILE}  ${PROVER_INPUTS_FILE} ${ISSUER_KEY_FILE}
    cd ${ROOT_DIR}
fi


# Copy files needed for zksetup, prove, etc..
R1CS_FILE=${OUTPUTS_DIR}/main_c.r1cs
WIT_GEN_FILE=${OUTPUTS_DIR}/circom/main_js/main.wasm
SYM_FILE=${OUTPUTS_DIR}/circom/io_locations.sym
CONFIG_FILE=${INPUTS_DIR}/config.json
TOKEN_FILE=${INPUTS_DIR}/token.jwt
ISSUER_KEY_FILE=${INPUTS_DIR}/issuer.pub
PROOF_SPEC_FILE=${INPUTS_DIR}/proof_spec.json

rm -rf ${COPY_DEST}
mkdir -p ${COPY_DEST}
cp ${R1CS_FILE} ${COPY_DEST}/  
cp ${WIT_GEN_FILE} ${COPY_DEST}/ 
cp ${SYM_FILE} ${COPY_DEST}/
cp ${CONFIG_FILE} ${COPY_DEST}/
cp ${ISSUER_KEY_FILE} ${COPY_DEST}/

if [ ${CREDTYPE} == 'jwt' ]; then
    cp ${TOKEN_FILE} ${COPY_DEST}/
    cp ${PROOF_SPEC_FILE} ${COPY_DEST}/ || true     # Optional file
fi

if [ ${CREDTYPE} == 'mdl' ]; then 
    cp ${PROVER_INPUTS_FILE} ${COPY_DEST}/
fi

cd scripts
echo "Done."

