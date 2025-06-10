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

# Determine the credential type, JWT or mDL
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

# Replace linux symlink with junction if on Windows
# There is a scenario where the symlink is broken on Windows, but then copied to the Ubuntu Docker container.
# In this case, we need to remove the broken symlink and create a new one.
if [ -f "${CIRCOM_SRC_DIR}/circomlib" ]; then
    echo "Detected broken symlink at ${CIRCOM_SRC_DIR}/circomlib"
    rm -f "${CIRCOM_SRC_DIR}/circomlib"
    if [[ "$OS" == "Windows_NT" || "$(uname -o 2>/dev/null)" == "Msys" ]]; then
        echo "Creating Windows junction..."
        cmd //c "mklink /J $(cygpath -wa "$CIRCOM_SRC_DIR"/circomlib) $(cygpath -wa "${ROOT_DIR}/circuits/circomlib")"
    else
        echo "Creating Linux symlink..."
        ln -s "${ROOT_DIR}/circuits/circomlib" "${CIRCOM_SRC_DIR}/circomlib"
fi
fi


# Determine if the credential should be device bound
DEVICE_BOUND_REGEX="\"device_bound\": ([a-z]+)"
if [[ `cat ${INPUTS_DIR}/config.json` =~ $DEVICE_BOUND_REGEX ]]; then
    if [ "${BASH_REMATCH[1]}" = "true" ]; then  
        DEVICE_BOUND=1 
    else
        DEVICE_BOUND=0
    fi
else
    DEVICE_BOUND=0
fi
echo "Credential is device bound: $DEVICE_BOUND"

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
    else
        echo "Error: algorithm not found in config.json"
        exit 1
    fi
    python3 scripts/jwk_gen.py ${ALG} ${INPUTS_DIR}/issuer.prv ${INPUTS_DIR}/issuer.pub
    if [ $DEVICE_BOUND ]; then
        echo "Creating device public key"
        python3 scripts/jwk_gen.py ES256 ${INPUTS_DIR}/device.prv ${INPUTS_DIR}/device.pub
        python3 scripts/jwt_sign.py ${INPUTS_DIR}/claims.json ${INPUTS_DIR}/issuer.prv  ${INPUTS_DIR}/token.jwt ${INPUTS_DIR}/device.pub
    else
        python3 scripts/jwt_sign.py ${INPUTS_DIR}/claims.json ${INPUTS_DIR}/issuer.prv  ${INPUTS_DIR}/token.jwt
    fi
elif [ ${CREDTYPE} == 'mdl' ] && ([ ! -f ${INPUTS_DIR}/device.prv ] || [ ! -f ${INPUTS_DIR}/issuer.prv ] || [ ! -f ${INPUTS_DIR}/issuer.pub ] || [ ! -f ${INPUTS_DIR}/issuer_certs.pem ] || [ ! -f ${INPUTS_DIR}/mdl.cbor ]); then
    echo "Creating sample issuer keys and mDL"
    rm ${INPUTS_DIR}/device.prv ${INPUTS_DIR}/issuer.prv ${INPUTS_DIR}/issuer.pub ${INPUTS_DIR}/issuer_certs.pem ${INPUTS_DIR}/mdl.org ${OUTPUTS_DIR}/issuer.pub 2>/dev/null && true         

    if [[ `cat ${INPUTS_DIR}/config.json` =~ $ALG_REGEX ]]; then
        ALG="${BASH_REMATCH[1]}"
        echo "Creating sample device/issuer keys and mdl for algorithm $ALG"
    else
        echo "Error: algorithm not found in config.json"
        exit 1
    fi
    cd ${ROOT_DIR}/scripts
    ./gen_mdl_device_key.sh
    ./gen_x509_cert_chain.sh
    cd ${ROOT_DIR}
fi

# Check that circomlib is present
if [ ! -f ${CIRCOM_SRC_DIR}/circomlib/README.md ]; then
    echo "Circomlib not found.  Run 'git submodule update --init --recursive' to get it."
    exit -1 
fi

echo "- Generating ${NAME}_main.circom..."

# Generate the circom main file.  
if [ ${CREDTYPE} == 'mdl' ]; then
    python3 scripts/prepare_mdl_setup.py ${INPUTS_DIR}/config.json ${CIRCOM_DIR}/main.circom
else
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
# for mDL, we need to add the device public key to the number of public inputs
if [ "${CREDTYPE}" == "mdl" ] && [ "${DEVICE_BOUND}" == "1" ]; then
    echo "Device bound mDL detected, adding device public key to public inputs"
    NUM_PUBLIC_INPUTS=$((NUM_PUBLIC_INPUTS + 2))
fi
NUM_PUBLIC_IOS=$(($NUM_PUBLIC_INPUTS + $NUM_PUBLIC_OUTPUTS))
echo "Number of public inputs: $NUM_PUBLIC_INPUTS"
echo "Number of public outputs: $NUM_PUBLIC_OUTPUTS"
echo "Total number of public I/Os: $NUM_PUBLIC_IOS"   

# clean up the main.sym file as follows. Each entry is of the form #s, #w, #c, name as described in https://docs.circom.io/circom-language/formats/sym/
awk -v max="$NUM_PUBLIC_IOS" -F ',' '$2 != -1 && $2 <= max {split($4, parts, "."); printf "%s,%s\n", parts[2], $2}' "${CIRCOM_DIR}/main.sym" > "${CIRCOM_DIR}/io_locations.sym"

if [ ${CREDTYPE} == 'mdl' ]; then 
    echo "=== Generating mDL ===" # delete me
    # Create the prover inputs (TODO: now that this has been ported to rust, do it in the library like for the JWT case)
    PROVER_INPUTS_FILE=${OUTPUTS_DIR}/prover_inputs.json
    PROVER_AUX_FILE=${OUTPUTS_DIR}/prover_aux.json
    MDL_FILE=${INPUTS_DIR}/mdl.cbor
    CONFIG_FILE=${INPUTS_DIR}/config.json
    CLAIMS_FILE=${INPUTS_DIR}/claims.json
    DEVICE_PRIV_KEY_FILE=${INPUTS_DIR}/device.prv
    ISSUER_PRIV_KEY_FILE=${INPUTS_DIR}/issuer.prv
    ISSUER_CERTS_FILE=${INPUTS_DIR}/issuer_certs.pem
    ISSUER_KEY_FILE=${OUTPUTS_DIR}/issuer.pub
    
    cd ${ROOT_DIR}/mdl-tools
    echo "Current dir: `pwd`"

    # generate the mDL
    cargo run --release --bin mdl-gen -- --claims ${CLAIMS_FILE} --device_priv_key ${DEVICE_PRIV_KEY_FILE} --issuer_private_key ${ISSUER_PRIV_KEY_FILE} --issuer_x5chain ${ISSUER_CERTS_FILE} --output ${MDL_FILE} 2>> ${LOG_FILE}
    if [ $? -ne 0 ]; then
        echo "Error running prepare_mdl_prover"
        exit 1
    fi
    
    # generate the prover inputs
    cargo run --release --bin prepare-prover-input -- --config ${CONFIG_FILE} --mdl ${MDL_FILE} --prover_inputs ${PROVER_INPUTS_FILE} --prover_aux ${PROVER_AUX_FILE} 2>> ${LOG_FILE}
    if [ $? -ne 0 ]; then
        echo "Error running prepare_prover_input"
        exit 1
    fi

    # extract key and signature from prover_inputs.json and add ecdsa precomputation and hash
    node ${ROOT_DIR}/scripts/precompEcdsa.js ${OUTPUTS_DIR}/prover_inputs.json

    cd ${ROOT_DIR}
fi

echo "Copying files to ${COPY_DEST}..."

# Copy files needed for zksetup, prove, etc..
R1CS_FILE=${OUTPUTS_DIR}/main_c.r1cs
WIT_GEN_FILE=${OUTPUTS_DIR}/circom/main_js/main.wasm
SYM_FILE=${OUTPUTS_DIR}/circom/io_locations.sym
CONFIG_FILE=${INPUTS_DIR}/config.json
ISSUER_KEY_FILE=${INPUTS_DIR}/issuer.pub
PROOF_SPEC_FILE=${INPUTS_DIR}/proof_spec.json
DEVICE_PUB_FILE=${INPUTS_DIR}/device.pub
DEVICE_PRV_FILE=${INPUTS_DIR}/device.prv
if [ ${CREDTYPE} == 'jwt' ]; then
    CRED_FILE=${INPUTS_DIR}/token.jwt
elif [ ${CREDTYPE} == 'mdl' ]; then 
    CRED_FILE=${INPUTS_DIR}/mdl.cbor
fi

rm -rf ${COPY_DEST}
mkdir -p ${COPY_DEST}
cp ${R1CS_FILE} ${COPY_DEST}/  
cp ${WIT_GEN_FILE} ${COPY_DEST}/ 
cp ${SYM_FILE} ${COPY_DEST}/
cp ${CONFIG_FILE} ${COPY_DEST}/
cp ${ISSUER_KEY_FILE} ${COPY_DEST}/
cp ${CRED_FILE} ${COPY_DEST}/
cp ${DEVICE_PUB_FILE} ${COPY_DEST}/ || true     # Optional file for JWTs
cp ${DEVICE_PRV_FILE} ${COPY_DEST}/ || true     # Optional file for JWTs
cp ${PROOF_SPEC_FILE} ${COPY_DEST}/
if [ ${CREDTYPE} == 'mdl' ]; then 
    cp ${PROVER_INPUTS_FILE} ${COPY_DEST}/
    cp ${PROVER_AUX_FILE} ${COPY_DEST}/
fi

cd scripts
echo "Done."
