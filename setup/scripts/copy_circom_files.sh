#!/usr/bin/bash

set -x
set -e

# NAME is the name of one of the subdirectories in inputs
NAME=$1

if [[ "$NAME" = "" ]] ;
then
    echo "Usage: $0 <name of directory in inputs>"
    echo "Must be run from scripts/"
    echo "E.g.: $0 demo"     
    exit -1
fi

# assume we're in scripts dir
cd ..
ROOT_DIR=`pwd`

OUTPUTS_DIR=${ROOT_DIR}/generated_files/$NAME
INPUTS_DIR=${ROOT_DIR}/inputs/$NAME
COPY_DEST=${ROOT_DIR}/../creds/test-vectors/$NAME

PROVER_INPUT_FILE=${OUTPUTS_DIR}/prover_inputs.json
PROVER_AUX_FILE=${OUTPUTS_DIR}/prover_aux.json
PUBLIC_IO_FILE=${OUTPUTS_DIR}/public_IOs.json
R1CS_FILE=${OUTPUTS_DIR}/main_c.r1cs
WIT_GEN_FILE=${OUTPUTS_DIR}/circom/main_js/main.wasm
SYM_FILE=${OUTPUTS_DIR}/circom/io_locations.sym
CONFIG_FILE=${INPUTS_DIR}/config.json
TOKEN_FILE=${INPUTS_DIR}/token.jwt
ISSUER_KEY_FILE=${INPUTS_DIR}/issuer.pub

# Copy the prover inputs, r1cs and wasm into a directory
rm -rf ${COPY_DEST}
mkdir -p ${COPY_DEST}
cp ${PROVER_INPUT_FILE} ${COPY_DEST}/ 
cp ${PROVER_AUX_FILE} ${COPY_DEST}/ 
cp ${PUBLIC_IO_FILE} ${COPY_DEST}/ 
cp ${R1CS_FILE} ${COPY_DEST}/  
cp ${WIT_GEN_FILE} ${COPY_DEST}/ 
cp ${SYM_FILE} ${COPY_DEST}/
cp ${CONFIG_FILE} ${COPY_DEST}/
cp ${TOKEN_FILE} ${COPY_DEST}/
cp ${ISSUER_KEY_FILE} ${COPY_DEST}/
