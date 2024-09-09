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
CIRCOM_DIR=${OUTPUTS_DIR}/circom
TOKEN_DIR=${ROOT_DIR}/inputs/$NAME

LOG_FILE=${OUTPUTS_DIR}/${NAME}.log

touch ${LOG_FILE}

# Create the prover's inputs and public IOs
PROVER_INPUT_FILE=${OUTPUTS_DIR}/prover_inputs.json
PUBLIC_INPUT_FILE=${OUTPUTS_DIR}/public_IOs.json
./scripts/prepare_prover.py ${TOKEN_DIR}/config.json ${TOKEN_DIR}/issuer.pub ${TOKEN_DIR}/token.jwt ${PUBLIC_INPUT_FILE} > ${PROVER_INPUT_FILE}

#echo "- Generate Spartan proof for proving ${NAME}..."
#echo -e "\n=== Generate proof output start ===" >> ${LOG_FILE}
#
#R1CS_FILE=${OUTPUTS_DIR}/main_c.r1cs
#PK_FILE=${OUTPUTS_DIR}/pk.bin
#PROOF_FILE=${OUTPUTS_DIR}/proof.bin
#
#WIT_GEN_FILE=${CIRCOM_DIR}/main_c_cpp/main_c
#if [[ ! -e ${WIT_GEN_FILE} ]] ; 
#then
#    WIT_GEN_FILE=${CIRCOM_DIR}/main_js/main.wasm
#fi
#
#cargo run --release --features print-trace -- prove --r1cs ${R1CS_FILE} --input ${PROVER_INPUT_FILE} --pk ${PK_FILE} --witness-generator ${WIT_GEN_FILE} --proof ${PROOF_FILE} >> ${LOG_FILE}
#
#echo "=== Generate proof output end ===" >> ${LOG_FILE}

cd scripts
echo "Done."

