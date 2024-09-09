#!/usr/bin/bash

#set -x
set -e

# NAME is the name of one of the subdirectories in inputs
NAME=$1
# $2 is an optional parameter that we can use to specify the name of the proof file

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

echo "- Generate verifier's input..."
VERIFIER_INPUT_FILE=${OUTPUTS_DIR}/verifier_inputs.json
PUBLIC_INPUT_FILE=${OUTPUTS_DIR}/public_IOs.json
./scripts/prepare_verifier.py ${TOKEN_DIR}/config.json ${TOKEN_DIR}/issuer.pub ${PUBLIC_INPUT_FILE} > ${VERIFIER_INPUT_FILE}

echo "- Verify Spartan proof for proving ${NAME}..."
echo -e "\n=== Verify proof output start ===" >> ${LOG_FILE}

VK_FILE=${OUTPUTS_DIR}/vk.bin

PROOF_FILE=${OUTPUTS_DIR}/proof.bin
if [[ $2 != "" ]] ;
then
    PROOF_FILE=${OUTPUTS_DIR}/$2
fi


cargo run --release --features print-trace -- verify --input ${VERIFIER_INPUT_FILE} --vk ${VK_FILE} --proof ${PROOF_FILE} >> ${LOG_FILE}

echo "=== Verify proof output end ===" >> ${LOG_FILE}

cd scripts
echo "Done."

