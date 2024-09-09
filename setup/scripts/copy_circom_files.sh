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

PROVER_INPUT_FILE=${OUTPUTS_DIR}/prover_inputs.json
PROVER_AUX_FILE=${OUTPUTS_DIR}/prover_aux.json
PUBLIC_IO_FILE=${OUTPUTS_DIR}/public_IOs.json
R1CS_FILE=${OUTPUTS_DIR}/main_c.r1cs
WIT_GEN_FILE=${OUTPUTS_DIR}/circom/main_js/main.wasm
SYM_FILE=${OUTPUTS_DIR}/circom/io_locations.sym

# Copy the prover inputs, r1cs and wasm into a directory
rm -rf ${OUTPUTS_DIR}/ark_inputs
mkdir -p ${OUTPUTS_DIR}/ark_inputs
cp ${PROVER_INPUT_FILE} ${OUTPUTS_DIR}/ark_inputs/
cp ${PROVER_AUX_FILE} ${OUTPUTS_DIR}/ark_inputs/
cp ${PUBLIC_IO_FILE} ${OUTPUTS_DIR}/ark_inputs/
cp ${R1CS_FILE} ${OUTPUTS_DIR}/ark_inputs/
cp ${WIT_GEN_FILE} ${OUTPUTS_DIR}/ark_inputs/
cp ${SYM_FILE} ${OUTPUTS_DIR}/ark_inputs/