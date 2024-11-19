# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

#!/usr/bin/bash

set -x
set -e

# NAME is the name of one of the subdirectories in inputs
NAME=$1

if [[ "$NAME" = "" ]] ;
then
    echo "\nDEPRECATED: This script is no longer required; prover inputs should be generated with crescent/creds/src/prep_inputs.rs\n" 
    echo "Usage: $0 <name of directory in inputs>"
    echo "Must be run from scripts/"
    echo "E.g.: $0 demo"     
    exit -1
fi

# assume we're in scripts dir
cd ..
ROOT_DIR=`pwd`

OUTPUTS_DIR=${ROOT_DIR}/generated_files/$NAME
TOKEN_DIR=${ROOT_DIR}/inputs/$NAME

LOG_FILE=${OUTPUTS_DIR}/${NAME}.log

touch ${LOG_FILE}

# Create the prover's inputs and public IOs
PROVER_INPUT_FILE=${OUTPUTS_DIR}/prover_inputs.json
PUBLIC_INPUT_FILE=${OUTPUTS_DIR}/public_IOs.json
python3 ./scripts/prepare_prover.py ${TOKEN_DIR}/config.json ${TOKEN_DIR}/issuer.pub ${TOKEN_DIR}/token.jwt ${PUBLIC_INPUT_FILE} > ${PROVER_INPUT_FILE}


cd scripts
echo "Done."

