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

# Create the output directory if not there.
mkdir $OUTPUTS_DIR 2>/dev/null || true
mkdir $CIRCOM_DIR 2>/dev/null  || true

touch ${LOG_FILE}

# Check that cicomlib is present
if [ ! -f circom/circomlib/README.md ]; then
    echo "Circomlib not found.  Run 'git submodule update --init --recursive' to get it."
    exit -1 
fi


echo "- Generating ${NAME}_main.circom..."

# Generate the circom main file.  
python3 scripts/prepare_setup.py ${INPUTS_DIR}/config.json ${CIRCOM_DIR}/main.circom

echo "- Compiling main.circom..."
echo -e "\n=== circom output start ===" >> ${LOG_FILE}


# Copy the circom files we need to the instance's circom folder.
cp -r ${ROOT_DIR}/circom/* ${CIRCOM_DIR}/

# Compile the circom circuit.  First check if the hash of the circom files has changed, only re-compile if so. To force a re-build remove circom_files.sha256
cd $CIRCOM_DIR

set +e
cat `find . -name "*.circom"` | sha256sum | diff circom_files.sha256 -
if [[ $? -ne 0 ]] || [[ ! -e main_c_cpp ]] ;
then 
    echo "Circom files hash changed; re-compiling" >> ${LOG_FILE}

    echo "Using Circom WASM witness generation" >> ${LOG_FILE}
    circom main.circom --r1cs --wasm --O2 --sym --prime ${CURVE} | awk -v start=2 -v end=9 'NR>=start && NR<=end' >> ${LOG_FILE}
    mv main.r1cs main_c.r1cs

    mv main_c.r1cs ${OUTPUTS_DIR}
    cat `find . -name "*.circom"` | sha256sum  > circom_files.sha256
else
    echo "Circom files did not change; not re-recompiling" >> ${LOG_FILE}
fi
set -e

cd ${ROOT_DIR}

echo "=== circom output end ===" >> ${LOG_FILE}

# Read the number of public inputs from $NAME.log
# there is a line of the form "public inputs: NUM_PUBLIC_INPUTS". parse out NUM_PUBLIC_INPUTS into a variable
NUM_PUBLIC_INPUTS=$(grep -m 1 "public inputs:" "$LOG_FILE" | awk '{print $3}')

# clean up the main.sym file as follows. Each entry is of the form #s, #w, #c, name as described in https://docs.circom.io/circom-language/formats/sym/
awk -v max="$NUM_PUBLIC_INPUTS" -F ',' '$2 != -1 && $2 <= max {split($4, parts, "."); printf "%s,%s\n", parts[2], $2}' "${CIRCOM_DIR}/main.sym" > "${CIRCOM_DIR}/io_locations.sym"

# Copy files needed for zksetup, prove, etc..
R1CS_FILE=${OUTPUTS_DIR}/main_c.r1cs
WIT_GEN_FILE=${OUTPUTS_DIR}/circom/main_js/main.wasm
SYM_FILE=${OUTPUTS_DIR}/circom/io_locations.sym
CONFIG_FILE=${INPUTS_DIR}/config.json
TOKEN_FILE=${INPUTS_DIR}/token.jwt
ISSUER_KEY_FILE=${INPUTS_DIR}/issuer.pub

rm -rf ${COPY_DEST}
mkdir -p ${COPY_DEST}
cp ${R1CS_FILE} ${COPY_DEST}/  
cp ${WIT_GEN_FILE} ${COPY_DEST}/ 
cp ${SYM_FILE} ${COPY_DEST}/
cp ${CONFIG_FILE} ${COPY_DEST}/
cp ${TOKEN_FILE} ${COPY_DEST}/
cp ${ISSUER_KEY_FILE} ${COPY_DEST}/

cd scripts
echo "Done."

