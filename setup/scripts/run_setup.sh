#!/usr/bin/bash

#set -x
set -e

curve=bn128

# Toggle whether to use WASM for witness generation. By default we use C++ because
# witness generation is about 3x faster. Sometimes there are bugs in Circom's C++
# code gen, and it's helpful to have an alternative. This should only be used 
# for debugging so it's a constant in this script, not an argument.
# Requires that node be installed. The proof bytes and verifier are unchanged.
# When switching this on, remove the directory in generated_files
# to clear anything cached with the C++ generation.
# if [[ -z ${USE_WASM} ]]
# then
# 	USE_WASM=1
# fi

USE_WASM=1

# Argument NAME is the name of one of the subdirectories in inputs
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
INPUTS_DIR=${ROOT_DIR}/inputs/$NAME

LOG_FILE=${OUTPUTS_DIR}/${NAME}.log

# Create the output directory if not there.
mkdir $OUTPUTS_DIR 2>/dev/null || true
mkdir $CIRCOM_DIR 2>/dev/null  || true

touch ${LOG_FILE}

echo "- Generating ${NAME}_main.circom..."

# Generate the circom main file.  
python3 scripts/prepare_setup.py ${INPUTS_DIR}/config.json ${CIRCOM_DIR}/main.circom

echo "- Compiling main.circom..."
echo -e "\n=== circom output start ===" >> ${LOG_FILE}


# Copy the circom files we need to the instance's circom folder.
# TODO: Use -l to specify the path of the includes for the circom compiler build command and use a symlink instead of copying all the time.  At least for /utils and /circomlib and /circom-ecdsa
cp -r ${ROOT_DIR}/circom/* ${CIRCOM_DIR}/

# Compile the circom circuit.  First check if the hash of the circom files has changed, only re-compile if so. To force a re-build remove circom_files.sha256
cd $CIRCOM_DIR

set +e
cat `find . -name "*.circom"` | sha256sum | diff circom_files.sha256 -
if [[ $? -ne 0 ]] || [[ ! -e main_c_cpp ]] ;
then 
    echo "Circom files hash changed; re-compiling" >> ${LOG_FILE}

    if [[ ${USE_WASM} -ne 1 ]] ; 
    then
        echo "Using Circom C++ witness generation" >> ${LOG_FILE}
        circom main.circom --r1cs --c --sym --prime ${curve} | awk -v start=2 -v end=9 'NR>=start && NR<=end' >> ${LOG_FILE}
        cd main_c_cpp
        make -j$(nproc)
        cd ..
    else
        echo "Using Circom WASM witness generation" >> ${LOG_FILE}
        circom main.circom --r1cs --wasm --O2 --sym --prime ${curve} | awk -v start=2 -v end=9 'NR>=start && NR<=end' >> ${LOG_FILE}
        mv main.r1cs main_c.r1cs
    fi

    mv main_c.r1cs ${OUTPUTS_DIR}
    cat `find . -name "*.circom"` | sha256sum  > circom_files.sha256
else
    echo "Circom files did not change; not re-recompiling" >> ${LOG_FILE}
fi
set -e

cd ${ROOT_DIR}

echo "=== circom output end ===" >> ${LOG_FILE}

#echo "- Generate pk and vk ..."
#echo "=== Generate key pair output start ===" >> ${LOG_FILE}

R1CS_FILE=${OUTPUTS_DIR}/main_c.r1cs
PK_FILE=${OUTPUTS_DIR}/pk.bin
VK_FILE=${OUTPUTS_DIR}/vk.bin

# read the number of public inputs from $NAME.log
# there is a line of the form "public inputs: NUM_PUBLIC_INPUTS". parse out NUM_PUBLIC_INPUTS into a variable
NUM_PUBLIC_INPUTS=$(grep -m 1 "public inputs:" "$LOG_FILE" | awk '{print $3}')

# clean up the main.sym file as follows. Each entry is of the form #s, #w, #c, name as described in https://docs.circom.io/circom-language/formats/sym/
awk -v max="$NUM_PUBLIC_INPUTS" -F ',' '$2 != -1 && $2 <= max {split($4, parts, "."); printf "%s,%s\n", parts[2], $2}' "${CIRCOM_DIR}/main.sym" > "${CIRCOM_DIR}/io_locations.sym"

#cargo run --release --features print-trace -- setup --r1cs ${R1CS_FILE} --pk ${PK_FILE} --vk ${VK_FILE}  >> ${LOG_FILE}

#echo "=== Generate key pair output end ===" >> ${LOG_FILE}

cd scripts
echo "Done."

