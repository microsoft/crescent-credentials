#!/usr/bin/bash
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
#

set -eE -o pipefail -o errtrace
shopt -s extglob globstar nullglob


readonly CURVE=bn128

trap 'error "Unexpected error at line $LINENO in command: $BASH_COMMAND" "$?"' ERR


main() {
    usage "$@"
    setup
    generate_keys
    compile_circuit
    generate_mdl
    copy_artifacts
    prune
}

###############################################################################
#   Process command line arguments
#   Display usage information if arguments are missing or invalid
###############################################################################
usage() { 
    readonly SCRIPT_NAME="${0##*/}"
    readonly NAME=$1
    readonly PRUNE=$([[ "$2" == "--prune" ]] && echo true || echo "")

    readonly CRESCENT_ENV=${CRESCENT_ENV:-release}
    [[ "$CRESCENT_ENV" =~ ^(release|debug)$ ]] || { echo "Invalid CRESCENT_ENV: $CRESCENT_ENV" >&2; exit 1; }
    RELEASE_FLAG=$([[ "$CRESCENT_ENV" == "debug" ]] && echo "" || echo "--release")
    BIN=$(pwd)/target/${CRESCENT_ENV}

    if [[ -z "$NAME" || "$NAME" == "--prune" ]]; then
        echo
        echo -e "Usage: $SCRIPT_NAME <name of directory in inputs> [--prune]"
        echo
        echo "  <name>     Required. Name of the subdirectory under 'inputs/'."
        echo
        echo "  --prune    Optional. Cleans up intermediate artifacts after building."
        echo
        echo "             The subsequent run will take longer as it will recompile the circuit."
        echo
        echo "Example:"
        echo "  $0 rs256 --prune"
        echo 
        echo "Available inputs:"
        for dir in "../inputs"/*/; do
            echo "  - $(basename "$dir")"
        done
        exit 2
    fi
}


###############################################################################
#   Set up the environment and paths
#   Read the config.json file
#   Create the output directory and log file
#   Copy circom files to the instance's circom folder
###############################################################################
setup() {
    # Ensure this script runs from its own directory.
    # All paths are relative to this directory so this script can be run from anywhere.
    cd "$(dirname "${BASH_SOURCE[0]}")"

    readonly SCRIPTS_DIR=$(pwd)
    readonly CIRCUIT_SETUP=$(realpath "$SCRIPTS_DIR"/..)
    readonly ROOT_DIR=$(realpath "$CIRCUIT_SETUP"/..)
    readonly OUTPUTS_DIR=${CIRCUIT_SETUP}/generated_files/$NAME
    readonly INPUTS_DIR=${CIRCUIT_SETUP}/inputs/$NAME
    readonly COPY_DEST=$(realpath "${CIRCUIT_SETUP}/../creds/test-vectors/$NAME")
    readonly CIRCOM_DIR=${OUTPUTS_DIR}/circom
    readonly LOG_FILE=${OUTPUTS_DIR}/${NAME}.log
    readonly CONFIG_FILE=${INPUTS_DIR}/config.json
    readonly BIN=${ROOT_DIR}/target/${CRESCENT_ENV}

    assert_path "$CONFIG_FILE" "$INPUTS_DIR"/claims.json "$INPUTS_DIR"/proof_spec.json

    declare -g -A CONFIG 
    CONFIG[alg]=$(json_get "$CONFIG_FILE" alg)
    CONFIG[credtype]=$(json_get "$CONFIG_FILE" credtype); : "${CONFIG[credtype]:=jwt}"
    CONFIG[device_bound]=$([[ $(json_get "$CONFIG_FILE" device_bound) == "true" ]] && echo 1 || echo 0)
    readonly -n CONFIG

    if [[ -z ${CONFIG[alg]} ]]; then
        error "Algorithm (alg) not found in config.json."
    fi

    if [[ ${CONFIG[credtype]} == "mdl" ]]; then
        fix_symlink "${CIRCUIT_SETUP}/circuits-mdl/circomlib" "${CIRCUIT_SETUP}/circuits/circomlib"
    fi

    blue "Name: $(printf "%-10s" "$NAME") | Credential type: ${CONFIG[credtype]} | Credential algorithm: ${CONFIG[alg]} | Device bound: ${CONFIG[device_bound]}"

    if [[ ${CONFIG[credtype]} == "mdl" ]]; then
        readonly CIRCOM_SRC_DIR="${CIRCUIT_SETUP}/circuits-mdl"
    else
        readonly CIRCOM_SRC_DIR="${CIRCUIT_SETUP}/circuits"
    fi

    if [ ! -f "${CIRCOM_SRC_DIR}/circomlib/package.json" ]; then
        error "Circomlib not found. Run 'git submodule update --init --recursive' to get it."
    fi

    mkdir -p "$OUTPUTS_DIR" "$CIRCOM_DIR"
    : > "$LOG_FILE"

    cp -r -L "${CIRCOM_SRC_DIR}"/* "${CIRCOM_DIR}/"
}

###############################################################################
#   Create issuer keys, device keys, certs, and tokens
###############################################################################
generate_keys() {
    pushd "$INPUTS_DIR" > /dev/null

    local jwt_files=(issuer.prv issuer.pub token.jwt claims.json )
    local jwt_db_files=("${jwt_files[@]}" device.prv device.pub)
    local mdl_files=(issuer.prv issuer.pub device.prv device.pub issuer_certs.pem)

    if [[ ${CONFIG[credtype]} == "jwt" ]]; then

        local -r scripts_dir=$(relative_path "${SCRIPTS_DIR}")

        if [[ ${CONFIG[device_bound]} == 1 ]] && have_files_changed "${jwt_db_files[@]}"; then
            echo "${NAME}: Creating issuer and device keys and JWT"
            python3 "${scripts_dir}"/jwk_gen.py "${CONFIG[alg]}" issuer.prv issuer.pub
            python3 "${scripts_dir}"/jwk_gen.py ES256 device.prv device.pub
            python3 "${scripts_dir}"/jwt_sign.py claims.json issuer.prv token.jwt device.pub
            checkpoint_files "${jwt_db_files[@]}"

        elif [[ ${CONFIG[device_bound]} == 0 ]] && have_files_changed "${jwt_files[@]}"; then
            echo "${NAME}: Creating issuer keys and JWT"
            python3 "${scripts_dir}"/jwk_gen.py "${CONFIG[alg]}" issuer.prv issuer.pub
            python3 "${scripts_dir}"/jwt_sign.py claims.json issuer.prv token.jwt;
            checkpoint_files "${jwt_files[@]}"

        else 
            green "${NAME}: Using existing keys and token"
        fi

    elif [[ ${CONFIG[credtype]} == 'mdl'  ]]; then 
    
        if have_files_changed "${mdl_files[@]}"; then
            echo "Creating sample issuer keys and mDL"
            rm -f ./!(*.json) 
            echo "Creating sample device/issuer keys and mdl for algorithm ${CONFIG[alg]}"
            "$SCRIPTS_DIR"/gen_mdl_device_key.sh
            "$SCRIPTS_DIR"/gen_x509_cert_chain.sh
            checkpoint_files "${mdl_files[@]}"
        else 
            green "${NAME}: Using existing keys"
        fi

    fi

    popd > /dev/null
}

###############################################################################
#   Generate circom main r1cs file
#   Extract the number of public inputs and outputs into io_locations.sym
###############################################################################
compile_circuit() {
    local circuit_inputs=(
        "${INPUTS_DIR}/config.json"
        "${CIRCOM_SRC_DIR}/main_header_${CONFIG[alg],,}.circom.template"
        ${CIRCOM_DIR}/{io_locations.sym,main.circom}
    )
    # Collect all .circom files under ${CIRCOM_DIR}
    while IFS= read -r -d '' file; do
        circuit_inputs+=("$file")
    done < <(find "${CIRCOM_DIR}" -type f -name '*.circom' -print0)

    if ! have_files_changed "${circuit_inputs[@]}"; then
        green "${NAME}: Using existing circuits"
        return 0
    fi

    green "${NAME}: Generating ${NAME}_main.circom... $(pwd)"

    local scripts=($(relative_path "${SCRIPTS_DIR}"))
    if [ "${CONFIG[credtype]}" == 'mdl' ]; then
        python3 "${scripts[0]}"/prepare_mdl_setup.py "${INPUTS_DIR}/config.json" "${CIRCOM_DIR}/main.circom"
    else
        python3 "${scripts[0]}"/prepare_setup.py "${INPUTS_DIR}/config.json" "${CIRCOM_DIR}/main.circom"
    fi

    pushd "$CIRCOM_DIR" > /dev/null
    log "=== ${NAME}: circom output start ==="
    circom main.circom --r1cs --wasm --O2 --sym --prime ${CURVE} | awk -v start=2 -v end=9 'NR>=start && NR<=end' >> "${LOG_FILE}"
    log "=== ${NAME}: circom output end ==="
    mv main.r1cs "${OUTPUTS_DIR}"/main_c.r1cs
    popd > /dev/null

    NUM_PUBLIC_INPUTS=$(grep -m 1 "public inputs:" "$LOG_FILE" | awk '{print $3}')
    NUM_PUBLIC_OUTPUTS=$(grep -m 1 "public outputs:" "$LOG_FILE" | awk '{print $3}')
    if [ "${CONFIG[credtype]}" == "mdl" ] && [ "${CONFIG[device_bound]}" == "1" ]; then
        log "Device bound mDL detected, adding device public key to public inputs"
        NUM_PUBLIC_INPUTS=$((NUM_PUBLIC_INPUTS + 2))
    fi
    NUM_PUBLIC_IOS=$((NUM_PUBLIC_INPUTS + NUM_PUBLIC_OUTPUTS))
    log "${NAME}: Number of public inputs: $NUM_PUBLIC_INPUTS"
    log "${NAME}: Number of public outputs: $NUM_PUBLIC_OUTPUTS"
    log "${NAME}: Total number of public I/Os: $NUM_PUBLIC_IOS"

    awk -v max="$NUM_PUBLIC_IOS" -F ',' '$2 != -1 && $2 <= max {split($4, parts, "."); printf "%s,%s\n", parts[2], $2}' "${CIRCOM_DIR}/main.sym" > "${CIRCOM_DIR}/io_locations.sym"

    checkpoint_files "${circuit_inputs[@]}"

}

###############################################################################
#   Generate mdl and prover inputs
#   Does nothing if cred type is not mdl
###############################################################################
generate_mdl() {
    if [ "${CONFIG[credtype]}" != 'mdl' ]; then
        return 0
    fi

    PROVER_INPUTS_FILE=${OUTPUTS_DIR}/prover_inputs.json
    PROVER_AUX_FILE=${OUTPUTS_DIR}/prover_aux.json

    # list of files to check for changes and trigger a new mdl generation, otherwise use existing mdl output
    local mdl_io=(
        ${INPUTS_DIR}/{mdl.cbor,claims.json,device.prv,issuer.prv,issuer_certs.pem}
        ${PROVER_INPUTS_FILE} ${PROVER_AUX_FILE}
    )
    local mdl_tools_src=( ${CIRCUIT_SETUP}/mdl-tools/src/bin/*.rs )
    local mdl_tools_bin=(${BIN}/{mdl-gen,prepare-prover-input})

    if ! have_files_changed "${mdl_io[@]}" "${mdl_tools_src[@]}"; then
        green "${NAME}: Using existing mDL and prover inputs"
        return 0
    fi

    log "=== Generating mDL ==="
    local mdl_file=${INPUTS_DIR}/mdl.cbor
    local claims_file=${INPUTS_DIR}/claims.json
    local device_priv_key_file=${INPUTS_DIR}/device.prv
    local issuer_priv_key_file=${INPUTS_DIR}/issuer.prv
    local issuer_certs_file=${INPUTS_DIR}/issuer_certs.pem

    if have_files_changed "${mdl_tools_bin[@]}" "${mdl_tools_src[@]}"; then
        echo "Building mdl-gen and prepare-prover-input..."
        cargo build -p mdl-tools $RELEASE_FLAG
        checkpoint_files "${mdl_tools_bin[@]}" "${mdl_tools_src[@]}"
    fi

    if ! "${BIN}"/mdl-gen --claims "${claims_file}" --device_priv_key "${device_priv_key_file}" --issuer_private_key "${issuer_priv_key_file}" --issuer_x5chain "${issuer_certs_file}" --output "${mdl_file}" 2>> "${LOG_FILE}"; then
        error "Error running mdl-gen"
    fi

    if ! "${BIN}"/prepare-prover-input --config "${CONFIG_FILE}" --mdl "${mdl_file}" --prover_inputs "${PROVER_INPUTS_FILE}" --prover_aux "${PROVER_AUX_FILE}" 2>> "${LOG_FILE}"; then
        error "Error running prepare_prover_input"
    fi

    node "${SCRIPTS_DIR}/precompEcdsa.mjs" "${OUTPUTS_DIR}/prover_inputs.json" > /dev/null 2>&1

    checkpoint_files "${mdl_io[@]}" "${mdl_tools_src[@]}"
}

###############################################################################
#   Copy all the required files to the destination directory
###############################################################################
copy_artifacts() {
    # Just do the copy every time, even if the files have not changed as its faster than checking if the files have changed
    echo "${NAME}: Copying files to $(relative_path "${COPY_DEST}")..."

    rm -rf "${COPY_DEST}"
    mkdir -p "${COPY_DEST}"
    cd "${COPY_DEST}"

    if [ "${CONFIG[credtype]}" == 'jwt' ]; then
        CRED_FILE="${INPUTS_DIR}/token.jwt"
    elif [ "${CONFIG[credtype]}" == 'mdl' ]; then
        CRED_FILE="${INPUTS_DIR}/mdl.cbor"
        cp "${PROVER_INPUTS_FILE}" "${PROVER_AUX_FILE}" .
    fi

    cp \
        "${CONFIG_FILE}" \
        "${OUTPUTS_DIR}/main_c.r1cs" \
        "${OUTPUTS_DIR}/circom/main_js/main.wasm" \
        "${OUTPUTS_DIR}/circom/io_locations.sym" \
        "${INPUTS_DIR}/issuer.pub" \
        "${INPUTS_DIR}/proof_spec.json" \
        "${CRED_FILE}" \
        .
    
    if [ "${CONFIG[device_bound]}" -eq 1 ]; then
        cp "${INPUTS_DIR}/device.pub" "${INPUTS_DIR}/device.prv" .
    fi

    cd "${CIRCUIT_SETUP}"
}

###############################################################################
#   Utility functions
###############################################################################

green() {
    echo -e "\033[0;32m$1\033[0m"
}

blue () {
    echo -e "\033[0;34m$1\033[0m"
}

log() {
    echo -e "\n$*" | tee -a "${LOG_FILE}"
}

assert_path() {
    for path in "$@"; do
        [ -e "$path" ] || error "Required path not found: $path"
    done
}

error() {
    local msg="$1"
    local code="${2:-1}"
    local script="$SCRIPT_NAME"
    local line_trace=""
    local n="${#BASH_LINENO[@]}"
    for (( i = 0; i < n - 1; i++ )); do
        [[ -n "$line_trace" ]] && line_trace+=":"
        line_trace+="${BASH_LINENO[$i]}"
    done
    echo -e "\n\033[41;97m Error (${script}:${line_trace}): \033[0m $msg\n" >&2
    exit 1
}

fix_symlink() {
    local link_path="$1"
    local target_path="$2"

    if [ -f "$link_path" ]; then
        echo "Detected broken symlink at $link_path"
        rm -f "$link_path"

        if [[ "$OS" == "Windows_NT" || "$(uname -o 2>/dev/null)" == "Msys" ]]; then
            echo "Creating Windows junction..."
            cmd //c "mklink /J $(cygpath -wa "$link_path") $(cygpath -wa "$target_path")"
        else
            echo "Creating Linux symlink..."
            ln -s "$target_path" "$link_path"
        fi

        # Mark the symlink as unchanged so it doesn't appear as modified in git
        # to undo: git update-index --no-assume-unchanged "$link_path"
        git update-index --assume-unchanged "$link_path"
    fi

    if [ ! -d "$link_path" ]; then
        error "Expected directory symlink/junction at: $link_path"
    fi
}

relative_path() {
    realpath --relative-to="$(pwd)" "$1"
}

json_get() {
    local -r json_file=$(relative_path "$1")
    [ -f "$json_file" ] || error "JSON file not found: $json_file"
    local key="$2"
    # Python converts booleans to title case (True/False), so we have to convert booleans back to lowercase
    python3 -c "import json;val = json.load(open('$json_file')).get('$key', '');print(str(val).lower() if isinstance(val, bool) else val)" 2>/dev/null
}

prune() {

    [ -z "$PRUNE" ] && return 0

    echo -e "\nPruning intermediate artifacts..."

    local before after saved

    before=$(du -s "${CIRCUIT_SETUP}" | awk '{print $1}')

    rm -rf "${OUTPUTS_DIR}"
    rm -rf "${INPUTS_DIR:?}"/!(*.json)

    if [[ ${CONFIG[credtype]} == "mdl" ]]; then
        cargo clean -p "mdl-tools"
        cargo clean -p "mdl-tools" --release
    fi

    after=$(du -s "${CIRCUIT_SETUP}" | awk '{print $1}')
    saved=$((before - after))

    echo "✂️ Reclaimed:       $((saved / 1024)) MB"
}

have_files_changed() {
    local files=("$@")

    # If any of the files are missing, consider them changed
    for f in "${files[@]}"; do
        [[ -f "$f" ]] || return 0
    done

    # Generate current hash file
    local -r current_hash_file=$(hash_files "${files[@]}")
    local saved_hash_file="${current_hash_file%.current}"

    # Compare hash files
    if [[ ! -f "$saved_hash_file" ]] || ! cmp -s "$current_hash_file" "$saved_hash_file"; then
        return 0 # Files have changed
    else
        rm "$current_hash_file"
        return 1 # Files have not changed
    fi
}

hash_files() {
    local files=("$@")
    local rel_files=()
    for file in "${files[@]}"; do
        if [[ ! -e "$file" ]]; then
            error "File not found: $file"
        fi
        rel_files+=("$(realpath --relative-to=. "$file")")
    done
    # Generate hash ID from sorted file paths
    local -r hash_id=$(printf "%s\n" "${rel_files[@]}" | sort -u | sha256sum | awk '{print substr($1,1,12)}')
    local hash_file="${OUTPUTS_DIR}/${hash_id}.sha256.current"
    sha256sum "${rel_files[@]}" | sort -u > "$hash_file"
    echo "$hash_file"
}

checkpoint_files() {
    local files=("$@")
    local current
    current=$(hash_files "${files[@]}")
    mv "$current" "${current%.current}" # Rename to remove .current suffix
}

expand_files() {
    shopt -s globstar nullglob
    local inputs=("$@")
    local files_set=()
    for item in "${inputs[@]}"; do
        for match in $item; do
            if [[ -f "$match" ]]; then
                rel_path=$(realpath --relative-to=. "$match")
                files_set+=("$rel_path")
            fi
        done
    done
    printf "%s\n" "${files_set[@]}" | sort -u
}



SECONDS=0
main "$@"
green "\n✅ Done: $SCRIPT_NAME $NAME in ${SECONDS}s"
