#!/bin/bash

# TODO: we currently do not need this script anymore; delete if it's still the case

# Default values
JWT_PATH=""
PARAMS_UID=""

# Parse optional parameters
while getopts "j:p:" opt; do
  case $opt in
    j) JWT_PATH=$OPTARG ;;
    p) PARAMS_UID=$OPTARG ;;
    \?) echo "Invalid option -$OPTARG" >&2; exit 1 ;;
  esac
done

echo "setting up Crescent Setup Service"

# If JWT_PATH is not provided, call generate-dummy-jwt.sh and set JWT_PATH
if [ -z "$JWT_PATH" ]; then
  ./generate-dummy-jwt.sh
  JWT_PATH="dummy.jwt"
fi

# If PARAMS_UID is not provided, generate a unique UID
if [ -z "$PARAMS_UID" ]; then
  PARAMS_UID=$(uuidgen)
fi

# Call the function with the parameters
echo $PARAMS_UID
echo $JWT_PATH
(cd ../../creds && cargo run --bin crescent --release --features print-trace zksetup --name ../../sample/setup_service/data/rs256)
