#!/bin/bash

# usage: clean-sample.sh [--data-and-build]

DATA_AND_BUILD=false
if [ "$1" == "--data-and-build" ]; then
    DATA_AND_BUILD=true
fi

# clean client_helper project
rm -fr ./client_helper/data
if ($DATA_AND_BUILD); then
    cargo clean
fi
echo "Cleaned client_helper project"

# clean issuer project
rm -fr ./issuer/data
if ($DATA_AND_BUILD); then
    cargo clean
fi
echo "Cleaned issuer project"

# clean verifier project
rm -fr ./verifier/data
if ($DATA_AND_BUILD); then
    cargo clean
fi
echo "Cleaned verifier project"