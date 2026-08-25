#!/usr/bin/bash
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
#

# usage: clean-sample.sh [--data-and-build]

set -e

cd "$(dirname "${BASH_SOURCE[0]}")"

DATA_AND_BUILD=false
if [ "$1" == "--data-and-build" ]; then
    DATA_AND_BUILD=true
fi

rm -fr ./client/dist ./client/mdl.json
if ($DATA_AND_BUILD); then
    ( cd ./client && npm run clean -p crescent-sample-client-helper )
fi
echo "Cleaned client project"

rm -fr ./client_helper/data ./client_helper/bin
if ($DATA_AND_BUILD); then
    ( cd ./client_helper && cargo clean )
fi
echo "Cleaned client_helper project"

rm -fr ./issuer/data ./issuer/keys ./issuer/.well-known ./issuer/bin
if ($DATA_AND_BUILD); then
    ( cd ./issuer && cargo clean )
fi
echo "Cleaned issuer project"

rm -fr ./verifier/data ./verifier/bin
if ($DATA_AND_BUILD); then
    ( cd ./verifier && cargo clean )
fi
echo "Cleaned verifier project"

rm -fr ./setup_service/bin
if ($DATA_AND_BUILD); then
    ( cd ./setup_service && cargo clean )
fi
echo "Cleaned setup_service project"
