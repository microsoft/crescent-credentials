#!/bin/bash

# call the key generation script
../common/generate-keys.sh

# call the JWKS generation script
node scripts/generate-jwks.js
