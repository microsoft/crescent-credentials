#!/bin/bash

# call the key generation script
../common/generate-keys.sh

# call the JWKS generation script
node scripts/generate-jwks.js

# call the Rocket config update script
node scripts/update-rocket-toml.js
