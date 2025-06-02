# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

#!/bin/bash
# This script generates 3-cert ECDSA chains (root -> CA -> issuer).
# The leaf cert uses P-256 and is valid for 1 year, the CA and root CA use
# the increasingly stronger P-384 and P-521, and are valid for
# 5 and 10 years, respectively.

# prevent gitbash from auto-converting paths to windows syntax
export MSYS_NO_PATHCONV=1

# directory where intermediate files are kept
tmpdir=../generated_files/mdl1
# force relative paths that will work with openssl on both linux and windows.
scriptsdir=$(realpath --relative-to=$tmpdir $(pwd)) 
outdir=$(realpath --relative-to=$tmpdir ../inputs/mdl1) 
mkdir -p "$tmpdir"
cd "$tmpdir" || exit 1


# generate self-signed root CA cert
rm -f ecparamp521
openssl ecparam -name secp521r1 -out ecparamp521
openssl req -x509 -new -newkey ec:ecparamp521 -keyout root_CA.key -out root_CA.crt -nodes -subj "/CN=NY DMV Test Root CA" -days 3650 -config "$scriptsdir/openssl_ca.cnf" -extensions v3_ca -sha512

# generate intermediate CA cert request
rm -f ecparamp384
openssl ecparam -name secp384r1 -out ecparamp384
openssl req -new -newkey ec:ecparamp384  -keyout CA.key -out CA.csr -nodes -subj "/CN=NY DMV Test CA" -config "$scriptsdir/openssl_ca.cnf" -sha384

# root CA signs the CA cert request
openssl x509 -req -in CA.csr -out CA.crt -CA root_CA.crt -CAkey root_CA.key -CAcreateserial -days 1825 -extfile "$scriptsdir/openssl_ca.cnf" -extensions v3_ca -sha512

# generate signer cert request
rm -f ecparamp256
openssl ecparam -name prime256v1 -out ecparamp256
openssl req -new -newkey ec:ecparamp256  -keyout issuer.key -out issuer.csr -nodes -subj "/CN=NY DMV Test Issuer" -config "$scriptsdir/openssl_ca.cnf" -sha256

# intermediate CA signs the issuer cert request
openssl x509 -req -in issuer.csr -out issuer.crt -CA CA.crt -CAkey CA.key -CAcreateserial -days 365 -extfile "$scriptsdir/openssl_ca.cnf" -extensions v3_signer -sha384

# copy the issuer key to the output directory
cp issuer.key "$outdir/issuer.prv"
echo "Generated issuer private key: $outdir/issuer.prv"

# extract the public key from the issuer cert
openssl x509 -in issuer.crt -pubkey -noout > "$outdir/issuer.pub"

# create a X509 chain file in the output directory
cat issuer.crt CA.crt root_CA.crt > "$outdir/issuer_certs.pem"
echo "Generated issuer cert chain: $outdir/issuer_certs.pem"
