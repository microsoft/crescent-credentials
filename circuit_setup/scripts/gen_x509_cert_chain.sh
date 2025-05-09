# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

#!/bin/bash
# This script generates 3-cert ECDSA chains (root -> CA -> issuer).
# The leaf cert uses P-256 and is valid for 1 year, the CA and root CA use
# the increasingly stronger P-384 and P-521, and are valid for
# 5 and 10 years, respectively.

# directory where intermediate files are kept
tmpdir=../generated_files/mdl1
outdir=../inputs/mdl1
mkdir -p "$tmpdir"

# prevent gitbash path expansion
export MSYS_NO_PATHCONV=1

# generate self-signed root CA cert
openssl ecparam -name secp521r1 -out tmpkey.pem
openssl req -x509 -new -newkey ec:tmpkey.pem -keyout "$tmpdir/root_CA.key" -out "$tmpdir/root_CA.crt" -nodes -subj "/CN=NY DMV Test Root CA" -days 3650 -config openssl_ca.cnf -extensions v3_ca -sha512
rm tmpkey.pem

# generate intermediate CA cert request
openssl ecparam -name secp384r1 -out tmpkey.pem
openssl req -new -newkey ec:tmpkey.pem  -keyout "$tmpdir/CA.key" -out "$tmpdir/CA.csr" -nodes -subj "/CN=NY DMV Test CA" -config openssl_ca.cnf -sha384
rm tmpkey.pem

# root CA signs the CA cert request
openssl x509 -req -in "$tmpdir/CA.csr" -out "$tmpdir/CA.crt" -CA "$tmpdir/root_CA.crt" -CAkey "$tmpdir/root_CA.key" -CAcreateserial -days 1825 -extfile openssl_ca.cnf -extensions v3_ca -sha512

# generate signer cert request
openssl ecparam -name prime256v1 -out tmpkey.pem
openssl req -new -newkey ec:tmpkey.pem  -keyout "$tmpdir/issuer.key" -out "$tmpdir/issuer.csr" -nodes -subj "/CN=NY DMV Test Issuer" -config openssl_ca.cnf -sha256
rm tmpkey.pem

# intermediate CA signs the issuer cert request
openssl x509 -req -in "$tmpdir/issuer.csr" -out "$tmpdir/issuer.crt" -CA "$tmpdir/CA.crt" -CAkey "$tmpdir/CA.key" -CAcreateserial -days 365 -extfile openssl_ca.cnf -extensions v3_signer -sha384

# copy the issuer key to the output directory
cp "$tmpdir/issuer.key" "$outdir/issuer.priv"
echo "Generated issuer private key: $outdir/issuer.priv"

# extract the public key from the issuer cert
openssl x509 -in "$tmpdir/issuer.crt" -pubkey -noout > "$outdir/issuer.pub"

# create a X509 chain file in the output directory
cat "$tmpdir/issuer.crt" "$tmpdir/CA.crt" "$tmpdir/root_CA.crt" > "$outdir/issuer_certs.pem"
echo "Generated issuer cert chain: $outdir/issuer_certs.pem"
