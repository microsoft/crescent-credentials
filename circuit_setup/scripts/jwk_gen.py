# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

#!/usr/bin/python3

# Depends on python-jwt:
#   pip install python_jwt
# https://pypi.org/project/python-jwt/

# The registry of supported algorithms in JWS is found here:
#    https://www.iana.org/assignments/jose/jose.xhtml
# JWT: https://www.rfc-editor.org/rfc/rfc7519
# JWS: https://www.rfc-editor.org/rfc/rfc7515
# python JWT docs: https://jwcrypto.readthedocs.io
# python JWT Source: https://github.com/latchset/jwcrypto

# Keys can be inspected from the command line with OpenSSL
# Inspect private key with: 
#   openssl pkey -in test.prv -text -noout
# Inspect public EC key with 
#   openssl ec -inform PEM -text -noout -in test.pub -pubin
# Inspect public RSA key with
#   openssl rsa -inform PEM -text -noout -in test.pub -pubin

import python_jwt as jwt, jwcrypto.jwk as jwk, datetime
import sys, os

def usage():
    print("Python3 script to generate a JWK (JSON web key)")
    print("Usage:")
    print("\t./" + os.path.basename(sys.argv[0]) + " <alg: ES256, ES256K, RS256> <private key file> <public key file>")
    print("Example:")
    print("\tpython3 " + os.path.basename(sys.argv[0]) + "RS256 key.prv key.pub")
    print("creates an RSA key pair output to files key.prv and key.pub (overwriting these files if they already exist)")
    print("Keys are stored in PEM format")
    print("Algorithms:")
    print("RS256 - RSA signing key, 2048-bit")
    print("ES256 - ECDSA key with curve NIST P256 (secp256r1)")
    print("ES256K - ECDSA key with curve secp256k1 (bitcoin)")



### Main ###

if len(sys.argv) != 4 : 
    usage()
    sys.exit(-1)

algs = ('RS256', 'ES256K', 'ES256')
alg = sys.argv[1]
if alg not in algs:
    print("Algorithm '{}' is not supported\n".format(alg))
    usage()
    sys.exit(-1)


# Create key pair
key = None
if alg == "RS256":
    key = jwk.JWK.generate(kty='RSA', size=2048)
elif alg == "ES256":
    key = jwk.JWK.generate(kty='EC', crv="P-256")
elif alg == "ES256K":
    key = jwk.JWK.generate(kty='EC', crv="secp256k1")
else:
    raise ValueError('Invalid algorithm.')


# Save to file
priv_pem = key.export_to_pem(private_key=True, password=None)
pub_pem = key.export_to_pem()

with open(sys.argv[2], "wb") as f:
    f.write(priv_pem)
    
with open(sys.argv[3], "wb") as f:
    f.write(pub_pem)    






