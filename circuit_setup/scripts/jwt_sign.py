# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

#!/usr/bin/python3

# pip install python_jwt
# https://pypi.org/project/python-jwt/


# The registry of supported algorithms in JWS is found here:
#    https://www.iana.org/assignments/jose/jose.xhtml
# JWT: https://www.rfc-editor.org/rfc/rfc7519
# JWS: https://www.rfc-editor.org/rfc/rfc7515
# python JWT docs: https://jwcrypto.readthedocs.io
# python JWT Source: https://github.com/latchset/jwcrypto

import python_jwt as jwt, jwcrypto.jwk as jwk
from jwcrypto.common import base64url_decode, base64url_encode
from jwcrypto.jws import JWS
import sys, os, json, datetime

def usage():
    print("Python3 script to create a JWT")
    print("Usage:")
    print("\t./" + os.path.basename(sys.argv[0]) + " <claims.file.json> <issuer private key> <output JWT> <optional device public key>")
    print("Example:")
    print("\tpython3 " + os.path.basename(sys.argv[0]) + "claims.json issuer.prv token.jwt")
    print("will sign the json in claims.json with the issuer private key in issuer.prv and output the JWT in token.jwt")
    print("If a device public key is provided, it will be added to the claims.")

### Main ###

if len(sys.argv) != 4 and len(sys.argv) != 5 : 
    usage()
    sys.exit(-1)

# Load issuer key
with open(sys.argv[2], "rb") as f:
    issuer_key_bytes = f.read()

issuer_key = jwk.JWK.from_pem(issuer_key_bytes, password=None)

new_alg = None
if issuer_key.get('kty') == "RSA" :
    print("Read issuer key type: RSA")
    new_alg = "RS256"
elif issuer_key.get('kty') == "EC":
    print("Read issuer key type: EC", end='')
    if issuer_key.get('crv') == "P-256":
        print(" with curve P-256")
        new_alg = "ES256"
    elif issuer_key.get('crv') == "secp256k1":
        print(" with curve secp256k1")
        new_alg = "ES256K"
    else:
        raise ValueError("Unsupported curve")
else:
    raise ValueError("Unsupported key type")

print("Using signature algorithm {} for new token\n".format(new_alg))

# load the claims from a file
with open(sys.argv[1], 'r') as file:
    claims = json.load(file)

# If a device public key was provided, add it to the claims, in the format expected by 
# Crescent.  This is currently a custom format, but ideally would be a 'cnf' claim
# https://datatracker.ietf.org/doc/html/rfc7800#section-3.2
if sys.argv[4] is not None: 
    print("Adding device public key to claims")
    with open(sys.argv[4], "rb") as f:
        device_key_bytes = f.read()

    device_key = jwk.JWK.from_pem(device_key_bytes, password=None)    
    if device_key.get('kty') != "EC" or device_key.get('crv') != "P-256":
        print("device_key kty: {}".format(device_key.get('kty')))
        print("device_key crv: {}".format(device_key.get('crv')))
        print("Error: device key must be of type EC on curve P-256")
        sys.exit(-1)

    pk_x = device_key.get('x')
    pk_x_int = int.from_bytes(base64url_decode(pk_x), byteorder='big')
    device_key_0 = pk_x_int & ((1 << 128) - 1)
    device_key_1 = pk_x_int >> 128
    assert( device_key_0 + (1 << 128) * device_key_1 == pk_x_int)
    claims['device_key_0'] = device_key_0
    claims['device_key_1'] = device_key_1

# Create the new token with the claims, and one year lifetime
short_kid = issuer_key.get('kid')
new_jwt = jwt.generate_jwt(claims, issuer_key, new_alg, datetime.timedelta(weeks=52), other_headers={'kid': short_kid})

#print("New JWT: " + new_jwt)
new_token_header, new_token_claims = jwt.process_jwt(new_jwt)
#print("new header:")
#print(str(new_token_header))

print("Verifying... ", end="")
try:
    jwt.verify_jwt(new_jwt, issuer_key.public(), allowed_algs=['RS256', 'ES256', 'ES256K'])
    print("  success")
except jwt._JWTError as e:
    if str(e) == 'expired':
        print("Token signature is valid, but token is expired")
    else:
        print("WARNING: Token is invalid, caught JWTError: " + str(e))
        # We don't fail here since some reasons for verify_jwt to fail don't apply to W3C VCs, 
        # E.g., failing because the "nbf" claim is not present

with open(sys.argv[3], "w") as f:
    token = f.write(new_jwt)
print("New token written to {}".format(sys.argv[3]))
