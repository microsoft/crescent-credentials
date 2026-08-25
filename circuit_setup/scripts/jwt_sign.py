#!/usr/bin/python3
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
#

# The registry of supported algorithms in JWS is found here:
#    https://www.iana.org/assignments/jose/jose.xhtml
# JWT: https://www.rfc-editor.org/rfc/rfc7519
# JWS: https://www.rfc-editor.org/rfc/rfc7515

import sys, os, json, datetime, time
from jwcrypto import jwt, jwk
from jwcrypto.common import base64url_decode
import time

def usage():
    print("Python3 script to create a JWT")
    print("Usage:")
    print(f"\t{os.path.basename(sys.argv[0])} <claims.file.json> <issuer private key> <output JWT> <optional device public key>")
    print("Example:")
    print(f"\tpython3 {os.path.basename(sys.argv[0])} claims.json issuer.prv token.jwt")
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

print(f"Using signature algorithm {new_alg} for new token\n")

# load the claims from a file
with open(sys.argv[1], 'r') as file:
    claims = json.load(file)

# If a device public key was provided, add it to the claims, in the format expected by 
# Crescent.  This is currently a custom format, but ideally would be a 'cnf' claim
# https://datatracker.ietf.org/doc/html/rfc7800#section-3.2
if len(sys.argv) > 4 and sys.argv[4] is not None: 
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

# Add expiration (1 year from now)
now = datetime.datetime.now(datetime.UTC)
claims['iat'] = int(now.timestamp())
claims['exp'] = int((now + datetime.timedelta(weeks=52)).timestamp())
claims['nbf'] = int(now.timestamp())

# Create the new token with the claims, and one year lifetime
short_kid = issuer_key.get('kid')
jwt_token = jwt.JWT(header={"alg": new_alg, "kid": short_kid, "typ": "JWT"}, claims=claims)
jwt_token.make_signed_token(issuer_key)
new_jwt = jwt_token.serialize()


print("Verifying... ", end="")
try:
    verified_token = jwt.JWT(jwt=new_jwt, key=issuer_key.public(), algs=['RS256', 'ES256', 'ES256K'])
    verified_token.validate(issuer_key.public())
    claims = json.loads(verified_token.claims)
    if int(time.time()) >= claims.get('exp'):
        print("Token signature is valid, but token is expired")

    print("  success")
except Exception as e:
    print("WARNING: Token is invalid, caught error: " + str(e))

with open(sys.argv[3], "w") as f:
    f.write(new_jwt)

print(f"New token written to {sys.argv[3]}")
