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
    print("Python3 script to replace the signature on a JWT with another signature")
    print("Usage:")
    print("\t./" + os.path.basename(sys.argv[0]) + " <existing JWT> <new issuer private key> <new JWT>")
    print("Example:")
    print("\tpython3 " + os.path.basename(sys.argv[0]) + "token.jwt issuer.prv new_token.jwt")
    print("will remove the signature on token.jwt and re-sign the payload with issuer.prv, writing the output to new_token.jwt")
    print("To change the claims in the token, look at the source code of this script.")

### Main ###

if len(sys.argv) != 4 : 
    usage()
    sys.exit(-1)

# Load new issuer key
with open(sys.argv[2], "rb") as f:
    issuer_key_bytes = f.read()

issuer_key = jwk.JWK.from_pem(issuer_key_bytes, password=None)

new_alg = None
if issuer_key.get('kty') == "RSA" :
    print("Read new issuer key type: RSA")
    new_alg = "RS256"
elif issuer_key.get('kty') == "EC":
    print("Read new issuer key type: EC", end='')
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

# Read token
with open(sys.argv[1], "r") as f:
    token = f.read()

h_b64, c_b64, s_b64 = token.split(".")
header, claims = jwt.process_jwt(token)
#print("Header: {}\nClaims: {}".format(header, claims))
short_kid = issuer_key.get('kid')
old_claims = claims

# Add or make changes to claims here, e.g., 
#claims['padding'] = "a"*3500

# Make a set of 10 dummy claims
claims = {}
for i in range(1,11):
    k = "claim{:02d}".format(i)
    v = "Sample claim value {}".format(i)
    claims[k] = v

# load the claims from a file
# with open('eg-claims.json', 'r') as file:
#     claims = json.load(file)


# Create the new token with the modified claims, and one year lifetime
new_jwt = jwt.generate_jwt(claims, issuer_key, new_alg, datetime.timedelta(weeks=52), other_headers={'kid': short_kid})

print("New JWT: " + new_jwt)
new_token_header, new_token_claims = jwt.process_jwt(new_jwt)
print("old header:")
print(str(header))
print("new header:")
print(str(new_token_header))
if str(old_claims) == str(new_token_claims):
    print("new claims and old claims are identical:")
    print(json.dumps(str(new_token_claims), indent=4))
else:
    print("old claims:")
    print(str(old_claims))
    print("new claims:")
    print(str(new_token_claims))

print("Verifying... ", end="")
try:
    jwt.verify_jwt(new_jwt, issuer_key.public(), allowed_algs=['RS256', 'ES256', 'ES256K'])
    print("  success")
except jwt._JWTError as e:
    if str(e) == 'expired':
        print("Token signature is valid, but token is expired")
    else:
        print("WARNING: Token is invalid, caught JWTError: " + str(e))
        # We don't fail here since some reasons for verify_jwt to fail don't apply to VCs, 
        # E.g., failing because the "nbf" claim is not present

#write token to file
with open(sys.argv[3], "w") as f:
    token = f.write(new_jwt)
print("New token written to {}".format(sys.argv[3]))
