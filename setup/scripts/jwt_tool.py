#!/usr/bin/python3

import sys, os, json
import argparse
import python_jwt as jwt
from jwcrypto.jws import JWS
from jwcrypto.common import base64url_encode

INFILE_ARG = "infile"
OUTFILE_ARG = "outfile"
JSON_INFILE_ARG = "json_infile"

DUMP_CMD = "dump" # dumps like a truck



HEADER = 0
CLAIMS = 1

def load_jwt(jwtfile):
    return jwtfile.read()

def load_json(jsonfile):
    return json.loads(jsonfile.read())

def dump_token(jwt_json_token):
    print(json.dumps(jwt_json_token,indent=4))

def format_unsecured_jwt(claims):
    header = {"typ":"JWT", "alg":"none"}
    header_str = json.dumps(header, separators=(',', ':')).encode('utf-8')
    claims_str = json.dumps(claims, separators=(',', ':')).encode('utf-8')
    signature_str = ""

    h = base64url_encode(header_str)
    c = base64url_encode(claims_str)
    s = base64url_encode(signature_str)

    new_jwt = "{}.{}.{}".format(h, c, s)

    return new_jwt

parser = argparse.ArgumentParser(   
            prog=os.path.basename(sys.argv[0]),
            description="Tool to load and manipulate JSON Web Tokens (JWTs).")
parser.add_argument("-i","--input", dest=INFILE_ARG, nargs=1, required=False, metavar="input_file", type=argparse.FileType("r"),
                    help="The input jwt file.")
parser.add_argument("-j","--json",dest=JSON_INFILE_ARG, nargs=1, required=False,metavar="json_input_file", type=argparse.FileType("r"),
                    help="The input json file.")
parser.add_argument("-d", "--dump", action='append_const', dest="commands", const=DUMP_CMD,
                    help="Dump the json of the current jwt.")
parser.add_argument("-o", "--output", dest=OUTFILE_ARG, nargs="?", metavar="output_file",
                    const=sys.stdout, type=argparse.FileType("w"),
                    help="Output to an Unsecured JWT, to stdout or supplied file.")

args = parser.parse_args()

args_dict = vars(args)
cmds = args.commands

input_jwt = None
input_json = None

if (None == args_dict[INFILE_ARG]) and (None == args_dict[JSON_INFILE_ARG]):
    #make print_debug
    print("No jwt or json input file specified.")
    parser.print_usage()
elif (None != args_dict[INFILE_ARG]) and (None != args_dict[JSON_INFILE_ARG]):
    print("May not specify both jwt and json input files.")
    parser.print_usage()
elif (None != args_dict[INFILE_ARG]):
    # TODO: Make input optional in which case the token will be read from STDIN
    input_jwt = load_jwt(args_dict[INFILE_ARG][0])
    jwt_json_token = jwt.process_jwt(input_jwt)
else: # elif (None != args_dict[JSON_INFILE_ARG])
    input_json = load_json(args_dict[JSON_INFILE_ARG][0])
    jwt_json_token = ({},input_json)

if None != cmds:
    for c in cmds:
        if (DUMP_CMD == c):
            dump_token(jwt_json_token)

outfile = vars(args)[OUTFILE_ARG]

if (None != outfile):
    output_jwt = format_unsecured_jwt(jwt_json_token[CLAIMS])
    outfile.write(output_jwt)
    outfile.flush()
