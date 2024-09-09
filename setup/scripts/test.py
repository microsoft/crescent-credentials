#!/usr/bin/python3

import sys, os
import json

from crescent_helper import *

s = "Example claim value 1"

s_int = pack_string_to_int(s, 31)

s_str = unpack_int_to_string(s_int, 31)

print("s_input = {}\ns_output= {}".format(s, s_str))


