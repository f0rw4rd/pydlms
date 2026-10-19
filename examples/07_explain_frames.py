#!/usr/bin/env python3
"""Explain raw bytes layer by layer: framing, ciphering, APDU and COSEM data.

Usage: 07_explain_frames.py [HEX [ENCRYPTION_KEY_HEX]]

The same output as ``pydlms decode``. The default input is the Green Book
AARQ for the public client (LN referencing, no security) and a GET request for
the clock, each in a TCP wrapper frame from client SAP 16 to logical device 1.
"""

import sys

from pydlms import explain
from pydlms.wrapper import encode_wrapper

AARQ = bytes.fromhex("601DA109060760857405080101BE10040E01000000065F1F0400007E1F04B0")
GET_CLOCK = bytes.fromhex("C0010000080000010000FF0200")

if len(sys.argv) > 1:
    data = [bytes.fromhex(sys.argv[1])]
else:
    data = [encode_wrapper(16, 1, AARQ), encode_wrapper(16, 1, GET_CLOCK)]
key = bytes.fromhex(sys.argv[2]) if len(sys.argv) > 2 else None
print(explain(data, encryption_key=key))
