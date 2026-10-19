#!/usr/bin/env python3
"""Trace a session: hexdumps of every frame and APDU on stderr.

DLMS_LAYERS limits the output to some layers, e.g. ``DLMS_LAYERS=hdlc,security``.
Keys, passwords and HLS challenges are redacted from the log.
"""

import os

from _meter import connect

from pydlms import enable_debug

layers = os.environ.get("DLMS_LAYERS")
enable_debug("TRACE", layers=layers.split(",") if layers else None)

with connect() as meter:
    print(meter.get_register("1.0.1.8.0.255"))
