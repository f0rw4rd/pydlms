#!/usr/bin/env python3
"""HDLC over a serial line (needs pyserial: ``pip install "pydlms-client[serial]"``).

DLMS_SERIAL is a device or any pyserial URL (``/dev/ttyUSB0``,
``rfc2217://host:port``, ``socket://host:port``); DLMS_BAUD defaults to 9600.
Without DLMS_SERIAL the simulator serves HDLC over TCP and the example reaches
it through pyserial's ``socket://`` URL, so the serial code path still runs.
For an optical probe use ``DlmsClient.optical`` (IEC 62056-21 mode E).
"""

import os

from _meter import start_simulator

from pydlms import DlmsClient

port = os.environ.get("DLMS_SERIAL")
if not port:
    host, tcp_port = start_simulator(hdlc=True)
    port = f"socket://{host}:{tcp_port}"
baud = int(os.environ.get("DLMS_BAUD", "9600"))

with DlmsClient.serial(port, baud, client_sap=16) as meter:
    print(f"meter serial number: {meter.get('0.0.96.1.0.255').value}")
    print(f"active energy:       {meter.get_register('1.0.1.8.0.255')}")
