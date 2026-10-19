#!/usr/bin/env python3
"""Secured association: HLS-GMAC (mechanism 5), suite 0, ciphered APDUs (glo-).

Keys come from DLMS_EK / DLMS_AK (hex). The defaults are the Green Book example
keys, which the simulator is started with; a real meter has its own.
"""

import os

from _meter import HOST, connect

from pydlms import Mechanism, SecurityContext
from pydlms.simulator import ClientProfile, example_meter

EK = bytes.fromhex(os.environ.get("DLMS_EK", "000102030405060708090A0B0C0D0E0F"))
AK = bytes.fromhex(os.environ.get("DLMS_AK", "D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF"))
CLIENT_SAP = int(os.environ.get("DLMS_CLIENT", "1"))

simulator = None
if not HOST:
    simulator = example_meter(encryption_key=EK, authentication_key=AK)
    simulator.clients[CLIENT_SAP] = ClientProfile(Mechanism.HLS_GMAC, ciphered=True)

security = SecurityContext(
    encryption_key=EK,
    authentication_key=AK,
    client_system_title=b"PYDLMS01",
    invocation_counter=1,  # continue from the meter's last counter on a real meter
)

with connect(
    simulator, client_sap=CLIENT_SAP, mechanism=Mechanism.HLS_GMAC, security=security
) as meter:
    print(f"server system title: {meter.association.server_system_title.hex()}")
    print(f"active energy:       {meter.get_register('1.0.1.8.0.255')}")
    print(f"next invocation ctr: {security.invocation_counter}")
