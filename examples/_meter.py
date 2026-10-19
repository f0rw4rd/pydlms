"""Shared setup for the examples: a real meter from the environment, else the simulator.

Without ``DLMS_HOST`` every example starts the in-process example meter
(``pydlms.simulator``), so it runs as is. Set ``DLMS_HOST`` only for a meter
you own or are authorised to read.
"""

import os

from pydlms import DlmsClient
from pydlms.simulator import MeterSimulator, example_meter, serve

HOST = os.environ.get("DLMS_HOST")
PORT = int(os.environ.get("DLMS_PORT", "4059"))
HDLC = os.environ.get("DLMS_HDLC", "0") == "1"
CLIENT_SAP = int(os.environ.get("DLMS_CLIENT", "16"))


def start_simulator(meter: MeterSimulator | None = None, hdlc: bool = HDLC) -> tuple[str, int]:
    """Serve ``meter`` (default: the example meter) on a free local port."""
    server = serve(meter or example_meter(), hdlc=hdlc)
    host, port = server.server_address[:2]
    print(f"(DLMS_HOST not set: built-in simulator on {host}:{port})\n")
    return host, port


def connect(meter: MeterSimulator | None = None, **kw) -> DlmsClient:
    """A client for ``DLMS_HOST``, or for the simulator serving ``meter``."""
    kw.setdefault("client_sap", CLIENT_SAP)
    if HOST:
        return DlmsClient.tcp(HOST, PORT, hdlc=HDLC, **kw)
    host, port = start_simulator(meter)
    return DlmsClient.tcp(host, port, hdlc=HDLC, **kw)
