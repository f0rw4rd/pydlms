#!/usr/bin/env python3
"""Decode an encrypted push from a customer interface (M-Bus, Netz NÖ profile).

Usage: 06_decode_push.py [CAPTURE_HEX_FILE KEY_HEX]

Without arguments it decodes a real Netz NÖ capture from the esphome-libs/
dlms_parser test dumps (Apache-2.0, vendored under tests/fixtures). With
DLMS_SERIAL set it reads pushes from that port instead (needs pyserial).
"""

import os
import sys
from pathlib import Path

from pydlms import PushDecoder, SecurityContext
from pydlms.profiles import get_profile
from pydlms.security.suites import SecurityPolicy

DUMPS = Path(__file__).resolve().parent.parent / "tests/fixtures/dlms_parser/dumps"

if len(sys.argv) == 3:
    capture, key_hex = Path(sys.argv[1]), sys.argv[2]
else:
    capture = DUMPS / "mbus_netz_noe_p1.log"
    key_hex = (DUMPS / "mbus_netz_noe_p1.key").read_text()
key = bytes.fromhex(key_hex.strip())

# Netz NÖ pushes are encrypted only (SC 0x20): say so, or they are refused.
security = SecurityContext(key, policy=SecurityPolicy.ENCRYPTED)
decoder = PushDecoder("mbus", security, profile=get_profile("netz-noe-p1"))


def show(message) -> None:
    print(f"push from {message.system_title.hex()} at {message.timestamp}")
    for record in message.records:
        value = message.get(record.obis)  # scaler applied, date-times decoded
        unit = f" {record.unit.name.lower()}" if record.unit is not None else ""
        print(f"  {str(record.obis):16} {value!s:>30}{unit}")


if port := os.environ.get("DLMS_SERIAL"):
    import serial

    with serial.Serial(port, 2400, parity=serial.PARITY_EVEN, timeout=1) as line:
        while True:
            for message in decoder.feed(line.read(512)):
                show(message)
else:
    # The dump is hex text; "-" joins continuation lines.
    raw = bytes.fromhex("".join(capture.read_text().replace("-", "").split()))
    for message in decoder.feed(raw):
        show(message)
