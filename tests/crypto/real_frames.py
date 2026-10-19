"""Helpers that extract the ciphered APDU of real captures for crypto tests.

These deliberately use only the framing layers (HDLC, GBT, M-Bus), so the
crypto tests exercise real bytes without depending on the push decoder.
"""

from __future__ import annotations

from dataclasses import dataclass

from pydlms.apdu.gbt import GbtReassembler, decode_gbt
from pydlms.hdlc.framing import FrameReader, strip_llc
from pydlms.mbus import MbusReader
from tests.meter_fixtures import load


@dataclass
class CipheredCapture:
    apdu: bytes
    system_title: bytes
    encryption_key: bytes
    authentication_key: bytes | None


def hdlc_apdu(raw: bytes) -> bytes:
    frames = FrameReader(strict=True).feed(raw)
    infos = [strip_llc(f.info) if i == 0 else f.info for i, f in enumerate(frames)]
    if infos[0][:1] == b"\xe0":
        gbt = GbtReassembler()
        apdu = None
        for info in infos:
            apdu = gbt.add(decode_gbt(info)) or apdu
        assert apdu is not None
        return apdu
    return b"".join(infos)


def _capture(name: str) -> CipheredCapture:
    fx = load(name)
    if fx.transport == "mbus":
        apdu = MbusReader().feed(fx.raw)[0]
    else:
        apdu = hdlc_apdu(fx.raw)
    assert apdu[0] == 0xDB
    assert fx.encryption_key is not None
    return CipheredCapture(apdu, apdu[2:10], fx.encryption_key, fx.authentication_key)


def e450_ciphered_apdu() -> CipheredCapture:
    return _capture("hdlc_landis_gyr_e450")


def capture(name: str) -> CipheredCapture:
    return _capture(name)
