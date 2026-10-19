"""DSMR P1 telegram parsing (profiles/dsmr.py)."""

from __future__ import annotations

import datetime as dt

import pytest

from pydlms.exceptions import ChecksumError, DecodeError
from pydlms.profiles.dsmr import crc16_arc, decrypt_frame, parse_telegram

BODY = (
    "/ISK5\\2M550T-1012\r\n"
    "\r\n"
    "1-3:0.2.8(50)\r\n"
    "0-0:1.0.0(190101120000W)\r\n"
    "0-0:96.1.1(4530303334303036333632353636363237)\r\n"
    "1-0:1.8.1(001234.567*kWh)\r\n"
    "1-0:1.8.2(000765.432*kWh)\r\n"
    "1-0:1.7.0(00.512*kW)\r\n"
    "1-0:32.7.0(230.1*V)\r\n"
    "0-0:96.7.21(00004)\r\n"
    "0-1:24.2.1(190101115500W)(01234.567*m3)\r\n"
    "!"
)


def telegram(body: str = BODY) -> bytes:
    return (body + f"{crc16_arc(body.encode()):04X}\r\n").encode()


def test_crc16_arc_check_value():
    # CRC catalogue check value for CRC-16/ARC.
    assert crc16_arc(b"123456789") == 0xBB3D


def test_parse_values_units_and_timestamps():
    t = parse_telegram(telegram())
    assert t.crc_ok is True
    assert t.header == "/ISK5\\2M550T-1012" and t.manufacturer == "ISK"
    assert t.get("1.0.1.8.1") == pytest.approx(1234.567) and t.unit("1.0.1.8.1") == "kWh"
    assert t.get("1-0:32.7.0") == pytest.approx(230.1)
    assert t.get("1.3.0.2.8") == 50
    assert t.get("0.0.96.7.21") == 4
    assert t.get("0.0.96.1.1") == "E0034006362566627"
    stamp = t.get("0.0.1.0.0")
    assert stamp == dt.datetime(2019, 1, 1, 12, 0, tzinfo=dt.timezone(dt.timedelta(hours=1)))
    assert t.get("0.1.24.2.1") == pytest.approx(1234.567)  # gas: last value is the reading


def test_crc_mismatch_rejected_and_bypass():
    bad = bytearray(telegram())
    bad[bad.index(b"230.1")] ^= 0x01
    with pytest.raises(ChecksumError):
        parse_telegram(bytes(bad))
    assert parse_telegram(bytes(bad), verify_crc=False).crc_ok is False


def test_old_telegram_without_crc():
    t = parse_telegram(BODY)
    assert t.crc_ok is None and t.get("1.0.1.8.2") == pytest.approx(765.432)


@pytest.mark.parametrize("raw", ["no header", "/X\r\n1-0:1.8.1(1*kWh)\r\n", "/X\r\ngarbage\r\n!"])
def test_malformed(raw):
    with pytest.raises(DecodeError):
        parse_telegram(raw)


def test_smarty_encrypted_frame():
    pytest.importorskip("cryptography")
    from pydlms.security.ciphering import wrap_general_glo
    from pydlms.security.context import SecurityContext

    ek, ak = bytes(range(16)), bytes(range(16, 32))
    meter = SecurityContext(ek, ak, client_system_title=b"SAG12345")
    frame = wrap_general_glo(meter, telegram())
    t = decrypt_frame(frame, SecurityContext(ek, ak))
    assert t.get("1.0.1.8.1") == pytest.approx(1234.567)
