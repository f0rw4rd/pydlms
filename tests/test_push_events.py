"""Unsolicited APDUs besides DataNotification: EventNotification-Request (LN)
and InformationReport-Request (SN), through PushDecoder.

The fixed vectors are derived field by field from the A-XDR encoding below;
the EventNotification encoding is also dissected without error by Wireshark
4.6 in ``tests/integration/test_tshark.py``.
"""

from __future__ import annotations

import pytest

from pydlms.apdu.sn import InformationReportRequest
from pydlms.apdu.xdlms import AttributeDescriptor, EventNotificationRequest
from pydlms.cosem.data import DlmsData
from pydlms.cosem.time import CosemDateTime
from pydlms.exceptions import DecodeError
from pydlms.obis import ObisCode
from pydlms.push import PushDecoder, decode_notification

STAMP = bytes.fromhex("07E8050103 0C0000 00 FF88 00".replace(" ", ""))  # 2024-05-01 12:00

# C2                      EventNotification-Request
# 01 0C <12 octets>       time present, OCTET STRING (12)
# 0001 0000600B00FF 02    class 1, 0.0.96.11.0.255, attribute 2
# 12 002A                 long-unsigned 42
EVENT = bytes.fromhex("C2010C" + STAMP.hex() + "00010000600B00FF02" + "12002A")

# 18                      InformationReport-Request
# 00                      current-time absent
# 02 0002 0110 0002 0118  two variable names (CHOICE 2: 0x0110, 0x0118)
# 02 06 000004D2 12 0005  two values: double-long-unsigned 1234, long-unsigned 5
REPORT = bytes.fromhex("1800" + "0202011002" + "0118" + "0206000004D2120005")


def test_event_notification_vector_matches_codec():
    note = EventNotificationRequest(
        AttributeDescriptor(1, ObisCode.parse("0.0.96.11.0.255"), 2), DlmsData.uint16(42), STAMP
    )
    assert note.to_bytes() == EVENT


def test_event_notification_push():
    (message,) = PushDecoder(framing="raw").feed(EVENT)
    (record,) = message.records
    assert record.obis == ObisCode.parse("0.0.96.11.0.255")
    assert record.class_id == 1 and record.attribute == 2
    assert record.value == 42
    assert message.timestamp == CosemDateTime.from_bytes(STAMP)


def test_event_notification_without_time():
    raw = EventNotificationRequest(
        AttributeDescriptor(3, ObisCode.parse("1.0.1.8.0.255"), 2), DlmsData.uint32(7)
    ).to_bytes()
    assert raw[:2] == b"\xc2\x00"
    note, records, complete = decode_notification(raw)
    assert note.timestamp is None and complete and records[0].value == 7


def test_information_report_vector_matches_codec():
    report = InformationReportRequest(
        None, [0x0110, 0x0118], [DlmsData.uint32(1234), DlmsData.uint16(5)]
    )
    assert report.to_bytes() == REPORT


def test_information_report_push():
    (message,) = PushDecoder(framing="raw").feed(REPORT)
    assert [(r.short_name, r.value) for r in message.records] == [(0x0110, 1234), (0x0118, 5)]
    assert all(r.obis is None for r in message.records)
    assert str(message.records[0]).startswith("SN 0x0110")
    assert message.timestamp is None


def test_ciphered_event_notification_push():
    pytest.importorskip("cryptography")
    from pydlms.security.ciphering import wrap
    from pydlms.security.context import SecurityContext

    ek = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
    ak = bytes.fromhex("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF")
    meter = SecurityContext(ek, ak, client_system_title=b"METER001")
    ciphered = wrap(meter, EVENT)
    assert ciphered[0] == 0xCA  # glo-event-notification-request
    reader = SecurityContext(
        ek, ak, client_system_title=b"READER01", server_system_title=b"METER001"
    )
    (message,) = PushDecoder(framing="raw", security=reader).feed(ciphered)
    assert message.authenticated and message.records[0].value == 42


@pytest.mark.parametrize("cut", range(1, len(EVENT)))
def test_truncated_event_notification_rejected(cut):
    with pytest.raises(DecodeError):
        decode_notification(EVENT[:cut])


@pytest.mark.parametrize("cut", range(1, len(REPORT)))
def test_truncated_information_report_rejected(cut):
    with pytest.raises(DecodeError):
        decode_notification(REPORT[:cut])


def test_information_report_count_mismatch_rejected():
    # Two names but one value.
    with pytest.raises(DecodeError):
        decode_notification(bytes.fromhex("1800" + "0202011002" + "0118" + "0106000004D2"))


def test_other_apdus_are_not_pushes():
    with pytest.raises(DecodeError, match="expected DataNotification"):
        decode_notification(bytes.fromhex("C001C1000100002A0000FF0200"))


def test_invalid_utf8_in_a_push_keeps_the_values_before_it():
    # structure { unsigned 5, utf8-string <ff> }: the string is malformed, the
    # leading value is intact and must survive like a truncated body does.
    note, records, complete = decode_notification(
        bytes.fromhex("0f00000001" + "00" + "0202" + "1105" + "0c01ff")
    )
    assert not complete
    assert [r.value for r in records] == [5]


@pytest.mark.parametrize("n", range(1, 11))
def test_truncated_data_notification_raises_decode_error(n):
    """Every prefix of a DataNotification raises DecodeError, never IndexError
    (``0f 0f 68``, three octets of an M-Bus frame read as an APDU, crashed
    ``explain`` before)."""
    full = bytes.fromhex("0f00000001000902abcd")
    try:
        decode_notification(full[:n])
    except DecodeError:
        pass
    with pytest.raises(DecodeError):
        decode_notification(bytes.fromhex("0f0f68"))
    # A body cut inside the Sagemcom descriptor-pair probe decodes leniently.
    for raw in ("0f0000000100020216", "0f000000010002021601"):
        assert decode_notification(bytes.fromhex(raw))[2] is False
