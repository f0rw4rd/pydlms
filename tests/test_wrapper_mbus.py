"""Tests for the TCP/UDP wrapper and the M-Bus long-frame layer."""

from __future__ import annotations

from pathlib import Path

import pytest

from pydlms.exceptions import ChecksumError, DlmsTimeoutError, FramingError
from pydlms.mbus import MbusFrame, MbusReader, decode_mbus_frame, encode_mbus_frame, segment_apdu
from pydlms.transports.base import LoopbackTransport
from pydlms.wrapper import (
    WPORT_BROADCAST,
    WPORT_MANAGEMENT_CLIENT,
    WPORT_MANAGEMENT_LOGICAL_DEVICE,
    WPORT_PUBLIC_CLIENT,
    WrapperLink,
    decode_wrapper,
    encode_wrapper,
)

DUMPS = Path(__file__).parent / "fixtures" / "dlms_parser" / "dumps"

# --- wrapper -----------------------------------------------------------------------


def test_wrapper_vector():
    # version 1, client wPort 0x10 -> logical device 1, 3-octet GET.
    raw = encode_wrapper(0x10, 0x01, b"\xc0\x01\xc1")
    assert raw == bytes.fromhex("0001 0010 0001 0003 C001C1".replace(" ", ""))
    pdu = decode_wrapper(raw)
    assert (pdu.source, pdu.destination, pdu.apdu) == (0x10, 0x01, b"\xc0\x01\xc1")


@pytest.mark.parametrize(
    "raw",
    [
        "0001001000010003C001",  # short payload
        "0001001000010003C001C1FF",  # trailing octet
        "0002001000010001C0",  # wrong version
        "00010010",  # truncated header
    ],
)
def test_wrapper_malformed(raw):
    with pytest.raises(FramingError):
        decode_wrapper(bytes.fromhex(raw))


def test_wrapper_too_large():
    with pytest.raises(ValueError):
        encode_wrapper(1, 1, bytes(0x10000))


def test_reserved_wports():
    # IEC 62056-47 reserved wPort numbers.
    assert WPORT_MANAGEMENT_CLIENT == 0x0001
    assert WPORT_PUBLIC_CLIENT == 0x0010
    assert WPORT_MANAGEMENT_LOGICAL_DEVICE == 0x0001
    assert WPORT_BROADCAST == 0x007F


def test_wrapper_link_defaults_to_public_client_and_management_device():
    transport = LoopbackTransport()
    link = WrapperLink(transport)
    link.connect()
    link.send_apdu(b"\x60")
    assert transport.sent == [bytes.fromhex("0001 0010 0001 0001 60")]


def test_wrapper_link_reassembles_split_reads():
    transport = LoopbackTransport()
    link = WrapperLink(transport, timeout=0.2)
    link.connect()
    reply = encode_wrapper(0x01, 0x10, bytes(range(50)))
    # Deliver one octet at a time through recv's max_bytes.
    transport.inject(reply)
    assert link.receive_apdu() == bytes(range(50))


def test_wrapper_link_request():
    def responder(data):
        pdu = decode_wrapper(data)
        return encode_wrapper(pdu.destination, pdu.source, b"\xc4" + pdu.apdu[1:])

    link = WrapperLink(LoopbackTransport(responder), client_wport=0x20, server_wport=0x01)
    link.connect()
    assert link.request(b"\xc0\x01\x02") == b"\xc4\x01\x02"


def test_wrapper_link_wrong_destination_is_skipped():
    """A WPDU for another wPort (e.g. a push on a shared connection) is not
    ours; it is discarded and the wait goes on (REVIEW F8)."""
    transport = LoopbackTransport()
    link = WrapperLink(transport, client_wport=0x10, timeout=0.05)
    transport.inject(encode_wrapper(1, 0x11, b"\x00"))
    with pytest.raises(DlmsTimeoutError):
        link.receive_apdu()
    assert link.discarded == 1


# REVIEW F8 repro: a version-2 WPDU followed by a good one.
BAD_VERSION_THEN_GOOD = bytes.fromhex("0002000100100004deadbeef0001000100100007c401c100090142")


def test_wrapper_bad_version_consumes_its_length():
    transport = LoopbackTransport()
    link = WrapperLink(transport, timeout=0.05)
    transport.inject(BAD_VERSION_THEN_GOOD)
    assert link.receive_apdu() == bytes.fromhex("c401c100090142")
    assert link.discarded == 1


def test_wrapper_wrong_source_wport_is_skipped():
    """REVIEW F8 repro: source wPort 5 while we talk to logical device 1."""
    transport = LoopbackTransport()
    link = WrapperLink(transport, timeout=0.05)
    transport.inject(bytes.fromhex("0001000500100007c401c100090142"))
    with pytest.raises(DlmsTimeoutError):
        link.receive_apdu()
    transport.inject(bytes.fromhex("0001000500100001c40001000100100001c5"))
    assert link.receive_apdu() == b"\xc5"


def test_wrapper_push_to_other_wport_does_not_fail_request():
    """REVIEW F8 repro: a push to wPort 0x66 queued before the answer."""

    def responder(data):
        pdu = decode_wrapper(data)
        push = encode_wrapper(1, 0x66, bytes.fromhex("0f00000001000902abcd"))
        return push + encode_wrapper(pdu.destination, pdu.source, b"\xc4\x01")

    link = WrapperLink(LoopbackTransport(responder), timeout=0.2)
    link.connect()
    assert link.request(b"\xc0\x01") == b"\xc4\x01"


def test_wrapper_check_ports_off_accepts_any_port():
    transport = LoopbackTransport()
    link = WrapperLink(transport, timeout=0.05, check_ports=False)
    transport.inject(encode_wrapper(9, 0x66, b"\x0f"))
    assert link.receive_apdu() == b"\x0f"


def test_wrapper_broadcast_server_wport_accepts_any_source():
    transport = LoopbackTransport()
    link = WrapperLink(transport, timeout=0.05, server_wport=WPORT_BROADCAST)
    transport.inject(encode_wrapper(9, 0x10, b"\xc4"))
    assert link.receive_apdu() == b"\xc4"


class DatagramTransport(LoopbackTransport):
    """Loopback that keeps datagram boundaries, like UdpTransport."""

    def __init__(self, datagrams):
        super().__init__()
        self.datagrams = list(datagrams)

    def recv_datagram(self, timeout=None):
        if not self.datagrams:
            raise DlmsTimeoutError("no datagram")
        return self.datagrams.pop(0)


def test_wrapper_udp_datagram_length_mismatch_is_discarded():
    """Over UDP a datagram whose wrapper length disagrees with its size must
    not desync the next datagram (IEC 62056-4-7 via cB-Sigma)."""
    good = encode_wrapper(1, 0x10, b"\xc4\x01")
    short = encode_wrapper(1, 0x10, b"\xc4\x01\x02")[:-1]
    link = WrapperLink(DatagramTransport([short, good]), timeout=0.05)
    assert link.receive_apdu() == b"\xc4\x01"
    assert link.discarded == 1


def test_wrapper_link_timeout():
    link = WrapperLink(LoopbackTransport(), timeout=0.05)
    with pytest.raises(DlmsTimeoutError):
        link.receive_apdu()


# --- M-Bus ------------------------------------------------------------------------------


def _kaifa_raw() -> bytes:
    return bytes.fromhex((DUMPS / "mbus_kaifa_ma309m.log").read_text().split()[0])


def _netz_noe_raw() -> bytes:
    text = (DUMPS / "mbus_netz_noe_p1.log").read_text()
    return bytes.fromhex("".join(text.replace("-", "").split()))


def test_real_kaifa_frames_decode_and_round_trip():
    raw = _kaifa_raw()
    first = decode_mbus_frame(raw[:256])
    assert (first.control, first.address, first.ci, first.stsap, first.dtsap) == (
        0x53,
        0xFF,
        0x00,
        0x01,
        0x67,
    )
    assert not first.final and first.sequence == 0
    second = decode_mbus_frame(raw[256:])
    assert second.final and second.sequence == 1
    assert encode_mbus_frame(first) == raw[:256]
    assert encode_mbus_frame(second) == raw[256:]


def test_real_netz_noe_reassembly():
    apdus = MbusReader().feed(_netz_noe_raw())
    assert len(apdus) == 1
    apdu = apdus[0]
    assert apdu[0] == 0xDB
    # general-glo-ciphering length field matches the reassembled size.
    assert apdu[10] == 0x81 and apdu[11] == len(apdu) - 12


def test_reader_byte_by_byte_with_noise():
    reader = MbusReader()
    stream = b"\xe5\x10\x40\x01\x41\x16\x00\x00" + _netz_noe_raw()
    apdus = []
    for b in stream:
        apdus += reader.feed(bytes([b]))
    assert len(apdus) == 1


@pytest.mark.parametrize("position", range(4, 30))
def test_any_corrupted_body_byte_rejected(position):
    raw = bytearray(_kaifa_raw()[:256])
    raw[position] ^= 0x01
    with pytest.raises((ChecksumError, FramingError)):
        decode_mbus_frame(bytes(raw))


def test_bad_checksum_is_checksum_error():
    raw = bytearray(_kaifa_raw()[:256])
    raw[-2] ^= 0xFF
    with pytest.raises(ChecksumError):
        decode_mbus_frame(bytes(raw))


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        bytes.fromhex("6805056853FF000167CC17"),  # wrong stop
        bytes.fromhex("6805066853FF0001670016"),  # L mismatch
        bytes.fromhex("6805056853FF5001670A16"),  # CI not DLMS, checksum ok
        bytes.fromhex("6803036853FFF04216"),  # too short for SAPs
    ],
)
def test_malformed_mbus(raw):
    with pytest.raises(FramingError):
        decode_mbus_frame(raw)


def test_segment_and_reassemble_round_trip():
    apdu = bytes(range(256)) * 3
    frames = segment_apdu(apdu, max_data=200)
    assert len(frames) == 4
    reader = MbusReader()
    out = []
    for f in frames:
        out += reader.feed(f)
    assert out == [apdu]


def test_sequence_rolls_over_after_1111():
    # KSMWest H1 interface (Honeywell 2018, p. 6): "when the sequence number
    # reaches the value 1111 and there are segments remaining ..., the next
    # segment sequence number will take the value 0000".
    apdu = bytes(range(256)) * 2
    frames = segment_apdu(apdu, max_data=20)
    cis = [decode_mbus_frame(f).ci for f in frames]
    assert len(frames) == 26 and cis == [*range(16), *range(9), 0x19]
    reader = MbusReader()
    assert reader.feed(b"".join(frames)) == [apdu]


def test_reader_caps_a_never_ending_apdu():
    reader = MbusReader(max_apdu_size=100)
    frames = [segment_apdu(bytes(250), max_data=10)[i] for i in range(15)]
    assert reader.feed(b"".join(frames)) == []
    assert reader.dropped_apdus == 1
    assert reader.feed(b"".join(segment_apdu(b"ok"))) == [b"ok"]


def test_unsegmented_ci_0x10():
    frames = segment_apdu(b"\x0f\x01")
    assert decode_mbus_frame(frames[0]).ci == 0x10


def test_out_of_order_segment_discarded():
    frames = segment_apdu(bytes(600), max_data=200)
    reader = MbusReader()
    assert reader.feed(frames[0] + frames[2]) == []
    # A fresh complete sequence still works afterwards.
    assert reader.feed(b"".join(frames)) == [bytes(600)]


def test_new_first_segment_restarts():
    a = segment_apdu(b"A" * 300, max_data=200)
    b = segment_apdu(b"B" * 10)
    reader = MbusReader()
    assert reader.feed(a[0] + b[0]) == [b"B" * 10]


def test_frame_dataclass_flags():
    f = MbusFrame(0x53, 0xFF, 0x13, 1, 0x67, b"")
    assert f.sequence == 3 and f.final
