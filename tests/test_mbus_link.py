"""Wired M-Bus request/response link (pydlms.mbus_link) and the simulator's MbusServer.

Sources: M-Bus Usergroup "The M-Bus: A
Documentation" Rev. 4.8 (5.2 telegram formats, 5.3 C field Table 1, 5.4
timing and repetition, 5.5 FCB/FCV, 6.1 and 6.4.1 printed telegrams, 7.1
selection); OMS Vol. 2 Issue 5.0.1 Annex N N.4.3 (wired REQ-UD2 / RSP-UD
with toggling FCB, printed byte by byte). Line sessions run on a scripted
transport with an injected clock, so every time-out is exact and instant.
"""

from __future__ import annotations

import pytest

from pydlms.exceptions import ChecksumError, DlmsTimeoutError, FramingError, ProtocolError
from pydlms.mbus import MbusFrame, MbusTransportHeader, decode_mbus_frame, encode_mbus_frame
from pydlms.mbus_link import (
    C_RSP_UD,
    MBUS_MAX_APDU,
    MbusLink,
    MbusLinkFrame,
    _secondary_octets,
    decode_link_frame,
    encode_long_frame,
    encode_selection,
    encode_short_frame,
    reply_timeout_for,
)
from pydlms.simulator import MbusServer, example_meter
from pydlms.transports.base import Transport

# OMS Vol. 2 Annex N N.4.3 / N.4.4 / N.4.5: REQ-UD2 to the meter selected by
# secondary address (A = FDh), FCB set for fragment 1 and 3, clear for 2.
OMS_REQ_UD2_FCB1 = bytes.fromhex("107BFD7816")
OMS_REQ_UD2_FCB0 = bytes.fromhex("105BFD5816")
# N.4.3 RSP-UD, fragment 1 (AFL CI 90h, encrypted): C=08h, A=03h, CS=16h.
OMS_RSP_UD = bytes.fromhex(
    "682A2A68 08 03 90 0501704 05D00 72 78563412 9344 10 07 05 00 5005 28FC"
    " B763E51B4A6D4FDDF2EEA906F61ED0DA7AB2 16 16".replace(" ", "")
)
# M-Bus documentation 4.8 6.1: application reset to the test address 254.
DOC_APP_RESET = bytes.fromhex("6804046853FE5010B116")
# 6.4.1: switch to 2400 baud, a control frame (L=3, no user data).
DOC_SET_BAUD = bytes.fromhex("6803036853FEBD0E16")
# 6.4.2: write primary address 8 to the test address.
DOC_SET_ADDRESS = bytes.fromhex("6806066853FE51017A082516")
# 6.2: RSP_UD of slave 5, fixed data structure (CI 73h).
DOC_RSP_UD_FIXED = bytes.fromhex(
    "6813136808057378563412 0A00E97E0100000035010000 3C16".replace(" ", "")
)

GET = bytes.fromhex("c001c100030100010800ff0200")


# --- frame vectors ---------------------------------------------------------------------


def test_short_frame_vectors():
    assert encode_short_frame(0x7B, 0xFD) == OMS_REQ_UD2_FCB1
    assert encode_short_frame(0x5B, 0xFD) == OMS_REQ_UD2_FCB0
    frame = decode_link_frame(OMS_REQ_UD2_FCB1)
    assert (frame.kind, frame.control, frame.address, frame.from_master) == (
        "short",
        0x7B,
        0xFD,
        True,
    )
    # SND_NKE: C=40h, CS = C + A (doc 4.8 5.2/Table 1).
    assert encode_short_frame(0x40, 5) == bytes.fromhex("1040054516")


@pytest.mark.parametrize(
    ("raw", "control", "address", "ci", "data"),
    [
        (OMS_RSP_UD, 0x08, 0x03, 0x90, OMS_RSP_UD[7:-2]),
        (DOC_APP_RESET, 0x53, 0xFE, 0x50, b"\x10"),
        (DOC_SET_BAUD, 0x53, 0xFE, 0xBD, b""),
        (DOC_SET_ADDRESS, 0x53, 0xFE, 0x51, bytes.fromhex("017A08")),
        (DOC_RSP_UD_FIXED, 0x08, 0x05, 0x73, DOC_RSP_UD_FIXED[7:-2]),
    ],
)
def test_long_frame_vectors(raw, control, address, ci, data):
    frame = decode_link_frame(raw)
    assert (frame.kind, frame.control, frame.address, frame.ci, frame.data) == (
        "long",
        control,
        address,
        ci,
        data,
    )
    assert encode_long_frame(control, address, ci, data) == raw


def test_rsp_ud_flags():
    frame = decode_link_frame(OMS_RSP_UD)
    assert frame.is_rsp_ud and not frame.from_master and not frame.is_dlms
    assert decode_link_frame(b"\xe5") == MbusLinkFrame("ack", b"\xe5")
    nack = decode_link_frame(encode_short_frame(0x01, 5))
    assert nack.is_nack and not nack.is_rsp_ud


@pytest.mark.parametrize("raw", [OMS_REQ_UD2_FCB1, DOC_APP_RESET, OMS_RSP_UD])
def test_every_byte_tamper_is_refused(raw):
    for i in range(len(raw)):
        for flip in (0x01, 0x80):
            tampered = bytearray(raw)
            tampered[i] ^= flip
            with pytest.raises(FramingError):
                decode_link_frame(bytes(tampered))


def test_checksum_error_type():
    with pytest.raises(ChecksumError):
        decode_link_frame(OMS_REQ_UD2_FCB1[:3] + b"\x00\x16")
    with pytest.raises(ChecksumError):
        decode_link_frame(DOC_APP_RESET[:-2] + b"\x00\x16")


@pytest.mark.parametrize("raw", [OMS_REQ_UD2_FCB1, DOC_APP_RESET, OMS_RSP_UD])
def test_truncated_frames(raw):
    for n in range(len(raw)):
        with pytest.raises(FramingError):
            decode_link_frame(raw[:n] if n else b"\x00")


def test_long_frame_limits():
    assert len(encode_long_frame(0x53, 1, 0x10, bytes(252))) == 261  # L=255, frame L+6
    with pytest.raises(ValueError, match="L=255"):
        encode_long_frame(0x53, 1, 0x10, bytes(253))


def test_secondary_address_notation():
    # libmbus notation: ID digits, then manufacturer, version, medium in line order.
    assert _secondary_octets("14491001 1057 01 06") == bytes.fromhex("0110491410570106")
    assert _secondary_octets("FFFFFFFFFFFFFFFF") == b"\xff" * 8
    assert _secondary_octets("1234FFFF" + "FFFF" + "FF" + "07") == bytes.fromhex("FFFF3412FFFFFF07")
    assert _secondary_octets(bytes(8)) == bytes(8)
    for bad in ("1234", "1234567A00000000", "12345678zz000000", b"\x00"):
        with pytest.raises(ValueError):
            _secondary_octets(bad)
    # Fig. 29: 68 0B 0B 68 53 FD 52 ID1-4 Man1-2 Gen Med CS 16.
    sel = encode_selection("12345678" + "9344" + "10" + "07")
    assert sel[:7] == bytes.fromhex("680B0B6853FD52")
    assert sel[7:15] == bytes.fromhex("7856341293441007")
    assert sel[-2] == sum(sel[4:-2]) & 0xFF


def test_reply_timeout():
    assert reply_timeout_for(2400) == pytest.approx(330 / 2400 + 0.05)
    assert reply_timeout_for(300) == pytest.approx(1.15)


# --- a scripted line with an injected clock ----------------------------------------------


class Clock:
    def __init__(self) -> None:
        self.t = 0.0

    def now(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.t += seconds


class Line(Transport):
    """A serial line whose far end is ``slave(raw) -> bytes``; a read with
    nothing pending advances the clock by its whole time-out."""

    def __init__(self, slave, clock: Clock, baudrate: int = 2400) -> None:
        self.slave = slave
        self.clock = clock
        self.baudrate = baudrate
        self.rx = bytearray()
        self.sent: list[bytes] = []

    def open(self) -> None:
        pass

    def close(self) -> None:
        pass

    def _write(self, data: bytes) -> None:
        self.sent.append(data)
        answer = self.slave(data)
        if answer:
            self.rx += answer

    def _read(self, max_bytes: int, timeout: float) -> bytes:
        if not self.rx:
            self.clock.sleep(timeout)
            return b""
        out = bytes(self.rx[:max_bytes])
        del self.rx[:max_bytes]
        return out


class Script:
    """Answers telegrams from a list, in order; None = no answer."""

    def __init__(self, *answers) -> None:
        self.answers = list(answers)

    def __call__(self, raw: bytes) -> bytes:
        answer = self.answers.pop(0)
        return b"" if answer is None else answer


class _Sock:
    def __init__(self) -> None:
        self.out = bytearray()

    def sendall(self, data: bytes) -> None:
        self.out += data


def server_line(clock: Clock, **options):
    """A Line to an MbusServer (address 5) in front of the example meter."""
    sock = _Sock()
    server = MbusServer(example_meter(), sock, address=5, **options)

    def slave(raw: bytes) -> bytes:
        server.feed(raw)
        out = bytes(sock.out)
        sock.out.clear()
        return out

    return Line(slave, clock), server


def link_on(line: Line, clock: Clock, **kw) -> MbusLink:
    kw.setdefault("primary_address", 5)
    return MbusLink(line, clock=clock.now, sleep=clock.sleep, **kw)


def rsp(ci: int, data: bytes, address: int = 5, stsap: int = 1, dtsap: int = 16, header=None):
    return encode_mbus_frame(MbusFrame(C_RSP_UD, address, ci, stsap, dtsap, data, header))


# --- addressing and set-up ---------------------------------------------------------------


@pytest.mark.parametrize("address", [-1, 251, 252, 253, 255])
def test_primary_address_range(address):
    with pytest.raises(ValueError):
        MbusLink(Line(Script(), Clock()), address)


def test_link_options_validated():
    line = Line(Script(), Clock())
    MbusLink(line, 254)
    MbusLink(line, 0)
    for kw in ({"client_sap": 256}, {"server_sap": -1}, {"max_segment": 251}, {"retries": -1}):
        with pytest.raises(ValueError):
            MbusLink(line, 1, **kw)
    link = MbusLink(line, 1)
    with pytest.raises(ValueError):
        link.client_sap = 300
    assert MbusLink(line, 1).reply_timeout == pytest.approx(330 / 2400 + 0.05 + 0.25)


def test_connect_sends_snd_nke_and_resets_fcb():
    clock = Clock()
    line = Line(Script(b"\xe5"), clock)
    link = link_on(line, clock)
    link.fcb_send = link.fcb_request = False
    link.connect()
    assert line.sent == [bytes.fromhex("1040054516")]
    assert link.fcb_send and link.fcb_request


def test_connect_without_answer_tries_three_times():
    clock = Clock()
    line = Line(Script(None, None, None), clock)
    link = link_on(line, clock)
    with pytest.raises(DlmsTimeoutError, match="3 attempts"):
        link.connect()
    assert len(line.sent) == 3 and len(set(line.sent)) == 1
    # Three reply time-outs, then the idle time of 33 bit periods.
    assert clock.t == pytest.approx(3 * link.reply_timeout + 33 / 2400)
    assert link.repetitions == 2


def test_connect_after_corrupt_answer():
    clock = Clock()
    line = Line(Script(b"\x10\x08\x05\x00\x16", b"\xe5"), clock)
    link = link_on(line, clock)
    link.connect()
    assert link.repetitions == 1 and len(line.sent) == 2


def test_corrupt_answers_raise_protocol_error():
    clock = Clock()
    line = Line(Script(b"\x42", b"\x68\x03", OMS_RSP_UD), clock)
    with pytest.raises(ProtocolError, match="corrupt answer, corrupt answer, unexpected"):
        link_on(line, clock).connect()


def test_nack_is_a_protocol_error():
    clock = Clock()
    line = Line(Script(encode_short_frame(0x01, 5)), clock)
    with pytest.raises(ProtocolError, match="NACK"):
        link_on(line, clock).connect()


def test_echo_is_skipped():
    clock = Clock()
    line = Line(lambda raw: raw + b"\xe5", clock)
    link = link_on(line, clock)
    link.connect()
    assert link.repetitions == 0


def test_secondary_selection():
    clock = Clock()
    secondary = _secondary_octets("12345678" + "9344" + "10" + "07")
    line, server = server_line(clock, secondary=secondary)
    link = link_on(
        line, clock, primary_address=0, secondary_address="12345678" + "9344" + "10" + "07"
    )
    assert link.address == 0xFD
    link.connect()
    assert line.sent[0] == bytes.fromhex("1040FD3D16")
    assert line.sent[1] == encode_selection(secondary)
    assert server.selected
    link.request(GET)
    # REQ_UD2 goes to 253 with FCB=1 first (doc 4.8 7.2; OMS Annex N N.4.3).
    assert OMS_REQ_UD2_FCB1 in line.sent
    # A wrong secondary address is not acknowledged: three attempts.
    other = link_on(Line(server_line(Clock(), secondary=secondary)[0].slave, clock),
                    clock, secondary_address="87654321FFFFFFFF")  # fmt: skip
    with pytest.raises(DlmsTimeoutError):
        other.connect()


# --- SND_UD ----------------------------------------------------------------------------


def test_send_apdu_fcb_toggles_per_segment():
    clock = Clock()
    line = Line(lambda raw: b"\xe5", clock)
    link = link_on(line, clock)
    apdu = bytes(range(256)) * 2 + bytes(100)  # 612 octets: 3 segments of <= 250
    link.send_apdu(apdu)
    frames = [decode_link_frame(raw) for raw in line.sent]
    assert [(f.control, f.ci) for f in frames] == [(0x73, 0x00), (0x53, 0x01), (0x73, 0x12)]
    assert all(f.address == 5 and f.data[:2] == bytes([16, 1]) for f in frames)
    assert b"".join(f.data[2:] for f in frames) == apdu
    link.send_apdu(b"\x01")
    assert decode_link_frame(line.sent[-1]).control == 0x53


def test_send_apdu_repeats_with_same_fcb_when_e5_is_lost():
    clock = Clock()
    line, server = server_line(clock, drop_ack={1})
    link = link_on(line, clock)
    link.connect()
    link.send_apdu(GET)
    snd = line.sent[1:]
    assert len(snd) == 2 and snd[0] == snd[1] and snd[0][4] == 0x73
    assert link.repetitions == 1 and not link.fcb_send
    # The server took the data once and acknowledged the repetition.
    assert server.duplicates == 1


def test_send_apdu_limits():
    clock = Clock()
    link = link_on(Line(lambda raw: b"\xe5", clock), clock)
    with pytest.raises(ProtocolError, match="exceeds"):
        link.send_apdu(bytes(MBUS_MAX_APDU + 1))
    # KSMWest H1 interface (Honeywell 2018, p. 6): the sequence number
    # rolls over from 1111 to 0000 while segments remain.
    line = Line(lambda raw: b"\xe5", clock)
    link = link_on(line, clock, max_segment=10, max_apdu_size=1000)
    link.send_apdu(bytes(171))
    cis = [decode_mbus_frame(raw).ci for raw in line.sent if raw[0] == 0x68]
    assert cis == [*range(16), 0x00, 0x11]


def test_send_without_ack_fails_after_three_attempts():
    clock = Clock()
    line = Line(Script(None, None, None), clock)
    with pytest.raises(DlmsTimeoutError, match="SND_UD CI 0x10"):
        link_on(line, clock).send_apdu(GET)


def test_broadcast_is_refused():
    clock = Clock()
    with pytest.raises(ProtocolError, match="broadcast"):
        link_on(Line(Script(), clock), clock).send_unconfirmed(GET, broadcast=True)


# --- REQ_UD2 / RSP_UD ------------------------------------------------------------------


def test_receive_multi_segment_with_fcb():
    clock = Clock()
    apdu = bytes(range(250)) + bytes(range(250)) + b"end"
    line = Line(Script(rsp(0x00, apdu[:250]), rsp(0x01, apdu[250:500]), rsp(0x12, b"end")), clock)
    link = link_on(line, clock)
    assert link.receive_apdu() == apdu
    assert [raw[1] for raw in line.sent] == [0x7B, 0x5B, 0x7B]
    assert link.fcb_request is False


def test_receive_repeats_after_corrupt_or_missing_rsp_ud():
    clock = Clock()
    good = rsp(0x10, b"\x01\x02")
    bad = good[:-2] + bytes([(good[-2] + 1) & 0xFF]) + b"\x16"
    line = Line(Script(bad, None, good), clock)
    link = link_on(line, clock)
    assert link.receive_apdu() == b"\x01\x02"
    assert line.sent == [bytes.fromhex("107B058016")] * 3
    assert link.repetitions == 2


def test_receive_gives_up_after_retries():
    clock = Clock()
    line = Line(Script(None, None, None), clock)
    with pytest.raises(DlmsTimeoutError, match="no answer after 3 attempts"):
        link_on(line, clock).receive_apdu()
    line = Line(Script(b"\x68", b"\x10", b"\x77"), clock)
    with pytest.raises(ProtocolError, match="corrupt answer after 3 attempts"):
        link_on(line, clock).receive_apdu()


@pytest.mark.parametrize("idle_ack", [False, True], ids=["rsp-ud-ci72", "e5"])
def test_receive_polls_until_ready(idle_ack):
    clock = Clock()
    line, server = server_line(clock, not_ready=3, idle_ack=idle_ack)
    link = link_on(line, clock, poll_interval=0.1)
    link.connect()
    response = link.request(GET)
    assert response[:1] == b"\xd8"  # exception-response: GET without an association
    assert server.req_ud2_count == 4
    controls = [raw[1] for raw in line.sent if raw[0] == 0x10][1:]
    # FCB toggles after each RSP_UD, stays after an E5 (not an RSP_UD).
    assert controls == ([0x7B] * 4 if idle_ack else [0x7B, 0x5B, 0x7B, 0x5B])


def test_receive_times_out_on_injected_clock():
    clock = Clock()
    line = Line(lambda raw: b"\xe5", clock)
    link = link_on(line, clock, poll_interval=0.5, timeout=3.0)
    with pytest.raises(DlmsTimeoutError, match=r"within 3\.0s \(0 segment"):
        link.receive_apdu()
    assert clock.t == pytest.approx(3.0)
    assert len(line.sent) == 6


def test_receive_max_polls():
    clock = Clock()
    link = link_on(Line(lambda raw: b"\xe5", clock), clock, poll_interval=0, max_polls=4)
    with pytest.raises(ProtocolError, match="after 4 polls"):
        link.receive_apdu()


def test_duplicate_segment_is_dropped():
    clock = Clock()
    first = rsp(0x00, b"a" * 250)
    line = Line(Script(first, first, rsp(0x11, b"b")), clock)
    link = link_on(line, clock)
    assert link.receive_apdu() == b"a" * 250 + b"b"
    assert link.discarded == 1


def test_out_of_order_segment():
    clock = Clock()
    line = Line(Script(rsp(0x00, b"a"), rsp(0x12, b"c")), clock)
    with pytest.raises(ProtocolError, match="segment 2 out of order"):
        link_on(line, clock).receive_apdu()


def test_wrong_address_and_saps_are_discarded():
    clock = Clock()
    line = Line(
        Script(rsp(0x10, b"x", address=6), rsp(0x10, b"y", dtsap=17), rsp(0x10, b"z")), clock
    )
    link = link_on(line, clock)
    assert link.receive_apdu() == b"z"
    assert link.discarded == 2


def test_header_ci_frames():
    clock = Clock()
    up = MbusTransportHeader("up", 1, 0, 0)
    line = Line(Script(rsp(0x7D, b"whole", header=up)), clock)
    assert link_on(line, clock).receive_apdu() == b"whole"
    down = MbusTransportHeader("down", 1, 0, 0)
    line = Line(Script(rsp(0x61, b"x", header=down)), clock)
    with pytest.raises(ProtocolError, match="downlink"):
        link_on(line, clock).receive_apdu()


def test_mbus_layer_ciphertext_is_refused():
    clock = Clock()
    plain = rsp(0x7D, b"secret", header=MbusTransportHeader("up", 1, 0, 0))
    # Configuration field 0x0500: security mode 5 (bits 12..8).
    body = bytearray(plain[4:-2])
    body[6] = 0x05  # C A CI ACC STS CF(LSB) CF(MSB)
    ciphered = plain[:4] + bytes(body) + bytes([sum(body) & 0xFF]) + b"\x16"
    with pytest.raises(FramingError, match="security mode 5"):
        link_on(Line(Script(ciphered), clock), clock).receive_apdu()


def test_apdu_size_cap():
    clock = Clock()
    answers = [rsp(i, bytes(100)) for i in range(3)]
    link = link_on(Line(Script(*answers), clock), clock, max_apdu_size=250)
    with pytest.raises(ProtocolError, match="exceeds 250"):
        link.receive_apdu()


def test_sequence_rolls_over_after_sixteen_segments():
    # KSMWest H1 interface (Honeywell 2018, p. 6): after 1111 the next
    # segment is 0000. 20 one-octet segments: 0..15, 0, 1, 2, then 3 final.
    clock = Clock()
    answers = [rsp(i % 16, bytes([i])) for i in range(19)] + [rsp(0x13, b"\x13")]
    link = link_on(Line(Script(*answers), clock), clock)
    assert link.receive_apdu() == bytes(range(20))


def test_rolled_over_duplicate_is_dropped():
    clock = Clock()
    answers = [rsp(i % 16, bytes([i])) for i in range(17)]
    answers += [rsp(0x00, b"\x10"), rsp(0x11, b"\x11")]  # segment 16 (seq 0) again
    link = link_on(Line(Script(*answers), clock), clock)
    assert link.receive_apdu() == bytes(range(18))
    assert link.discarded == 1


def test_endless_segments_hit_the_size_cap():
    clock = Clock()
    answers = [rsp(i % 16, b"s") for i in range(40)]
    link = link_on(Line(Script(*answers), clock), clock, max_apdu_size=32)
    with pytest.raises(ProtocolError, match="exceeds 32"):
        link.receive_apdu()


def test_request_user_data_link_level():
    clock = Clock()
    line = Line(Script(DOC_RSP_UD_FIXED, None, DOC_RSP_UD_FIXED), clock)
    link = link_on(line, clock)
    first = link.request_user_data()
    assert first.ci == 0x73 and link.fcb_request is False
    assert link.request_user_data().raw == DOC_RSP_UD_FIXED
    assert [raw[1] for raw in line.sent] == [0x7B, 0x5B, 0x5B]


# --- simulator end to end over the scripted line, with faults ----------------------------


def test_simulator_faults_end_to_end():
    from pydlms.client import DlmsClient

    clock = Clock()
    line, server = server_line(clock, drop_ack={2}, drop_response={3}, corrupt_response={5})
    link = link_on(line, clock, max_segment=40)
    client = DlmsClient(link, DlmsClient._settings(max_receive_pdu_size=640))
    with client:
        view = client.get_association_view()
    assert len(view) > 5
    assert server.duplicates == 1  # the SND_UD repeated after the lost E5
    assert link.repetitions == 3  # lost E5, missing and corrupt RSP_UD
    assert server.bad_frames == 0


def test_simulator_repeated_segment_is_dropped():
    """A slave that sends the same RSP_UD again despite the toggled FCB: the
    repeated segment is recognised by its sequence number and dropped. (A
    repeated final segment of a one-segment APDU cannot be told from a new
    APDU; the FCB rule is what prevents it.)"""
    from pydlms.client import DlmsClient

    clock = Clock()
    line, server = server_line(clock, repeat_response={2}, max_segment=20)
    link = link_on(line, clock)
    with DlmsClient(link, DlmsClient._settings()):
        pass  # the AARE spans 20-octet segments; poll 2 gets segment 0 again
    assert link.discarded == 1


def test_simulator_response_rolls_over_past_sixteen_segments():
    """Small segments: the object list spans more than 16 RSP_UD frames, so
    the sequence rolls over from 15 to 0 on both sides (KSMWest H1 p. 6)."""
    from pydlms.client import DlmsClient

    clock = Clock()
    line, server = server_line(clock, max_segment=8)
    link = link_on(line, clock)
    client = DlmsClient(link, DlmsClient._settings(max_receive_pdu_size=640))
    with client:
        view = client.get_association_view()
    assert len(view) > 5
    rsp_cis = [line_ci for line_ci in server.log if line_ci.startswith("RSP_UD CI=0x0F")]
    assert rsp_cis and server.bad_frames == 0


# --- DlmsClient.mbus against the simulator over TCP (an M-Bus gateway) -------------------


def test_dlms_client_mbus_large_attribute_over_tcp():
    from pydlms.client import DlmsClient
    from pydlms.simulator import serve_mbus

    srv = serve_mbus(example_meter(), address=7)
    host, port = srv.server_address[:2]
    try:
        with DlmsClient.mbus(f"tcp://{host}:{port}", 7, timeout=5) as client:
            assert client.association.settings.max_receive_pdu_size == 4000
            view = client.get_association_view()
            energy = client.get_register("1.0.1.8.0.255")
        server = srv.mbus_servers[0]
    finally:
        srv.shutdown()
        srv.server_close()
    assert len(view) > 10 and str(energy) == "12345678 Wh"
    sent = [line.split("=")[1] for line in server.log if line.startswith("RSP_UD")]
    # The object list spans several segments: 0x00, 0x01, ... then 0x1N.
    assert "0x00" in sent and "0x01" in sent
    assert server.log[0] == "SND_NKE A=7"


def test_dlms_client_mbus_constructor():
    from pydlms.client import DlmsClient
    from pydlms.transports.serial import SerialTransport
    from pydlms.transports.tcp import TcpTransport

    client = DlmsClient.mbus("/dev/ttyUSB7", 5, server_logical=1, client_sap=16)
    transport = client.link.transport
    assert isinstance(transport, SerialTransport)
    assert (transport.baudrate, transport.bytesize, transport.parity) == (2400, 8, "E")
    assert client.link.address == 5 and client.link.server_sap == 1
    client = DlmsClient.mbus("tcp://gw.example:10001", 254, max_receive_pdu_size=1024)
    assert isinstance(client.link.transport, TcpTransport)
    assert client.link.reply_timeout == 2.0
    assert client.association.settings.max_receive_pdu_size == 1024
    with pytest.raises(ValueError, match="host and a port"):
        DlmsClient.mbus("tcp://gw.example", 5)
    with pytest.raises(ValueError):
        DlmsClient.mbus("/dev/ttyUSB7", 253)
    client = DlmsClient.mbus("/dev/ttyUSB7", secondary_address="12345678FFFFFFFF")
    assert client.link.address == 0xFD


def test_stale_octets_are_dropped_before_sending():
    """A second E5 (two slaves, or mbus-device acknowledging SND_NKE to 253
    twice) must not acknowledge the next telegram."""
    clock = Clock()
    line = Line(Script(b"\xe5\xe5", None, None, None), clock)
    link = link_on(line, clock)
    link.connect()
    with pytest.raises(DlmsTimeoutError):
        link.send_apdu(GET)
    assert link.stale_octets == 1
