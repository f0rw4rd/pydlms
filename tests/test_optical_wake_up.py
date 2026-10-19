"""IEC 62056-21 break (B0), sign-off (B1) and the Annex B wake-ups on the
optical transport.

Every test runs on an injected clock whose ``sleep`` advances it, and
``time.sleep`` itself is made to fail: no test here waits in real time.
Timing values follow cB-Sigma's iec6205621 package (Annex B.1: NULs for
2.2 s then a 1.6 s pause; Annex B.2: 0.55 s NUL strings, each followed by
an ACK wait, for about 5 s); the annex text was not read (unverified).
"""

from __future__ import annotations

import logging

import pytest

from pydlms.exceptions import DlmsTimeoutError, ProtocolError
from pydlms.transports.iec62056_21 import BREAK, SIGN_OFF
from pydlms.transports.serial import OpticalTransport
from tests.test_optical_mode_c import GOOD, ModeCPort
from tests.test_transports import LGZ_ACK, LGZ_IDENT, FakePort

REQUEST = b"/?!\r\n"
ACK = b"\x06"
NUL = b"\x00"


class FakeClock:
    """Monotonic clock that only moves when something sleeps on it."""

    def __init__(self):
        self.now = 1000.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        assert seconds >= 0
        self.sleeps.append(seconds)
        self.now += seconds


class ClockPort(FakePort):
    """FakePort that time-stamps writes and can ACK the n-th NUL string."""

    def __init__(self, replies, clock, ack_on_burst=None):
        super().__init__(replies)
        self.clock = clock
        self.ack_on_burst = ack_on_burst
        self.bursts = 0
        self.log: list[tuple[float, bytes, tuple]] = []

    def write(self, data):
        self.log.append((self.clock.now, data, (self.baudrate, self.bytesize, self.parity)))
        if data and set(data) == {0}:
            self.bursts += 1
            if self.bursts == self.ack_on_burst:
                self.rx += ACK
        super().write(data)


@pytest.fixture(autouse=True)
def no_real_sleep(monkeypatch):
    def fail(seconds):
        raise AssertionError(f"real time.sleep({seconds}) in a clock-injected test")

    monkeypatch.setattr("pydlms.transports.serial.time.sleep", fail)


@pytest.fixture
def clock():
    return FakeClock()


def _optical(port, clock, **kw):
    transport = OpticalTransport("fake", timeout=1, clock=clock, sleep=clock.sleep, **kw)
    transport._serial = port
    return transport


def _written_at(port, data):
    return next(t for t, d, _ in port.log if d == data)


# --- break (B0) ----------------------------------------------------------------------


def test_send_break_writes_b0(clock):
    port = ClockPort({}, clock)
    _optical(port, clock).send_break()
    assert port.written == [BREAK] == [bytes.fromhex("0142300371")]


def test_send_break_crlf_form_is_opt_in(clock):
    # Gurux's form: SOH B0 ETX CR LF, no BCC. The CR LF ends the line for
    # meters that read lines and have no inter-character timeout.
    from pydlms.transports.iec62056_21 import BREAK_CRLF

    port = ClockPort({}, clock)
    _optical(port, clock, break_form="crlf").send_break()
    assert port.written == [BREAK_CRLF] == [bytes.fromhex("014230030d0a")]


def test_break_form_is_checked(clock):
    with pytest.raises(ValueError, match="break_form"):
        _optical(ClockPort({}, clock), clock, break_form="lf")


def test_break_before_sign_on_goes_first_at_300_7e1(clock):
    port = ClockPort({REQUEST: LGZ_IDENT, LGZ_ACK: LGZ_ACK}, clock)
    _optical(port, clock, break_before_sign_on=True).sign_on()
    assert port.written == [BREAK, REQUEST, LGZ_ACK]
    assert port.log[0][2] == (300, 7, "E")
    # An idle meter drops the B0 characters after its inter-character
    # timeout (1500 ms) before the request starts.
    assert _written_at(port, REQUEST) - _written_at(port, BREAK) > 1.5


def test_break_drains_what_the_meter_left_on_the_line(clock):
    port = ClockPort({REQUEST: LGZ_IDENT, LGZ_ACK: LGZ_ACK, BREAK: b"\x15junk"}, clock)
    ident = _optical(port, clock, break_before_sign_on=True).sign_on()
    assert ident.manufacturer == "LGZ"


def test_no_break_by_default(clock):
    port = ClockPort({REQUEST: LGZ_IDENT, LGZ_ACK: LGZ_ACK}, clock)
    _optical(port, clock).sign_on()
    assert BREAK not in port.written


# --- sign-off (B1) -------------------------------------------------------------------


def test_sign_off_sends_b1_and_reads_ack(clock):
    port = ClockPort({SIGN_OFF: ACK}, clock)
    _optical(port, clock).sign_off()
    assert port.written == [SIGN_OFF] == [bytes.fromhex("0142310370")]
    assert port.rx == b""


@pytest.mark.parametrize("reply,match", [(b"", "no ACK"), (b"\x15", "not ACK"), (BREAK, "not ACK")])
def test_sign_off_without_ack_is_a_protocol_error(clock, reply, match):
    port = ClockPort({SIGN_OFF: reply}, clock)
    with pytest.raises(ProtocolError, match=match):
        _optical(port, clock).sign_off()


def test_sign_off_accepts_ack_with_parity_bit(clock):
    port = ClockPort({SIGN_OFF: b"\x86"}, clock)  # bit 7 set by an 8N1 bridge
    _optical(port, clock).sign_off()


# --- normal wake-up (Annex B.1) -------------------------------------------------------


def test_normal_wake_up_sends_2_2s_of_nul_then_pauses_1_6s(clock):
    port = ClockPort({REQUEST: LGZ_IDENT, LGZ_ACK: LGZ_ACK}, clock)
    _optical(port, clock, wake_up="normal").sign_on()
    assert port.written[0] == NUL * 66  # 66 characters of 10 bits at 300 baud = 2.2 s
    assert port.log[0][2] == (300, 7, "E")
    assert port.written[1:] == [REQUEST, LGZ_ACK]
    gap = _written_at(port, REQUEST) - port.log[0][0]
    assert gap == pytest.approx(2.2 + 1.6, abs=0.01)


def test_normal_wake_up_does_not_double_count_a_blocking_flush(clock):
    """pyserial's flush() returns once the octets are on the wire."""
    port = ClockPort({REQUEST: LGZ_IDENT, LGZ_ACK: LGZ_ACK}, clock)
    blocking_flush = port.flush

    def flush():
        written = port.log[-1][1]
        clock.now += len(written) * 10 / port.baudrate
        blocking_flush()

    port.flush = flush
    _optical(port, clock, wake_up="normal").sign_on()
    gap = _written_at(port, REQUEST) - port.log[0][0]
    assert gap == pytest.approx(3.8, abs=0.01)


def test_normal_wake_up_drains_the_echo_of_the_nuls(clock):
    port = ClockPort({NUL * 66: NUL * 66, REQUEST: LGZ_IDENT, LGZ_ACK: LGZ_ACK}, clock)
    assert _optical(port, clock, wake_up="normal").sign_on().manufacturer == "LGZ"


def test_normal_wake_up_needs_no_sign_off(clock):
    port = ClockPort({REQUEST: LGZ_IDENT, LGZ_ACK: LGZ_ACK}, clock)
    transport = _optical(port, clock, wake_up="normal")
    transport.sign_on()
    transport.close()
    assert SIGN_OFF not in port.written


# --- fast wake-up (Annex B.2) ---------------------------------------------------------


def test_fast_wake_up_repeats_nul_strings_until_ack(clock):
    port = ClockPort({REQUEST: LGZ_IDENT, LGZ_ACK: LGZ_ACK}, clock, ack_on_burst=3)
    _optical(port, clock, wake_up="fast").sign_on()
    assert port.written[:3] == [NUL * 16] * 3  # 16 characters at 300 baud: 0.53 s
    assert port.written[3:] == [REQUEST, LGZ_ACK]
    burst_times = [t for t, d, _ in port.log if d == NUL * 16]
    spacing = burst_times[1] - burst_times[0]
    assert 0.55 < spacing < 0.8  # string plus the short ACK wait
    # About 300 ms after the ACK before the request.
    assert _written_at(port, REQUEST) - burst_times[-1] == pytest.approx(16 / 30 + 0.3, abs=0.03)


def test_fast_wake_up_without_ack_times_out_after_about_5s(clock):
    port = ClockPort({REQUEST: LGZ_IDENT}, clock)
    start = clock.now
    with pytest.raises(DlmsTimeoutError, match="fast wake-up"):
        _optical(port, clock, wake_up="fast").sign_on()
    assert REQUEST not in port.written
    assert 6 <= port.bursts <= 9
    assert 4.5 <= clock.now - start <= 5.8


def test_fast_wake_up_ignores_echoed_nuls_and_noise(clock):
    port = ClockPort({NUL * 16: NUL * 16 + b"\x15", REQUEST: LGZ_IDENT}, clock, ack_on_burst=2)
    port.replies[LGZ_ACK] = LGZ_ACK
    _optical(port, clock, wake_up="fast").sign_on()
    assert port.bursts == 2


def test_fast_wake_up_close_sends_b1_and_restores_sign_on_format(clock):
    port = ClockPort({REQUEST: LGZ_IDENT, LGZ_ACK: LGZ_ACK, SIGN_OFF: ACK}, clock, 1)
    transport = _optical(port, clock, wake_up="fast")
    transport.sign_on()
    transport.close()
    assert port.written[-1] == SIGN_OFF
    assert port.log[-1][2] == (9600, 8, "N")  # sent at the session's rate
    assert (transport.baudrate, transport.bytesize, transport.parity) == (300, 7, "E")


def test_close_after_failed_sign_off_still_restores(clock, caplog):
    port = ClockPort({REQUEST: LGZ_IDENT, LGZ_ACK: LGZ_ACK}, clock, 1)  # B1 unanswered
    transport = _optical(port, clock, wake_up="fast")
    transport.sign_on()
    with caplog.at_level(logging.WARNING, logger="pydlms.transport"):
        transport.close()
    assert "B1" in caplog.text
    assert transport._serial is None
    assert (transport.baudrate, transport.bytesize, transport.parity) == (300, 7, "E")


def test_sign_off_is_sent_once(clock):
    port = ClockPort({REQUEST: LGZ_IDENT, LGZ_ACK: LGZ_ACK, SIGN_OFF: ACK}, clock, 1)
    transport = _optical(port, clock, wake_up="fast")
    transport.sign_on()
    transport.sign_off()
    transport.close()
    assert port.written.count(SIGN_OFF) == 1


def test_break_then_wake_up_then_request(clock):
    port = ClockPort({REQUEST: LGZ_IDENT, LGZ_ACK: LGZ_ACK}, clock, ack_on_burst=1)
    _optical(port, clock, wake_up="fast", break_before_sign_on=True).sign_on()
    assert port.written == [BREAK, NUL * 16, REQUEST, LGZ_ACK]


def test_mode_c_readout_after_fast_wake_up_signs_off(clock):
    class Port(ModeCPort):
        def write(self, data):
            if data and set(data) == {0}:
                self.rx += ACK
            elif data == SIGN_OFF:
                self.rx += ACK
            super().write(data)

    port = Port(b"/LGZ5X\r\n", GOOD, b"\x06050\r\n", 9600)
    transport = _optical(port, clock, wake_up="fast")
    assert len(transport.read_mode_c().data_sets) == 6
    assert port.written == [NUL * 16, REQUEST, b"\x06050\r\n", SIGN_OFF]
    transport.close()
    assert port.written.count(SIGN_OFF) == 1


def test_wake_up_rejects_unknown_mode():
    with pytest.raises(ValueError, match="wake_up"):
        OpticalTransport("fake", wake_up="slow")


def test_sign_on_without_injected_clock_uses_module_time(monkeypatch):
    """The default clock is resolved at call time, so patching the module's
    time functions (as the older optical tests do) keeps working."""
    monkeypatch.setattr("pydlms.transports.serial.time.sleep", lambda s: None)
    transport = OpticalTransport("fake", timeout=1)
    transport._serial = FakePort({REQUEST: LGZ_IDENT, LGZ_ACK: LGZ_ACK})
    assert transport.sign_on().manufacturer == "LGZ"


# --- client and CLI options -----------------------------------------------------------


def test_client_optical_passes_wake_up_and_break():
    from pydlms.client import DlmsClient

    transport = DlmsClient.optical(
        "loop://", wake_up="fast", break_before_sign_on=True
    ).link.transport
    assert (transport.wake_up, transport.break_before_sign_on) == ("fast", True)
    default = DlmsClient.optical("loop://").link.transport
    assert (default.wake_up, default.break_before_sign_on) == ("none", False)
    assert default.break_form == "bcc"
    crlf = DlmsClient.optical("loop://", break_form="crlf").link.transport
    assert crlf.break_form == "crlf"


def _cli_client(*argv):
    from pydlms.cli import build_client, build_parser

    return build_client(build_parser().parse_args(["clock", *argv]))


def test_cli_optical_wake_up_and_break_flags():
    transport = _cli_client(
        "optical://loop://", "--optical-wake-up", "normal", "--optical-break"
    ).link.transport
    assert (transport.wake_up, transport.break_before_sign_on) == ("normal", True)
    default = _cli_client("optical://loop://").link.transport
    assert (default.wake_up, default.break_before_sign_on) == ("none", False)
    assert default.break_form == "bcc"
    crlf = _cli_client("optical://loop://", "--optical-break", "--optical-break-form", "crlf")
    assert crlf.link.transport.break_form == "crlf"


@pytest.mark.parametrize(
    "flags",
    [["--optical-wake-up", "fast"], ["--optical-break"], ["--optical-break-form", "crlf"]],
    ids=["wake-up", "break", "break-form"],
)
def test_cli_optical_flags_need_an_optical_endpoint(flags):
    with pytest.raises(SystemExit, match="optical://"):
        _cli_client("tcp://192.0.2.1", *flags)


def test_cli_rejects_unknown_wake_up():
    with pytest.raises(SystemExit):
        _cli_client("optical://loop://", "--optical-wake-up", "slow")
