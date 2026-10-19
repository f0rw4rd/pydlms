"""Serial and optical (IEC 62056-21 modes C and E) transports.

Both use :func:`serial.serial_for_url`, so besides device paths they accept
pyserial URLs such as ``rfc2217://host:port``, ``socket://host:port`` and
``loop://``.

Optical sign-on (IEC 62056-21, mode E, protocol "HDLC")::

    client  /?!<CR><LF>                       at 300 baud, 7E1
    meter   /XXXZ\\2Ident<CR><LF>               Z = baud char, \\2 = mode E
    client  <ACK>2Z2<CR><LF>                  V=2 (HDLC), Z, Y=2 (binary)
            ...switch both ends to the baud for Z, 8N1, then HDLC...

Optical data readout (IEC 62056-21 clause 6.3, mode C, protocol control 0)::

    client  /?!<CR><LF>                       at 300 baud, 7E1
    meter   /XXXZIdent<CR><LF>
    client  <ACK>0Z0<CR><LF>                  V=0 (normal), Z, Y=0 (data readout)
            ...switch both ends to the baud for Z, still 7E1...
    meter   <STX>data block!<CR><LF><ETX><BCC>

The data block is a sequence of data lines (each ending in CR LF) of data sets
``address(value*unit)``; BCC is the XOR of every character after STX up to
and including ETX.

Baud characters for modes C/E: ``0``=300 ``1``=600 ``2``=1200 ``3``=2400
``4``=4800 ``5``=9600 ``6``=19200.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from pydlms.debug import get_logger
from pydlms.exceptions import (
    DlmsError,
    DlmsTimeoutError,
    FramingError,
    ProtocolError,
    TransportError,
)
from pydlms.transports.base import Transport

# The message structures moved to iec62056_21; re-exported so that imports
# from this module keep working.
from pydlms.transports.iec62056_21 import (
    ACK,
    BAUD_CHARS,
    BREAK,
    BREAK_CRLF,
    BREAK_FORMS,
    ETX,
    FAST_WAKE_UP_SETTLE,
    FAST_WAKE_UP_TOTAL,
    MAX_READOUT_SIZE,
    SIGN_OFF,
    STX,
    WAKE_UP_PAUSE,
    DataMessage,
    DataReadout,
    IecIdentification,
    ReadoutDataSet,
    ReadoutValue,
    block_check_character,
    fast_wake_up_nuls,
    parse_data_message,
    parse_identification,
    wake_up_nuls,
)

__all__ = [
    "SerialTransport",
    "OpticalTransport",
    "WAKE_UP_MODES",
    "IecIdentification",
    "BAUD_CHARS",
    "parse_identification",
    "DataReadout",
    "ReadoutDataSet",
    "ReadoutValue",
    "parse_data_message",
    "read_mode_c",
    "DataMessage",
    "block_check_character",
]

log = get_logger("transport")

#: Seconds after the break B0 before anything else is sent: more than the
#: IEC 62056-21 inter-character timeout of 1500 ms (unverified, no public
#: source found), so an idle
#: meter has dropped the B0 characters when the request starts.
BREAK_PAUSE = 1.6

#: ``OpticalTransport(wake_up=...)``: no wake-up, the IEC 62056-21 Annex B.1
#: wake-up message, or the Annex B.2 fast wake-up.
WAKE_UP_MODES = ("none", "normal", "fast")


def _import_serial():
    try:
        import serial  # type: ignore[import-untyped]
    except ImportError as exc:  # pragma: no cover - depends on extras
        raise TransportError(
            "serial transports need pyserial: pip install 'pydlms-client[serial]'"
        ) from exc
    return serial


class SerialTransport(Transport):
    """A serial port (8N1 by default) or pyserial URL.

    ``clock`` (a monotonic clock in seconds) and ``sleep`` replace
    :func:`time.monotonic` and :func:`time.sleep` for every wait and
    deadline, so tests can run the line timing on a simulated clock.
    """

    def __init__(
        self,
        port: str,
        baudrate: int = 9600,
        timeout: float = 5.0,
        bytesize: int = 8,
        parity: str = "N",
        stopbits: float = 1,
        clock: Callable[[], float] | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        self.clock = clock
        self.sleep = sleep
        self.port = port
        self.baudrate = baudrate
        self.timeout = timeout
        self.bytesize = bytesize
        self.parity = parity
        self.stopbits = stopbits
        self._serial = None

    @property
    def description(self) -> str:
        return f"serial:{self.port}@{self.baudrate}"

    def _now(self) -> float:
        # Resolved per call, so patching the time module still takes effect.
        return (self.clock or time.monotonic)()

    def _pause(self, seconds: float) -> None:
        (self.sleep or time.sleep)(seconds)

    def _wait_until(self, deadline: float) -> None:
        remaining = deadline - self._now()
        if remaining > 0:
            self._pause(remaining)

    def _tx_time(self, octets: int) -> float:
        """How long ``octets`` characters (10 bits each) take on the line."""
        return octets * 10 / self.baudrate

    def _drain(self) -> int:
        """Discard everything already received; return how many octets."""
        drained = 0
        while drained < MAX_READOUT_SIZE:
            chunk = self._read(4096, 0)
            if not chunk:
                break
            drained += len(chunk)
        if drained:
            log.debug("discarded %d received octets", drained)
        return drained

    def open(self) -> None:
        if self._serial is not None:
            return
        serial = _import_serial()
        try:
            self._serial = serial.serial_for_url(
                self.port,
                baudrate=self.baudrate,
                bytesize=self.bytesize,
                parity=self.parity,
                stopbits=self.stopbits,
                timeout=0,
            )
        except (serial.SerialException, ValueError, OSError) as exc:
            raise TransportError(f"cannot open {self.port}: {exc}") from exc
        except Exception as exc:  # noqa: BLE001 - termios.error is not an OSError
            if type(exc).__name__ != "error" or type(exc).__module__ != "termios":
                raise
            # A Linux PTY can refuse a setting (seen with parity E on reopen).
            raise TransportError(f"cannot open {self.port}: {exc}") from exc
        log.info("opened %s", self.description)

    def close(self) -> None:
        if self._serial is not None:
            try:
                self._serial.close()
            finally:
                self._serial = None

    def _port(self):
        if self._serial is None:
            raise TransportError(f"{self.description} is not open")
        return self._serial

    def reconfigure(self, baudrate: int, bytesize: int = 8, parity: str = "N") -> None:
        port = self._port()
        settings = {"baudrate": baudrate, "bytesize": bytesize, "parity": parity}
        try:
            # One atomic tcsetattr: setting the three properties one by one
            # makes pyserial reconfigure through intermediate states.
            port.apply_settings(settings)
        except Exception as exc:  # noqa: BLE001 - termios.error is not an OSError
            # Some drivers (Linux PTYs, a few USB adapters) refuse to switch
            # back from 7E1 in place; reopening with the new settings works.
            log.debug("in-place reconfigure failed (%s); reopening %s", exc, self.port)
            port.close()
            self._serial = None
            self.baudrate, self.bytesize, self.parity = baudrate, bytesize, parity
            # Only the port: a subclass open() (the optical sign-on) would
            # start a new session from inside this one.
            SerialTransport.open(self)
            return
        self.baudrate, self.bytesize, self.parity = baudrate, bytesize, parity
        log.debug("serial reconfigured to %d %d%s1", baudrate, bytesize, parity)

    def _write(self, data: bytes) -> None:
        port = self._port()
        port.write(data)
        port.flush()

    def _read(self, max_bytes: int, timeout: float) -> bytes:
        port = self._port()
        deadline = self._now() + timeout
        while True:
            waiting = port.in_waiting
            if waiting:
                return port.read(min(waiting, max_bytes))
            if self._now() >= deadline:
                return b""
            self._pause(0.005)


class OpticalTransport(SerialTransport):
    """Optical probe: IEC 62056-21 mode E sign-on, then 8N1 at the agreed baud.

    ``max_baud`` caps the rate the meter offers. ``device_address`` is put in
    the request message (``/?<address>!``) for multi-drop buses.

    ``break_before_sign_on`` sends the break message B0 at the sign-on rate
    first, ending a session a previous client left open. ``break_form``
    picks how B0 is sent: ``"bcc"`` (default, the command message with its
    BCC) or ``"crlf"`` (Gurux's ``SOH B0 ETX CR LF``, for meters that read
    lines without an inter-character timeout). ``wake_up`` precedes
    the request with the Annex B.1 wake-up message (``"normal"``: NULs for
    2.2 s, then 1.6 s pause) or the Annex B.2 fast wake-up (``"fast"``: NUL
    strings of 0.55 s until the meter answers ACK, :class:`DlmsTimeoutError`
    after about 5 s). A session opened with the fast wake-up is ended with
    the sign-off B1 on :meth:`close` (or after a mode C readout). Order:
    break, wake-up, request. ``clock`` and ``sleep`` as for
    :class:`SerialTransport`.
    """

    def __init__(
        self,
        port: str,
        timeout: float = 5.0,
        max_baud: int = 19200,
        device_address: str = "",
        skip_sign_on: bool = False,
        sign_on_bytesize: int = 7,
        sign_on_parity: str = "E",
        break_before_sign_on: bool = False,
        wake_up: str = "none",
        clock: Callable[[], float] | None = None,
        break_form: str = "bcc",
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        if wake_up not in WAKE_UP_MODES:
            raise ValueError(f"wake_up must be one of {WAKE_UP_MODES}, not {wake_up!r}")
        if break_form not in BREAK_FORMS:
            raise ValueError(f"break_form must be one of {BREAK_FORMS}, not {break_form!r}")
        # IEC 62056-21 sign-on runs at 300 baud 7E1. Bridges that handle the
        # line themselves (RFC 2217 servers, some TCP-serial gateways) may need
        # 8N1 here instead.
        super().__init__(
            port,
            300,
            timeout,
            bytesize=sign_on_bytesize,
            parity=sign_on_parity,
            clock=clock,
            sleep=sleep,
        )
        self.break_before_sign_on = break_before_sign_on
        self.break_form = break_form
        self.wake_up = wake_up
        #: Set by the fast wake-up: the meter expects B1 to end the session.
        self.signed_on_by_fast_wake_up = False
        self.sign_on_format = (sign_on_bytesize, sign_on_parity)
        self.max_baud = max_baud
        self.device_address = device_address
        self.skip_sign_on = skip_sign_on
        self.identification: IecIdentification | None = None
        #: How long to wait for the meter's ``ACK 2 Z 2 CR LF`` switch
        #: confirmation at the new baud (IEC 62056-21 tr <= 1500 ms). Meters
        #: that send none are tolerated after this wait.
        self.switch_confirm_timeout = 1.5
        self._echo = False
        self._ident_received = 0.0

    def open(self) -> None:
        super().open()
        if self.skip_sign_on:
            self.reconfigure(9600)
            return
        self.sign_on()

    def close(self) -> None:
        # The mode E switch is per session: the meter drops back to 300 baud
        # when the link ends, so the next open() must sign on at that rate
        # (DLMS UA 1000-2 Ed. 5 Excerpt 6.2 note: after the 60 s to 120 s
        # inactivity time-out "the operation moves from any point to the
        # start", 300 Bd 7E1 per its Figures 14 and 16).
        try:
            if self.signed_on_by_fast_wake_up and self._serial is not None:
                try:
                    self.sign_off()
                except DlmsError as exc:
                    log.warning("sign-off B1 on close failed: %s", exc)
        finally:
            try:
                super().close()
            finally:
                self.signed_on_by_fast_wake_up = False
                self._restore_sign_on_settings()

    # -- break, sign-off and wake-up (IEC 62056-21 Annex A/B, via cB-Sigma) ------------

    def send_break(self) -> None:
        """Send the break message B0 at the current rate and drain the line.

        The meter ends any session and returns to its initial state; it does
        not answer. ``break_form`` ``"bcc"`` sends ``01 42 30 03 71``,
        ``"crlf"`` Gurux's ``SOH B0 ETX CR LF`` without a BCC.
        """
        message = BREAK_CRLF if self.break_form == "crlf" else BREAK
        log.debug("sending break B0 (%s form)", self.break_form)
        started = self._now()
        self.send(message)
        # A meter already idle takes B0 for the start of a garbled message.
        # Waiting longer than the inter-character timeout (1500 ms; clause not
        # read, unverified) lets it discard B0 before the request arrives.
        self._wait_until(started + self._tx_time(len(message)) + BREAK_PAUSE)
        self._drain()
        self.signed_on_by_fast_wake_up = False

    def sign_off(self) -> None:
        """Send the sign-off B1 and wait for the meter's ACK (Annex B.2).

        Raises :class:`ProtocolError` when no ACK arrives within ``timeout``
        or the meter answers anything else. B1 goes out at the current rate.
        """
        # Cleared first: a failed sign-off is not repeated on close().
        self.signed_on_by_fast_wake_up = False
        self._pause(self._reaction_time())
        log.debug("sending sign-off B1")
        self.send(SIGN_OFF)
        self._skip_echo(SIGN_OFF)
        try:
            reply = self.recv(1, self.timeout)
        except DlmsTimeoutError:
            raise ProtocolError(f"no ACK to the sign-off B1 within {self.timeout:.1f}s") from None
        if reply[0] & 0x7F != ACK:
            raise ProtocolError(f"sign-off B1 answered with {reply!r}, not ACK")
        log.debug("sign-off acknowledged")

    def _normal_wake_up(self) -> None:
        """Annex B.1: NULs for 2.2 s, then a 1.6 s pause, then drain."""
        nuls = wake_up_nuls(self.baudrate)
        log.debug("wake-up: %d NUL characters", nuls)
        started = self._now()
        self.send(bytes(nuls))
        # flush() may already have waited for the NULs to leave the UART.
        self._wait_until(started + self._tx_time(nuls) + WAKE_UP_PAUSE)
        self._drain()

    def _fast_wake_up(self) -> None:
        """Annex B.2: NUL strings, each followed by a short wait for ACK."""
        nuls = fast_wake_up_nuls(self.baudrate)
        # Td: 20 ms plus two characters plus 20 ms, with a margin for a
        # converter (as cB-Sigma).
        ack_wait = 0.04 + self._tx_time(2) + 0.1
        end = self._now() + FAST_WAKE_UP_TOTAL
        strings = 0
        while self._now() < end:
            started = self._now()
            self.send(bytes(nuls))
            strings += 1
            self._wait_until(started + self._tx_time(nuls))
            deadline = self._now() + ack_wait
            while (remaining := deadline - self._now()) > 0:
                try:
                    chunk = self.recv(64, remaining)
                except DlmsTimeoutError:
                    break
                # Echoed NULs and line noise are skipped; bit 7 may carry parity.
                if any(octet & 0x7F == ACK for octet in chunk):
                    log.debug("fast wake-up acknowledged after %d NUL strings", strings)
                    self._pause(FAST_WAKE_UP_SETTLE)
                    self._drain()
                    self.signed_on_by_fast_wake_up = True
                    return
        raise DlmsTimeoutError(
            f"fast wake-up: no ACK after {strings} NUL strings ({FAST_WAKE_UP_TOTAL:.1f}s)"
        )

    def _prepare_sign_on(self) -> None:
        """Sign-on rate, then the optional break and wake-up."""
        self._enter_sign_on_rate()
        if self.break_before_sign_on:
            self.send_break()
        if self.wake_up == "normal":
            self._normal_wake_up()
        elif self.wake_up == "fast":
            self._fast_wake_up()

    def _restore_sign_on_settings(self) -> None:
        bytesize, parity = self.sign_on_format
        self.baudrate, self.bytesize, self.parity = 300, bytesize, parity

    def _enter_sign_on_rate(self) -> None:
        """Switch an open port back to 300 baud in the sign-on format."""
        bytesize, parity = self.sign_on_format
        if (self.baudrate, self.bytesize, self.parity) != (300, bytesize, parity):
            self.reconfigure(300, bytesize, parity)

    def _read_line(self, timeout: float) -> bytes:
        deadline = self._now() + timeout
        line = bytearray()
        while not line.endswith(b"\r\n"):
            remaining = deadline - self._now()
            if remaining <= 0:
                raise DlmsTimeoutError(
                    f"no identification line within {timeout:.1f}s: {bytes(line)!r}"
                )
            # The identification is 7-bit (ISO 646); an 8N1 bridge hands the
            # 7E1 parity bit over in bit 7.
            line += bytes(octet & 0x7F for octet in self.recv(1, remaining))
            if len(line) > 128:
                raise ProtocolError("identification line longer than 128 octets")
        start = line.find(b"/")
        return bytes(line[start:] if start >= 0 else line)

    def _request_identification(self) -> IecIdentification:
        request = b"/?" + self.device_address.encode("ascii") + b"!\r\n"
        log.debug("optical sign-on: %r", request)
        self.send(request)
        deadline = self._now() + self.timeout
        line = self._read_line(self.timeout)
        self._echo = line == request
        if self._echo:
            # Half-duplex RS-485 converters and some optical heads echo
            # what we send; the identification follows.
            log.debug("skipping the echo of our request")
            line = self._read_line(max(deadline - self._now(), 0))
        self._ident_received = self._now()
        ident = parse_identification(line)
        self.identification = ident
        log.info(
            "meter identification: %s (baud char %s, mode E=%s)",
            ident.manufacturer,
            ident.baud_char,
            ident.mode_e,
        )
        return ident

    def _agreed_baud_char(self, ident: IecIdentification) -> str:
        if ident.baud > self.max_baud:  # .baud raises for a char outside the table
            return next(
                c for c, b in sorted(BAUD_CHARS.items(), reverse=True) if b <= self.max_baud
            )
        return ident.baud_char

    def _wait_reaction_time(self, ident: IecIdentification) -> None:
        """Wait the minimum reaction time tr before answering: 200 ms, or
        20 ms when the manufacturer's third letter is lower case
        (IEC 62056-21 6.3.14)."""
        self._wait_until(self._ident_received + self._reaction_time(ident))

    def _reaction_time(self, ident: IecIdentification | None = None) -> float:
        ident = ident or self.identification
        return 0.02 if ident is not None and ident.manufacturer[2].islower() else 0.2

    def _skip_echo(self, sent: bytes) -> None:
        """Discard the echo of ``sent`` on a line that echoes."""
        if not self._echo:
            return
        deadline = self._now() + self.timeout
        echo = bytearray()
        while len(echo) < len(sent) and self._now() < deadline:
            try:
                echo += self.recv(len(sent) - len(echo), deadline - self._now())
            except DlmsTimeoutError:
                break
        if bytes(echo) != sent:
            log.debug("expected the echo %r, got %r", sent, bytes(echo))

    def _read_switch_confirm(self, ack: bytes) -> None:
        """Read the meter's ``ACK 2 Z 2 CR LF`` at the new baud. Per DLMS UA
        1000-2 Ed. 8 Excerpt 6.2 (the Green Book's restatement of IEC
        62056-21 Annex E) the confirmation comes "at the new baud rate but
        still with parity (7E1)"; on an 8N1 port the parity bit lands in bit
        7, so it is masked (Ed. 5 Excerpt Figure 17 prints it as ``06 B2 35
        B2 8D 0A`` for 9600 Bd). A meter that sends nothing is tolerated;
        anything else is a failed switch."""
        deadline = self._now() + self.switch_confirm_timeout
        reply = bytearray()
        while len(reply) < len(ack):
            remaining = deadline - self._now()
            if remaining <= 0:
                break
            try:
                reply += self.recv(len(ack) - len(reply), remaining)
            except DlmsTimeoutError:
                break
        if not reply:
            log.debug("no mode E switch confirmation; continuing")
            return
        masked = bytes(octet & 0x7F for octet in reply)
        if masked != ack:
            raise ProtocolError(f"meter did not confirm the mode E switch: {bytes(reply)!r}")
        log.debug("mode E switch confirmed")

    def sign_on(self) -> IecIdentification:
        self._prepare_sign_on()
        ident = self._request_identification()
        if not ident.mode_e:
            log.warning("meter did not announce mode E (\\2); trying HDLC anyway")
        baud_char = self._agreed_baud_char(ident)
        ack = b"\x062" + baud_char.encode("ascii") + b"2\r\n"
        self._wait_reaction_time(ident)
        self.send(ack)
        # The ACK must be fully on the wire at 300 baud before switching.
        self._pause(len(ack) * 10 / 300 + 0.05)
        self._skip_echo(ack)
        self.reconfigure(BAUD_CHARS[baud_char])
        self._read_switch_confirm(ack)
        return ident

    def _read_data_message(self) -> bytes:
        """Read ``STX ... ETX BCC``; ``timeout`` is an inactivity timeout."""
        message = bytearray()
        etx = -1
        while etx < 0 or len(message) < etx + 2:
            try:
                chunk = self.recv(4096, self.timeout)
            except DlmsTimeoutError:
                raise DlmsTimeoutError(
                    f"data message incomplete after {len(message)} octets"
                ) from None
            # Mode C is 7-bit (ISO 646); a bridge running 8N1 hands over the
            # parity bit in bit 7.
            message += bytes(octet & 0x7F for octet in chunk)
            if message[0] != STX:
                raise FramingError(f"data message does not start with STX: {bytes(message[:16])!r}")
            if len(message) > MAX_READOUT_SIZE:
                raise FramingError(f"data message exceeds {MAX_READOUT_SIZE} octets")
            if etx < 0:
                etx = message.find(bytes([ETX]))
        if len(message) > etx + 2:
            log.warning("ignoring %d octets after the BCC", len(message) - etx - 2)
        return bytes(message[: etx + 2])

    def read_mode_c(self) -> DataReadout:
        """IEC 62056-21 mode C data readout (clause 6.3, protocol control 0).

        Opens the port without the mode E sign-on if needed, signs on at 300
        baud, selects data readout at the announced baud (capped by
        ``max_baud``) and returns the verified, parsed data message. The port
        is left open at the readout baud; the meter returns to its idle state.
        """
        if self._serial is None:
            SerialTransport.open(self)
        self._prepare_sign_on()
        bytesize, parity = self.sign_on_format
        ident = self._request_identification()
        baud_char = self._agreed_baud_char(ident)
        ack = bytes([ACK]) + b"0" + baud_char.encode("ascii") + b"0\r\n"
        self._wait_reaction_time(ident)
        started = self._now()
        self.send(ack)
        # Switch once the ACK has left the UART at 300 baud. The meter answers
        # 200 ms to 1500 ms after the ACK, at the new baud, so do not wait
        # longer than the ACK takes to transmit (flush() may already have).
        remaining = started + len(ack) * 10 / 300 + 0.02 - self._now()
        if remaining > 0:
            self._pause(remaining)
        self._skip_echo(ack)
        self.reconfigure(BAUD_CHARS[baud_char], bytesize, parity)
        data_sets = parse_data_message(self._read_data_message())
        log.info("mode C readout: %d data sets", len(data_sets))
        if self.signed_on_by_fast_wake_up:
            self.sign_off()
        return DataReadout(ident, data_sets)


def read_mode_c(
    port: str,
    device_address: str = "",
    max_baud: int = 19200,
    timeout: float = 5.0,
    **kw,
) -> DataReadout:
    """Open ``port``, run one IEC 62056-21 mode C data readout and close it."""
    transport = OpticalTransport(
        port, timeout=timeout, max_baud=max_baud, device_address=device_address, **kw
    )
    try:
        return transport.read_mode_c()
    finally:
        transport.close()
