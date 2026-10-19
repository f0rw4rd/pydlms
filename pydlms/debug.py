"""Debugging and tracing support.

pydlms logs through the standard :mod:`logging` module under the ``pydlms``
logger tree, one child per layer, so a user can turn on exactly the layer they
are chasing::

    pydlms.transport   raw bytes on the wire (TX/RX hexdumps)
    pydlms.hdlc        HDLC frames, sequence numbers, segmentation
    pydlms.wrapper     TCP/UDP wrapper headers
    pydlms.mbus        M-Bus long frames and reassembly
    pydlms.security    ciphering decisions (SC byte, IC, system titles; never keys)
    pydlms.apdu        decoded APDUs (service, invoke-id, result)
    pydlms.association AARQ/AARE, HLS passes, release
    pydlms.client      high-level calls and their outcome

Two levels are used: ``DEBUG`` for one-line summaries and :data:`TRACE` (5)
for full hexdumps and annotated decodes.

:func:`enable_debug` is the one-call switch. :class:`RedactingFilter` is
installed on every pydlms handler it creates and is also usable on your own
handlers; it replaces registered secrets in log output with ``***``. The
library itself never formats key material into a log message (the security
context redacts its own ``repr``), so the filter is defence in depth.
:func:`hexdump` and :func:`hexstr` mask the octets of registered secrets
(``**``) before formatting, because a filter that matches rendered text
cannot see a key a hexdump splits over two lines (the dedicated key in an
InitiateRequest always is). Keys, the dedicated key and the association
secret (LLS password / HLS secret) are registered.
"""

from __future__ import annotations

import contextvars
import logging
import sys
import threading
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from typing import IO

__all__ = [
    "TRACE",
    "get_logger",
    "hexdump",
    "hexstr",
    "enable_debug",
    "disable_debug",
    "RedactingFilter",
    "register_secret",
    "unregister_secret",
    "FrameRecorder",
]

#: Log level below DEBUG used for full hexdumps and annotated decodes.
TRACE = 5
logging.addLevelName(TRACE, "TRACE")

_ROOT = "pydlms"


def get_logger(layer: str) -> logging.Logger:
    """Return the logger for one stack layer (``pydlms.<layer>``)."""
    return logging.getLogger(f"{_ROOT}.{layer}")


def _secret_mask(raw: bytes) -> list[bool] | None:
    """Which octets of ``raw`` belong to a registered secret (None: none do).

    Masking the bytes before they are formatted is what makes a key that a
    hexdump splits over two lines redactable at all.
    """
    with _SECRETS_LOCK:
        secrets = list(_SECRETS)
    mask = None
    for secret in secrets:
        start = raw.find(secret)
        while start != -1:
            if mask is None:
                mask = [False] * len(raw)
            mask[start : start + len(secret)] = [True] * len(secret)
            start = raw.find(secret, start + 1)
    return mask


def _hex(raw: bytes, mask: list[bool] | None, offset: int = 0) -> str:
    if mask is None:
        return raw.hex(" ").upper()
    return " ".join("**" if mask[offset + i] else f"{b:02X}" for i, b in enumerate(raw))


def hexstr(data: bytes | bytearray | memoryview, limit: int | None = None) -> str:
    """Compact uppercase hex with single spaces, optionally truncated.

    Octets of registered secrets (:func:`register_secret`) render as ``**``.
    """
    raw = bytes(data)
    mask = _secret_mask(raw)
    if limit is not None and len(raw) > limit:
        return _hex(raw[:limit], mask) + f" ... (+{len(raw) - limit} bytes)"
    return _hex(raw, mask)


def hexdump(data: bytes | bytearray | memoryview, width: int = 16, prefix: str = "") -> str:
    """Classic offset / hex / ASCII dump, one line per ``width`` octets.

    Octets of registered secrets render as ``**`` (``*`` in the ASCII column),
    even when a secret spans two lines.
    """
    raw = bytes(data)
    if not raw:
        return f"{prefix}<empty>"
    mask = _secret_mask(raw)
    lines = []
    for off in range(0, len(raw), width):
        chunk = raw[off : off + width]
        hexpart = _hex(chunk, mask, off).ljust(width * 3 - 1)
        text = "".join(
            "*" if mask is not None and mask[off + i] else (chr(b) if 0x20 <= b < 0x7F else ".")
            for i, b in enumerate(chunk)
        )
        lines.append(f"{prefix}{off:04X}  {hexpart}  |{text}|")
    return "\n".join(lines)


# --- secret redaction -----------------------------------------------------

_SECRETS: set[bytes] = set()
_SECRETS_LOCK = threading.Lock()


def register_secret(secret: object) -> None:
    """Register key material so :class:`RedactingFilter` masks it.

    Secrets shorter than 4 octets are ignored: masking them would mangle
    unrelated output and they would not be meaningful keys anyway. So is
    anything that is not bytes (a crypto provider handle: its bytes are
    not here to leak).
    """
    if isinstance(secret, (bytes, bytearray)) and len(secret) >= 4:
        with _SECRETS_LOCK:
            _SECRETS.add(bytes(secret))


def unregister_secret(secret: object) -> None:
    if isinstance(secret, (bytes, bytearray)) and secret:
        with _SECRETS_LOCK:
            _SECRETS.discard(bytes(secret))


def _secret_renderings(secret: bytes) -> Iterable[str]:
    yield secret.hex()
    yield secret.hex().upper()
    yield secret.hex(" ")
    yield secret.hex(" ").upper()
    yield repr(secret)


class RedactingFilter(logging.Filter):
    """Mask every registered secret (hex in any common rendering) in records."""

    def filter(self, record: logging.LogRecord) -> bool:
        with _SECRETS_LOCK:
            secrets = list(_SECRETS)
        if not secrets:
            return True
        message = record.getMessage()
        redacted = message
        for secret in secrets:
            for rendering in _secret_renderings(secret):
                if rendering in redacted:
                    redacted = redacted.replace(rendering, "***")
        if redacted != message:
            record.msg = redacted
            record.args = ()
        return True


# --- secret payloads ------------------------------------------------------

_SENSITIVE = contextvars.ContextVar("pydlms_sensitive_payloads", default=False)


@contextmanager
def sensitive_payloads() -> Iterator[None]:
    """Within this block, TRACE output omits plaintext APDU contents.

    For HLS passes 3 and 4, whose f(StoC) / f(CtoS) are authentication
    material (and travel encrypted in a ciphered association).
    """
    token = _SENSITIVE.set(True)
    try:
        yield
    finally:
        _SENSITIVE.reset(token)


def payloads_sensitive() -> bool:
    """Whether the caller is inside :func:`sensitive_payloads`."""
    return _SENSITIVE.get()


# --- one-call switch ------------------------------------------------------

_HANDLER_ATTR = "_pydlms_debug_handler"


def enable_debug(
    level: int | str = logging.DEBUG,
    layers: Iterable[str] | None = None,
    stream: IO[str] | None = None,
    fmt: str = "%(asctime)s.%(msecs)03d %(name)-20s %(levelname)-5s %(message)s",
) -> logging.Handler:
    """Attach a stderr handler to the pydlms loggers and set their level.

    ``level`` may be ``"TRACE"`` (hexdumps of every frame) or ``"DEBUG"``.
    ``layers`` limits output to e.g. ``["hdlc", "security"]``. Returns the
    handler so callers can detach it with :func:`disable_debug`.
    """
    if isinstance(level, str):
        level = TRACE if level.upper() == "TRACE" else logging.getLevelName(level.upper())
        if not isinstance(level, int):
            raise ValueError(f"unknown log level {level!r}")
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(logging.Formatter(fmt, datefmt="%H:%M:%S"))
    handler.addFilter(RedactingFilter())
    setattr(handler, _HANDLER_ATTR, True)
    root = logging.getLogger(_ROOT)
    root.addHandler(handler)
    if layers is None:
        root.setLevel(level)
    else:
        root.setLevel(logging.WARNING)
        for layer in layers:
            get_logger(layer).setLevel(level)
    return handler


def disable_debug(handler: logging.Handler | None = None) -> None:
    """Remove handlers added by :func:`enable_debug` and reset levels."""
    root = logging.getLogger(_ROOT)
    for h in list(root.handlers):
        if h is handler or (handler is None and getattr(h, _HANDLER_ATTR, False)):
            root.removeHandler(h)
    root.setLevel(logging.NOTSET)
    for name in list(logging.root.manager.loggerDict):
        if name.startswith(_ROOT + "."):
            logging.getLogger(name).setLevel(logging.NOTSET)


class FrameRecorder:
    """Record every TX/RX buffer passing through a transport.

    Attach with ``transport.recorder = FrameRecorder()``; afterwards
    :attr:`frames` holds ``(direction, bytes)`` tuples in order and
    :meth:`dump` renders them. Useful to turn a field problem into a byte
    fixture for a regression test.

    Directions: ``TX``/``RX`` are the raw transport buffers; ``TX-APDU``/
    ``RX-APDU`` are the plaintext (deciphered) service APDUs added by the
    association, which :mod:`pydlms.replay` serves back. A recording of a
    ciphered session therefore holds meter data in clear: treat the file like
    the readout itself. The plaintext lines add no key material: no keys,
    no HLS pass 3/4, and the AARE without its StoC. The raw AARQ/AARE
    buffers still carry an LLS password or HLS challenge as sent on the wire.
    """

    def __init__(self) -> None:
        self.frames: list[tuple[str, bytes]] = []

    def record(self, direction: str, data: bytes) -> None:
        self.frames.append((direction, bytes(data)))

    def dump(self) -> str:
        lines = ["# pydlms recording v1: TX/RX raw buffers, TX-APDU/RX-APDU plaintext APDUs"]
        return "\n".join(lines + [f"{d} {data.hex()}" for d, data in self.frames])
