"""Tests for the debug/trace helpers."""

from __future__ import annotations

import io
import logging

import pytest

from pydlms.debug import (
    TRACE,
    FrameRecorder,
    RedactingFilter,
    disable_debug,
    enable_debug,
    get_logger,
    hexdump,
    hexstr,
    register_secret,
    unregister_secret,
)


def test_hexstr_and_truncation():
    assert hexstr(b"\x01\xab") == "01 AB"
    assert hexstr(bytes(10), 4) == "00 00 00 00 ... (+6 bytes)"


def test_hexdump_layout():
    dump = hexdump(b"ABC\x00" * 5)
    lines = dump.splitlines()
    assert lines[0].startswith("0000  41 42 43 00")
    assert lines[0].endswith("|ABC.ABC.ABC.ABC.|")
    assert lines[1].startswith("0010  ")
    assert hexdump(b"") == "<empty>"


def test_enable_debug_trace_and_layers():
    stream = io.StringIO()
    handler = enable_debug("TRACE", stream=stream)
    try:
        get_logger("hdlc").log(TRACE, "trace line")
        get_logger("security").debug("debug line")
    finally:
        disable_debug(handler)
    text = stream.getvalue()
    assert "TRACE" in text and "trace line" in text and "debug line" in text

    stream = io.StringIO()
    enable_debug(logging.DEBUG, layers=["hdlc"], stream=stream)
    try:
        get_logger("hdlc").debug("wanted")
        get_logger("security").debug("unwanted")
    finally:
        disable_debug()
    assert "wanted" in stream.getvalue() and "unwanted" not in stream.getvalue()


def test_enable_debug_rejects_unknown_level():
    with pytest.raises(ValueError):
        enable_debug("LOUD")


def test_redaction_of_registered_secret():
    secret = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")
    register_secret(secret)
    try:
        stream = io.StringIO()
        enable_debug("DEBUG", stream=stream)
        try:
            get_logger("client").debug("key=%s and %s", secret.hex(), secret.hex(" ").upper())
        finally:
            disable_debug()
        assert secret.hex() not in stream.getvalue()
        assert "key=*** and ***" in stream.getvalue()
    finally:
        unregister_secret(secret)


def test_short_secrets_not_registered():
    register_secret(b"ab")
    record = logging.LogRecord("pydlms", logging.INFO, "", 1, "ab cd", (), None)
    RedactingFilter().filter(record)
    assert record.getMessage() == "ab cd"


def test_frame_recorder_with_transport():
    from pydlms.transports.base import LoopbackTransport

    transport = LoopbackTransport(lambda data: b"\x01\x02")
    transport.recorder = FrameRecorder()
    transport.send(b"\xaa")
    assert transport.recv() == b"\x01\x02"
    assert transport.recorder.frames == [("TX", b"\xaa"), ("RX", b"\x01\x02")]
    assert transport.recorder.dump().splitlines()[1:] == ["TX aa", "RX 0102"]
    assert transport.recorder.dump().startswith("# pydlms recording v1")
