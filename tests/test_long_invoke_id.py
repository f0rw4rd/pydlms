"""Long-Invoke-Id-And-Priority (Data-Notification, ACCESS).

Layout, most significant bit first (Green Book, Long-Invoke-Id-And-Priority;
clause unverified): bit 31 priority (1 = high), bit 30 service class
(1 = confirmed), bit 29 processing option (1 = break-on-error), bit 28
self-descriptive, bits 27..24 reserved, bits 23..0 invoke id. Cross-checked
against dlms-cosem-rs ``data_notification.rs:36-66`` (MIT or Apache-2.0) and
the field masks of the pwitab/dlms-cosem MIT-era ``data_notification.py``.
"""

from __future__ import annotations

import itertools

import pytest

from pydlms.apdu import xdlms
from pydlms.apdu.xdlms import (
    DataNotification,
    LongInvokeIdAndPriority,
    ProcessingOption,
    long_invoke_id,
)
from pydlms.cosem.data import DlmsData
from pydlms.exceptions import DecodeError


@pytest.mark.parametrize(
    "value,high,confirmed,option,selfdesc,reserved,invoke",
    [
        (0xC0000005, True, True, ProcessingOption.CONTINUE_ON_ERROR, False, 0, 5),
        (0x00000000, False, False, ProcessingOption.CONTINUE_ON_ERROR, False, 0, 0),
        (0x80000001, True, False, ProcessingOption.CONTINUE_ON_ERROR, False, 0, 1),
        (0x40000001, False, True, ProcessingOption.CONTINUE_ON_ERROR, False, 0, 1),
        (0x20000001, False, False, ProcessingOption.BREAK_ON_ERROR, False, 0, 1),
        (0x10000001, False, False, ProcessingOption.CONTINUE_ON_ERROR, True, 0, 1),
        (0x0F000001, False, False, ProcessingOption.CONTINUE_ON_ERROR, False, 0xF, 1),
        (0x00FFFFFF, False, False, ProcessingOption.CONTINUE_ON_ERROR, False, 0, 0xFFFFFF),
        (0xFFFFFFFF, True, True, ProcessingOption.BREAK_ON_ERROR, True, 0xF, 0xFFFFFF),
    ],
)
def test_split_known_vectors(value, high, confirmed, option, selfdesc, reserved, invoke):
    fields = LongInvokeIdAndPriority.from_int(value)
    assert fields == LongInvokeIdAndPriority(high, confirmed, option, selfdesc, invoke, reserved)
    assert fields.to_int() == value
    assert fields.to_bytes() == value.to_bytes(4, "big")
    assert LongInvokeIdAndPriority.from_bytes(value.to_bytes(4, "big")) == fields


@pytest.mark.parametrize(
    "high,confirmed,option,selfdesc",
    list(itertools.product((False, True), (False, True), tuple(ProcessingOption), (False, True))),
)
def test_every_flag_combination_round_trips(high, confirmed, option, selfdesc):
    value = long_invoke_id(
        0x123456,
        high_priority=high,
        confirmed=confirmed,
        processing_option=option,
        self_descriptive=selfdesc,
    )
    fields = LongInvokeIdAndPriority.from_int(value)
    assert (fields.high_priority, fields.confirmed, fields.processing_option) == (
        high,
        confirmed,
        option,
    )
    assert fields.self_descriptive is selfdesc
    assert fields.invoke_id == 0x123456
    assert fields.reserved == 0
    assert fields.to_int() == value
    # one flag bit each, nothing leaks into the id
    assert value & 0xFFFFFF == 0x123456


def test_builder_vectors_and_defaults():
    assert long_invoke_id(5) == 0xC0000005
    assert long_invoke_id(5, high_priority=False, confirmed=False) == 5
    assert long_invoke_id(1, processing_option=ProcessingOption.BREAK_ON_ERROR) == 0xE0000001
    assert long_invoke_id(0xFFFFFF, self_descriptive=True) == 0xD0FFFFFF


@pytest.mark.parametrize("bad", [-1, 0x1000000, 1 << 32])
def test_builder_rejects_out_of_range_id(bad):
    with pytest.raises(ValueError):
        long_invoke_id(bad)


@pytest.mark.parametrize("bad", [-1, 1 << 32])
def test_from_int_rejects_out_of_range(bad):
    with pytest.raises(DecodeError):
        LongInvokeIdAndPriority.from_int(bad)


@pytest.mark.parametrize("raw", [b"", b"\xc0", b"\xc0\x00\x00", b"\xc0\x00\x00\x00\x05"])
def test_from_bytes_rejects_wrong_length(raw):
    with pytest.raises(DecodeError):
        LongInvokeIdAndPriority.from_bytes(raw)


def test_data_notification_properties_c0000005():
    note = xdlms.decode_apdu(bytes.fromhex("0F C0000005 00 1101".replace(" ", "")))
    assert isinstance(note, DataNotification)
    assert note.long_invoke_id == 0xC0000005  # raw field stays
    assert note.invoke_id == 5
    assert note.high_priority and note.confirmed
    assert note.processing_option is ProcessingOption.CONTINUE_ON_ERROR
    assert not note.self_descriptive
    assert note.to_bytes() == bytes.fromhex("0FC00000050011 01".replace(" ", ""))


def test_data_notification_built_with_builder():
    note = DataNotification(long_invoke_id(7, confirmed=False), DlmsData.uint8(1))
    raw = note.to_bytes()
    assert raw == bytes.fromhex("0F 80000007 00 1101".replace(" ", ""))
    again = xdlms.decode_apdu(raw)
    assert again.invoke_id == 7 and not again.confirmed and again.high_priority


def test_truncated_data_notification_still_rejected():
    for cut in range(1, 5):
        with pytest.raises(DecodeError):
            xdlms.decode_apdu(bytes.fromhex("0FC0000005")[:cut])
