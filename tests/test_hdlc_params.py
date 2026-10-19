"""SNRM/UA information field: user data subfield and max-info layout.

Layout (IEC 62056-46 6.4.4.4.3.2 and ISO/IEC 13239 5.5.3.2.3, both via
cB-Sigma ``hdlc/params.go``, Apache-2.0; the clause text was not read, so
the clause numbers are *unverified*): format identifier ``81``, the HDLC
parameter group ``80 len ...``, then optionally the user data subfield
``FF`` followed by the data with no length octet, always last. The two
maximum information field lengths take one octet each when both fit,
otherwise two octets each. The vectors below are hand-built from that
description, not copied.
"""

from __future__ import annotations

import pytest

from pydlms.exceptions import FramingError
from pydlms.hdlc.connection import (
    HdlcParameters,
    parameter_field,
    parse_parameter_field,
)
from pydlms.hdlc.framing import FrameType, decode_frame
from tests.test_hdlc import FakeMeter, make_link


def _hex(text: str) -> bytes:
    return bytes.fromhex(text.replace(" ", ""))


WINDOWS = "0704 00000001 0804 00000001"

# (parameters, user data, field)
VECTORS = [
    (HdlcParameters(), b"", _hex("818012 0501 80 0601 80 " + WINDOWS)),
    (HdlcParameters(255, 255), b"", _hex("818012 0501 ff 0601 ff " + WINDOWS)),
    # Either length above 255: both on two octets.
    (HdlcParameters(256, 128), b"", _hex("818014 0502 0100 0602 0080 " + WINDOWS)),
    (HdlcParameters(128, 2030), b"", _hex("818014 0502 0080 0602 07ee " + WINDOWS)),
    (HdlcParameters(1024, 1024), b"", _hex("818014 0502 0400 0602 0400 " + WINDOWS)),
    (
        HdlcParameters(128, 128, 7, 3),
        b"",
        _hex("818012 0501 80 0601 80 0704 00000007 0804 00000003"),
    ),
    # User data subfield: FF and the data, no length octet, after the group.
    (HdlcParameters(), b"\x01\x02\x03", _hex("818012 0501 80 0601 80 " + WINDOWS + " ff 010203")),
    (HdlcParameters(), b"\xff", _hex("818012 0501 80 0601 80 " + WINDOWS + " ff ff")),
]


@pytest.mark.parametrize("params,user_data,field", VECTORS)
def test_parameter_field_vectors_round_trip(params, user_data, field):
    assert params.to_bytes(user_data) == field
    assert parameter_field(params, user_data) == field
    assert parse_parameter_field(field) == (params, user_data)
    assert HdlcParameters.from_bytes(field) == params


def test_existing_two_octet_vector_now_round_trips_byte_identically():
    raw = _hex("818014 0502 0400 0602 0400 " + WINDOWS)
    assert HdlcParameters.from_bytes(raw).to_bytes() == raw


def test_default_snrm_field_is_unchanged():
    """The SNRM every existing session sends (and every pinned vector holds)."""
    assert HdlcParameters().to_bytes() == _hex("818012050180060180070400000001080400000001")


def test_user_data_alone():
    assert parameter_field(None, b"\xaa\xbb") == _hex("81 ff aabb")
    assert parse_parameter_field(_hex("81 ff aabb")) == (HdlcParameters(), b"\xaa\xbb")
    # An empty user data subfield is still well formed.
    assert parse_parameter_field(_hex("81 ff")) == (HdlcParameters(), b"")


def test_no_parameters_no_user_data_is_empty():
    assert parameter_field(None) == b""
    assert parse_parameter_field(b"") == (HdlcParameters(), b"")


def test_user_data_never_read_as_a_parameter():
    # FF 05 01 10 is user data, not a max-info-tx of 16.
    params, user_data = parse_parameter_field(_hex("81 ff 050110"))
    assert params == HdlcParameters()
    assert user_data == _hex("050110")


@pytest.mark.parametrize(
    "raw",
    [
        "81",  # format identifier and nothing else
        "8180",  # group without its length
        "818005050180",  # group length beyond the field
        "81800305 0580",  # parameter value beyond the group
        "8180030500",  # zero-length parameter
        "828003050180",  # wrong format identifier
        "81 82 00",  # unknown group
        "818003050180 00",  # trailing octet that is not user data
        "818003050180 8180030501 80",  # a second group
        "818007 05050000000080",  # parameter value longer than 4 octets
    ],
)
def test_malformed_fields_raise(raw):
    with pytest.raises(FramingError):
        parse_parameter_field(_hex(raw))
    with pytest.raises(FramingError):
        HdlcParameters.from_bytes(_hex(raw))


@pytest.mark.parametrize("cut", range(1, 21))
def test_truncated_fields_raise(cut):
    field = HdlcParameters(1024, 1024).to_bytes()
    with pytest.raises(FramingError):
        parse_parameter_field(field[:cut])


def test_out_of_range_lengths_still_rejected_in_two_octet_layout():
    with pytest.raises(FramingError):
        parse_parameter_field(_hex("818004 0502 07ef"))


# --- the link ----------------------------------------------------------------


class UserDataMeter(FakeMeter):
    """Answers SNRM with a UA whose field carries user data."""

    def __init__(self, ua_user_data=b"", **kw):
        super().__init__(**kw)
        self.snrm_fields: list[bytes] = []
        self.ua_user_data = ua_user_data

    def handle(self, f):
        if f.kind == FrameType.SNRM:
            self.snrm_fields.append(f.info)
            self.vs = self.vr = 0
            ua = HdlcParameters(self.max_info, self.max_info).to_bytes(self.ua_user_data)
            return self.frame(FrameType.UA | 0x10, ua)
        return super().handle(f)


def test_link_sends_snrm_user_data_and_exposes_ua_user_data():
    meter = UserDataMeter(ua_user_data=b"\x10\x20")
    link = make_link(meter, snrm_user_data=b"\x01\x02")
    link.connect()
    assert meter.snrm_fields == [HdlcParameters().to_bytes(b"\x01\x02")]
    assert link.ua_user_data == b"\x10\x20"
    assert link.request(b"\xc0\x01\x01") == b"\xc0\x01\x01"


def test_link_snrm_user_data_without_parameters():
    meter = UserDataMeter()
    link = make_link(meter, snrm_user_data=b"\x01", send_snrm_parameters=False)
    link.connect()
    assert meter.snrm_fields == [_hex("81 ff 01")]
    assert link.ua_user_data == b""


def test_link_default_snrm_is_byte_identical():
    meter = UserDataMeter()
    link = make_link(meter)
    link.connect()
    assert meter.snrm_fields == [_hex("818012050180060180070400000001080400000001")]
    assert link.ua_user_data == b""


def test_link_two_octet_proposal_negotiates():
    meter = UserDataMeter(max_info=512)
    link = make_link(meter, parameters=HdlcParameters(1024, 1024))
    link.connect()
    assert meter.snrm_fields == [_hex("818014 0502 0400 0602 0400 " + WINDOWS)]
    assert link.negotiated.max_info_tx == 512
    assert link.request(bytes(1500)) == bytes(1500)


def test_ua_user_data_cleared_on_reconnect():
    meter = UserDataMeter(ua_user_data=b"\x99")
    link = make_link(meter)
    link.connect()
    assert link.ua_user_data == b"\x99"
    meter.ua_user_data = b""
    link.connect()
    assert link.ua_user_data == b""


def test_snrm_frame_with_user_data_decodes():
    """The whole SNRM frame carries the field unchanged (HCS/FCS cover it)."""
    from pydlms.hdlc.address import HdlcAddress
    from pydlms.hdlc.framing import HdlcFrame, encode_frame

    field = HdlcParameters().to_bytes(b"\xde\xad")
    raw = encode_frame(
        HdlcFrame(HdlcAddress.server(1), HdlcAddress.client(16), FrameType.SNRM | 0x10, field)
    )
    assert parse_parameter_field(decode_frame(raw).info) == (HdlcParameters(), b"\xde\xad")
