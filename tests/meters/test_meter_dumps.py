"""End-to-end decoding of real meter pushes.

Every capture vendored from esphome-libs/dlms_parser (Apache-2.0) goes through
the full stack - framing (HDLC / M-Bus / bare), general-block-transfer,
deciphering with the published key, DataNotification, A-XDR, OBIS labelling,
scaler/unit - and the result is compared with upstream's independently
produced expected values (``tests/fixtures/dlms_parser/expected/*.h``).

Where upstream's semantics differ from ours the difference is listed in
``DIVERGENCES`` with the reason, so nothing is skipped silently.
"""

from __future__ import annotations

import pytest

from pydlms.obis import ObisCode
from pydlms.push import PushDecoder, PushRecord
from pydlms.security.context import SecurityContext
from pydlms.security.suites import SecurityPolicy
from tests.meter_fixtures import all_names, load

pytest.importorskip("cryptography")

PROFILES = {
    "mbus_netz_noe_p1": "netz-noe-p1",
    "hdlc_kaifa_ma304h3e": "kaifa-han-no",
}

# Upstream reports these the way its pattern engine sees them; we decode the
# bytes literally. Each entry: obis -> why the values legitimately differ.
DIVERGENCES: dict[str, dict[str, str]] = {
    # Self-descriptive push: upstream reads the capture-object *definitions*
    # as the values (its comments say "scaler=2", which is the attribute
    # index); we map value i to definition i. Our values are pinned in
    # test_energomera_self_descriptive_values instead.
    "raw_energomera": {
        "0.0.25.9.0.255": "definition read as value upstream",
        "0.0.96.5.134.255": "definition read as value upstream",
        "0.0.42.0.0.255": "definition read as value upstream",
        "0.0.96.1.0.255": "definition read as value upstream",
        "0.0.97.98.0.255": "definition read as value upstream",
        "0.0.97.98.10.255": "definition read as value upstream",
        "0.0.96.5.135.255": "definition read as value upstream",
    },
    "raw_egd_example": {
        "0.2.25.9.0.255": "value is an OBIS-valued octet string; upstream prints it as ''",
        "0.0.96.13.0.255": "value is an empty/raw octet string; upstream prints ''",
    },
}

# Captures whose upstream fixture is damaged: we must decode the intact
# prefix, flag the message incomplete, and not invent the rest.
DAMAGED = {
    # Second M-Bus segment carries 47 83 where the SAPs 01 67 belong.
    "mbus_kaifa_ma309m": 9,
    # 06 09 instead of 09 06 for three OBIS codes; the FCS fails too.
    "hdlc_landis_gyr_zmf100": 7,
}


def dlms_parser_datetime(record: PushRecord) -> str:
    """Format a date-time the way upstream prints it (raw deviation sign)."""
    dt = record.datetime
    assert dt is not None
    d, t = dt.date, dt.time
    text = f"{d.year:04d}-{d.month:02d}-{d.day:02d} {t.hour:02d}:{t.minute:02d}:{t.second:02d}"
    if t.hundredths is not None:
        text += f".{t.hundredths:02d}"
    if dt.deviation is not None:
        sign = "-" if dt.deviation < 0 else "+"
        text += f" {sign}{abs(dt.deviation) // 60:02d}:{abs(dt.deviation) % 60:02d}"
    return text


#: SC suite id of captures that do not use suite 0 (seen in the capture:
#: the Kaifa MA309M marks its enc-only pushes 0x21 with a 16-octet key).
SUITES = {"mbus_kaifa_ma309m": 1}


def security_for(fx) -> SecurityContext:
    """The context a user configures for this meter: the published keys, the
    capture's suite, and encryption-only when no authentication key exists."""
    return SecurityContext(
        fx.encryption_key,
        fx.authentication_key,
        suite=SUITES.get(fx.name, 0),
        policy=SecurityPolicy.AUTHENTICATED_ENCRYPTED
        if fx.authentication_key
        else SecurityPolicy.ENCRYPTED,
    )


def decode(name: str):
    fx = load(name)
    security = None
    if fx.encryption_key is not None:
        security = security_for(fx)
    from pydlms.profiles import get_profile

    profile = get_profile(PROFILES[name]) if name in PROFILES else None
    decoder = PushDecoder(
        framing=fx.transport,
        security=security,
        profile=profile,
        verify_checksums=name != "hdlc_landis_gyr_zmf100",
    )
    messages = decoder.feed(fx.raw)
    assert len(messages) == 1, f"{name}: expected one push, got {len(messages)}"
    return fx, messages[0]


def lookup(records: list[PushRecord], key: str) -> PushRecord | None:
    if key == "0.0.0.0.0.0":
        unlabelled = [r for r in records if r.obis is None]
        if unlabelled:
            return unlabelled[0]
        return records[0] if records else None
    wanted = ObisCode.parse(key)
    for record in records:
        if record.obis == wanted:
            return record
    return None


@pytest.mark.parametrize("name", all_names())
def test_meter_push_matches_upstream(name):
    fx, message = decode(name)
    skip = DIVERGENCES.get(name, {})
    if name in DAMAGED:
        assert not message.complete
        assert len(message.records) == DAMAGED[name]
    else:
        assert message.complete
    found = 0
    for key, expected in fx.expected_strings.items():
        if key in skip:
            continue
        record = lookup(message.records, key)
        if record is None and name in DAMAGED:
            continue
        assert record is not None, f"{name}: no record for {key}"
        actual = dlms_parser_datetime(record) if record.datetime is not None else record.text
        assert actual == expected, f"{name} {key}"
        found += 1
    for key, expected in fx.expected_floats.items():
        if key in skip:
            continue
        record = lookup(message.records, key)
        if record is None and name in DAMAGED:
            continue
        assert record is not None, f"{name}: no record for {key}"
        assert record.is_numeric, f"{name} {key}: {record.data}"
        assert record.value == pytest.approx(expected, rel=1e-5, abs=1e-6), f"{name} {key}"
        found += 1
    expected_total = len(fx.expected_strings) + len(fx.expected_floats)
    if name not in DAMAGED:
        assert found == expected_total - len(skip)


def test_every_fixture_is_covered():
    assert len(all_names()) == 16
    from tests.meter_fixtures import DUMPS

    # Every capture has an upstream expected header except the two below;
    # raw_sagecom_xt211.log is upstream's spelling of raw_sagemcom_xt211, and
    # mbus_kmswest has no published key (test_kmswest_is_ciphered_without_key).
    dumps = {p.stem for p in DUMPS.glob("*.log")}
    assert dumps - set(all_names()) == {"raw_sagecom_xt211", "mbus_kmswest"}


def test_authenticated_pushes_report_authentication():
    for name in ("hdlc_landis_gyr_e450", "hdlc_kamstrup_omnipower", "hdlc_lgz_e450_2"):
        _, message = decode(name)
        assert message.authenticated
        assert message.invocation_counter is not None


def test_netz_noe_profile_labels_trailing_meter_number():
    _, message = decode("mbus_netz_noe_p1")
    assert message.get("0.0.96.1.0.255") == "181220000009"
    assert message.get("1.0.32.7.0.255") == pytest.approx(233.7)


def test_kaifa_ma309m_intact_prefix():
    _, message = decode("mbus_kaifa_ma309m")
    assert message.get("1.0.32.7.0.255") == pytest.approx(236.3)
    assert message.system_title == bytes.fromhex("4B464D0000000001")
    assert str(message.timestamp) == "2026-06-05 12:37:45.00 +02:00"


def test_kaifa_han_compact_profile():
    _, message = decode("hdlc_kaifa_ma304h3e")
    assert message.get("0.0.96.1.7.255") == "MA304H3E"
    assert message.get("1.0.1.7.0.255") == 948
    assert message.get("1.0.32.7.0.255") == pytest.approx(238.5)


def test_self_descriptive_push_maps_by_index():
    _, message = decode("hdlc_landis_gyr_e450_cyprus")
    clock = lookup(message.records, "0.0.1.0.0.255")
    assert clock is not None and clock.class_id == 8 and clock.attribute == 2


def test_energomera_self_descriptive_values():
    _, message = decode("raw_energomera")
    assert message.get("0.0.96.5.134.255") == 1
    assert message.get("0.0.42.0.0.255") == "EMR0222173608710"
    assert message.get("0.0.96.1.0.255") == "012415173608710"
    assert message.get("0.0.97.98.0.255") == 16
    assert message.get("0.0.97.98.10.255") == 65535
    # 0.0.96.5.135.255 carries a nested {obis, value} pair; the inner pair is
    # surfaced as its own record (this one agrees with upstream: 3).
    assert message.get("0.0.99.98.4.255") == 3


def test_sagemcom_descriptor_pairs_carry_class_and_attribute():
    _, message = decode("raw_sagemcom_xt211")
    record = lookup(message.records, "1.0.1.8.0.255")
    assert record.class_id == 3 and record.attribute == 2
    assert record.value == 4913794


def test_ciphered_push_needs_a_key():
    from pydlms.exceptions import DlmsError

    fx = load("mbus_netz_noe_p1")
    with pytest.raises(DlmsError, match="SecurityContext"):
        PushDecoder(framing="mbus").feed(fx.raw)


def test_hdlc_split_delivery_byte_by_byte():
    fx = load("hdlc_iskra550")
    decoder = PushDecoder(framing="hdlc")
    messages = []
    for b in fx.raw:
        messages += decoder.feed(bytes([b]))
    assert len(messages) == 1
    assert messages[0].get("1.0.1.8.0.255") == 261927


def test_repeated_capture_rejected_as_replay():
    from pydlms.exceptions import ReplayError

    fx = load("hdlc_landis_gyr_e450")
    decoder = PushDecoder(
        framing="hdlc", security=SecurityContext(fx.encryption_key, fx.authentication_key)
    )
    assert len(decoder.feed(fx.raw)) == 1
    with pytest.raises(ReplayError):
        decoder.feed(fx.raw)


@pytest.mark.parametrize(
    ("name", "clock"),
    [
        ("hdlc_landis_gyr_e450", "2022-02-21 17:37:30"),
        ("hdlc_lgz_e450_2", "2023-11-10 10:58:50"),
    ],
)
def test_lg_e450_cii_profile_labels_leading_clock(name, clock):
    """The IDIS CII push leads with a date-time that carries no OBIS code."""
    from pydlms.profiles import get_profile

    fx = load(name)
    security = SecurityContext(fx.encryption_key, fx.authentication_key)
    bare = PushDecoder(framing="hdlc", security=security).feed(fx.raw)[0]
    assert bare.records[0].obis is None
    security = SecurityContext(fx.encryption_key, fx.authentication_key)
    decoder = PushDecoder(framing="hdlc", security=security, profile=get_profile("lg-e450-cii"))
    message = decoder.feed(fx.raw)[0]
    first = message.records[0]
    assert first.obis == ObisCode.parse("0.0.1.0.0.255")
    assert dlms_parser_datetime(first) == clock
    assert message.get("1.0.1.8.0.255") == bare.get("1.0.1.8.0.255")
    assert [r.obis for r in message.records[1:]] == [r.obis for r in bare.records[1:]]
    assert sum(r.obis is None for r in message.records) == 0


def test_kmswest_is_ciphered_without_key():
    """``mbus_kmswest`` cannot be decoded: it is enciphered and no key exists.

    Upstream publishes the capture with no ``.key`` file and no
    ``expected/*.h``; its own ``mbus_kmswest_decoded.log`` (not vendored)
    stops at "No key provided". Everything below is read from the 99 bytes:

    * ``68 5D 5D 68``: M-Bus long frame, L=93; ``53 FF 10`` = C (SND_UD),
      broadcast address, CI 0x10 (final segment, sequence 0); transport SAPs
      ``01 67`` (client 103, the consumer push SAP); CS ``83``, stop ``16``.
    * ``DB 08 454C536570000001``: general-glo-ciphering with an 8-octet system
      title whose first three octets read "ELS"; ``4D`` = 77 octets follow.
    * ``20``: security control, suite 0, encryption only (no GCM tag), so a
      guessed key cannot be checked cryptographically; ``0000541F`` =
      invocation counter 21535; the remaining 72 octets are ciphertext.
    """
    from pydlms.exceptions import DecodeError, DlmsError
    from pydlms.explain import explain
    from pydlms.mbus import decode_mbus_frame
    from tests.meter_fixtures import DUMPS

    raw = bytes.fromhex((DUMPS / "mbus_kmswest.log").read_text().strip())
    assert len(raw) == 99
    frame = decode_mbus_frame(raw)  # verifies the checksum
    assert (frame.control, frame.address, frame.ci) == (0x53, 0xFF, 0x10)
    assert (frame.stsap, frame.dtsap, frame.final) == (0x01, 0x67, True)
    apdu = frame.data
    assert len(apdu) == 88
    assert apdu[:2] == bytes.fromhex("DB08")
    assert apdu[2:10] == bytes.fromhex("454C536570000001")
    assert apdu[10] == 77 == len(apdu) - 11
    assert apdu[11] == 0x20
    assert int.from_bytes(apdu[12:16], "big") == 21535
    text = explain([raw])
    assert "SC=0x20 suite 0 enc-only" in text
    assert "ciphered content 72 octets" in text
    assert "no key given" in text

    with pytest.raises(DlmsError, match="pass a SecurityContext with the key"):
        PushDecoder(framing="mbus").feed(raw)
    # Without a tag a wrong key is noticed only when the "plaintext" fails to
    # parse as an APDU; it must raise, never yield records.
    with pytest.raises(DecodeError, match="expected DataNotification"):
        PushDecoder(
            framing="mbus", security=SecurityContext(bytes(16), policy=SecurityPolicy.ENCRYPTED)
        ).feed(raw)
