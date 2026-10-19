"""Tests for the layer-by-layer explainer (``pydlms decode``)."""

from __future__ import annotations

import pytest

from pydlms.catalog import obis_name
from pydlms.cosem.data import DlmsData
from pydlms.explain import detect_framing, explain, format_data
from pydlms.wrapper import encode_wrapper
from tests.meter_fixtures import load


def test_detect_framing():
    assert detect_framing(b"\x7e\xa0") == "hdlc"
    assert detect_framing(bytes.fromhex("68FAFA68")) == "mbus"
    assert detect_framing(encode_wrapper(1, 16, b"\x0f")) == "wrapper"
    assert detect_framing(b"\xc4\x01") == "apdu"


def test_explain_encrypted_hdlc_gbt_push():
    pytest.importorskip("cryptography")
    fx = load("hdlc_landis_gyr_e450")
    text = explain(fx.raw, fx.encryption_key, fx.authentication_key)
    for needle in [
        "== HDLC frame 1",
        "HCS       EE E1  ok",
        "general-block-transfer block 3 (last)",
        "reassembled 272 octets",
        "SC=0x30 suite 0 auth+enc",
        "tag verified",
        "OBIS 1.0.1.8.0.255 (Active energy import (+A) total)",
        "1.0.1.8.0.255        4408736",
    ]:
        assert needle in text, needle


def test_explain_without_key_shows_header_only():
    fx = load("mbus_netz_noe_p1")
    text = explain(fx.raw)
    assert "M-Bus frame 1" in text and "CI=0x00" in text and "CI=0x11" in text
    assert "SC=0x20 suite 0 enc-only" in text
    assert "no key given" in text


def test_explain_mbus_with_key_and_damage_report():
    pytest.importorskip("cryptography")
    fx = load("mbus_kaifa_ma309m")
    text = explain(fx.raw, fx.encryption_key)
    assert "body damaged" in text
    assert "1.0.32.7.0.255       236.3 V" in text


def test_explain_bad_checksum_and_override():
    fx = load("hdlc_landis_gyr_zmf100")
    assert "dropped" in explain(fx.raw)
    assert "EMBRIQ_V1_1" in explain(fx.raw, verify_checksums=False)


def test_explain_acse_and_services():
    aarq = bytes.fromhex(
        "6036A1090607608574050801018A0207808B0760857405080201AC0A80083132333435363738"
        "BE10040E01000000065F1F0400007E1F04B0"
    )
    text = explain(aarq)
    assert "AARQ" in text and "mechanism: 1" in text and "InitiateRequest" in text
    text = explain(bytes.fromhex("C001C1000300000100 08FF0200".replace(" ", "")))
    assert "GetRequestNormal" in text and "id 1, high priority, confirmed" in text
    text = explain(bytes.fromhex("D80106000004D2"))
    assert "INVOCATION_COUNTER_ERROR" in text


def test_explain_reports_errors_instead_of_raising():
    assert "!!" in explain(b"\xc4\x01")
    assert "!!" in explain(bytes.fromhex("7EA0070321930F027E"))


def test_explain_multiple_buffers_joined_for_segments():
    fx = load("hdlc_iskra550")
    frames = [fx.raw[:166], fx.raw[166:332], fx.raw[332:]]
    text = explain(frames)
    assert "segment; waiting" in text
    assert "84895126" in text


def test_explain_key_specific_needs_system_title():
    pytest.importorskip("cryptography")
    from tests.crypto.vectors import GB_AK, GB_EK, GB_SYSTEM_TITLE

    apdu = bytes.fromhex(
        "C81E300123456741 1312FF935A47566827C467BC7D825C3BE4A77C3FCC056B6B".replace(" ", "")
    )
    assert "pass --system-title" in explain(apdu, GB_EK, GB_AK)
    text = explain(apdu, GB_EK, GB_AK, system_title=GB_SYSTEM_TITLE)
    assert "GetRequestNormal" in text and "0.0.1.0.0.255" in text


def test_format_data_tree():
    lines = format_data(
        DlmsData.structure([DlmsData.octet_string(bytes([1, 0, 32, 7, 0, 255])), DlmsData.enum(35)])
    )
    assert lines[0].strip() == "structure[2]"
    assert "Voltage L1" in lines[1]
    assert "(V)" in lines[2]


def test_catalog():
    assert obis_name("1.0.1.8.0.255") == "Active energy import (+A) total"
    assert obis_name("9.9.9.9.9.9") is None
    assert obis_name(None) is None


def test_explain_general_ciphering_and_signing():
    pytest.importorskip("cryptography")
    from pydlms.security.general import KeyInfo, wrap_general_ciphering, wrap_general_signing
    from tests.crypto.test_general import SERVER, pair
    from tests.crypto.vectors import GB_PLAINTEXT

    client, _ = pair()
    apdu = wrap_general_ciphering(
        client, GB_PLAINTEXT, SERVER, KeyInfo("identified"), transaction_id=b"\x00" * 8
    )
    text = explain(apdu, client.encryption_key, client.authentication_key)
    for needle in [
        "transaction-id",
        "originator",
        "key-info      identified key-id 0",
        "tag verified",
        "GetRequestNormal",
    ]:
        assert needle in text, needle
    agreed = wrap_general_ciphering(client, GB_PLAINTEXT, SERVER, KeyInfo("agreed"))
    assert "agreed key, one-pass Diffie-Hellman, 128 octets" in explain(agreed)
    signed = wrap_general_signing(client, GB_PLAINTEXT, SERVER)
    text = explain(signed)
    assert "signature     64 octets" in text and "GetRequestNormal" in text
    assert "signature     MISSING" in explain(signed[:-65])
