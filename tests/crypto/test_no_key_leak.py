"""No key material in repr/str or in any log record."""

from __future__ import annotations

import logging

from pydlms.debug import TRACE, RedactingFilter
from pydlms.security import hls
from pydlms.security.ciphering import unwrap, wrap, wrap_general_glo
from pydlms.security.context import SecurityContext
from tests.crypto.vectors import GB_PLAINTEXT

EK = bytes.fromhex("A1A2A3A4A5A6A7A8A9AAABACADAEAFB0")
AK = bytes.fromhex("B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0")
KEK = bytes.fromhex("C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0")
SECRETS = [EK, AK, KEK]


def _renderings(secret: bytes):
    return [secret.hex(), secret.hex().upper(), secret.hex(" "), repr(secret), str(secret)]


def _assert_clean(text: str):
    for secret in SECRETS:
        for rendering in _renderings(secret):
            assert rendering not in text


def test_repr_and_str_redact_keys():
    ctx = SecurityContext(EK, AK, master_key=KEK, server_system_title=b"SERVER01")
    text = repr(ctx) + str(ctx)
    _assert_clean(text)
    assert "encryption_key=***" in text and "master_key=***" in text


def test_no_key_bytes_in_logs_during_ciphered_exchange(caplog):
    caplog.set_level(TRACE, logger="pydlms")
    client = SecurityContext(
        EK, AK, client_system_title=b"CLIENT01", server_system_title=b"SERVER01"
    )
    server = SecurityContext(
        EK, AK, client_system_title=b"SERVER01", server_system_title=b"CLIENT01"
    )
    for _ in range(3):
        unwrap(server, wrap(client, GB_PLAINTEXT))
        unwrap(client, wrap_general_glo(server, GB_PLAINTEXT))
    hls.hls_gmac(EK, AK, b"CLIENT01", 1, b"challenge-bytes!")
    assert caplog.records, "expected the exchange to log something at TRACE"
    _assert_clean(caplog.text)
    for record in caplog.records:
        _assert_clean(repr(record.args))


def test_redacting_filter_masks_registered_secrets():
    SecurityContext(EK, AK)  # registers the keys
    record = logging.LogRecord(
        "pydlms.x", logging.INFO, __file__, 1, "key is %s", (EK.hex(),), None
    )
    RedactingFilter().filter(record)
    assert record.getMessage() == "key is ***"


def test_trace_shows_every_encrypt_and_decrypt_in_full(caplog):
    """At TRACE each ciphering operation logs the full plaintext and ciphered
    APDU with SC, IC, title and tag verdict - and still no key."""
    caplog.set_level(TRACE, logger="pydlms")
    client = SecurityContext(EK, AK, client_system_title=b"CLIENT01")
    server = SecurityContext(EK, AK, server_system_title=b"CLIENT01")
    long_plaintext = GB_PLAINTEXT + bytes(range(200))  # longer than any old truncation
    apdu = wrap(client, b"\xc0" + long_plaintext[1:])
    unwrap(server, apdu)
    records = [r.getMessage() for r in caplog.records if r.levelno == TRACE]
    encrypts = [m for m in records if m.startswith("encrypt GLO_GET_REQUEST")]
    decrypts = [m for m in records if m.startswith("decrypt GLO_GET_REQUEST")]
    assert len(encrypts) == 1 and len(decrypts) == 1
    assert "[tag verified]" in decrypts[0]
    assert "IC=0" in encrypts[0] and "title=" + b"CLIENT01".hex() in decrypts[0]
    # Full hexdumps: the last plaintext octets (C5..C7) appear in both records.
    assert "C5 C6 C7" in encrypts[0] and "C5 C6 C7" in decrypts[0]
    assert f"ciphered ({len(apdu)} octets)" in encrypts[0]
    _assert_clean("\n".join(records))


def test_failed_tag_is_logged_before_raising(caplog):
    import logging

    import pytest

    from pydlms.exceptions import AuthenticationError

    caplog.set_level(logging.DEBUG, logger="pydlms")
    apdu = bytearray(wrap(SecurityContext(EK, AK, client_system_title=b"CLIENT01"), GB_PLAINTEXT))
    apdu[-1] ^= 1
    with pytest.raises(AuthenticationError):
        unwrap(SecurityContext(EK, AK, server_system_title=b"CLIENT01"), bytes(apdu))
    assert "authentication tag did NOT verify" in caplog.text


def _halves(secret: bytes) -> list[str]:
    """Every 4-octet window of ``secret`` as a hexdump renders it."""
    return [secret[i : i + 4].hex(" ").upper() for i in range(len(secret) - 3)]


def test_dedicated_key_split_across_hexdump_lines_is_masked(caplog):
    """The InitiateRequest plaintext puts the dedicated key at offset 3, so
    the TRACE hexdump (16 octets per line) always splits it; masking the
    rendered lines afterwards could not catch either half."""
    from pydlms.apdu.xdlms import Conformance, InitiateRequest

    caplog.set_level(TRACE, logger="pydlms")
    dedicated = bytes(range(0xD0, 0xE0))
    ctx = SecurityContext(EK, AK, client_system_title=b"CLIENT01")
    ctx.set_dedicated_key(dedicated)
    request = InitiateRequest(
        conformance=Conformance.default_ln(), max_receive_pdu_size=0xFFFF, dedicated_key=dedicated
    ).to_bytes()
    wrap(ctx, request)
    assert "plaintext" in caplog.text
    for window in _halves(dedicated):
        assert window not in caplog.text
    assert "** ** **" in caplog.text


def test_hexdump_and_hexstr_mask_registered_secrets():
    from pydlms.debug import hexdump, hexstr, register_secret

    secret = bytes(range(0x60, 0x70))
    register_secret(secret)
    data = b"\x01\x02\x03" + secret + b"\x04"
    for text in (hexdump(data), hexstr(data)):
        for window in _halves(secret):
            assert window not in text
        assert "01 02 03" in text and "04" in text


def test_association_secret_is_registered():
    """The LLS password / HLS secret is masked like a key."""
    from pydlms.association import Association, AssociationSettings
    from pydlms.debug import hexstr
    from pydlms.security.hls import Mechanism
    from tests.test_association import ScriptedLink

    secret = b"lls-pass-0815"
    Association(ScriptedLink([]), AssociationSettings(mechanism=Mechanism.LLS, secret=secret))
    assert secret.hex(" ").upper() not in hexstr(b"\x80" + secret)


def test_hls_pass_3_4_values_are_not_traced(caplog, monkeypatch):
    """f(StoC) and f(CtoS) travel encrypted in a ciphered association; the
    TRACE of the plaintext APDUs must not undo that."""
    import pydlms.association as association
    from pydlms.client import DlmsClient
    from pydlms.security.hls import Mechanism
    from pydlms.simulator import ClientProfile, example_meter, serve

    seen: list[bytes] = []
    original = association.hash_response

    def recording(mechanism, challenge, secret):
        value = original(mechanism, challenge, secret)
        seen.append(value)
        return value

    monkeypatch.setattr(association, "hash_response", recording)
    secret = b"0123456789ABCDEF"
    meter = example_meter(encryption_key=EK, authentication_key=AK)
    meter.clients[16] = ClientProfile(Mechanism.HLS_SHA1, secret, True)
    server = serve(meter)
    try:
        caplog.set_level(TRACE, logger="pydlms")
        host, port = server.server_address
        security = SecurityContext(EK, AK, client_system_title=b"CLIENT01")
        with DlmsClient.tcp(
            host, port, timeout=3, mechanism=Mechanism.HLS_SHA1, password=secret, security=security
        ) as client:
            client.get_register("1.0.1.8.0.255")
    finally:
        server.shutdown()
        server.server_close()
    assert len(seen) == 2  # f(StoC) sent, f(CtoS) expected
    # The simulator (the meter, in a server thread) logs its own side.
    client_text = "\n".join(r.getMessage() for r in caplog.records if r.threadName == "MainThread")
    assert "APDU TX" in client_text and "plaintext" in client_text
    assert "withheld" in client_text
    for value in seen:
        for window in _halves(value):
            assert window not in client_text
