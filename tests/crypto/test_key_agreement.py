"""Security Setup ``key_agreement`` (IC 64 method 3).

Known answer: IEC 62056-5-3:2023 annex I.1 / Table I.1 via cB-Sigma 26360a1
(``vectors.I1_*``): both signed offers verify (the client's only with the
key_id in front), Z and the global unicast key reproduce, and the ACTION
request pydlms builds is the annex's byte for byte with the table
signature in it. End to end, ``DlmsClient.agree_keys`` with the annex's
ephemeral key against a simulator answering with the annex's response
returns the annex's key.

Negative: every byte of the server's key-agreement item tampered, a wrong
length, an off-curve point, an unsolicited or missing key id, the master
key, a different signer.
"""

from __future__ import annotations

import pytest

from pydlms.apdu import xdlms
from pydlms.cosem.data import DlmsData
from pydlms.cosem.interface_classes import ClassId
from pydlms.exceptions import AuthenticationError, DecodeError, KeyMissingError, SecurityError
from pydlms.obis import ObisCode
from pydlms.security import ec, keyagreement
from pydlms.security.keywrap import KeyId
from tests.crypto import vectors as v

SUITE = 1
EK = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
AK = bytes.fromhex("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF")


def _private(value: int):
    from cryptography.hazmat.primitives.asymmetric import ec as cec

    return cec.derive_private_key(value, cec.SECP256R1())


CLIENT_SIGN = _private(v.I2_CLIENT_SIGNING_PRIVATE)
SERVER_SIGN = _private(v.I1_SERVER_SIGNING_PRIVATE)
CLIENT_EPH = _private(v.I1_CLIENT_EPHEMERAL_PRIVATE)
SERVER_EPH = _private(v.I1_SERVER_EPHEMERAL_PRIVATE)
CLIENT_OFFER = v.I1_CLIENT_EPHEMERAL_PUBLIC + v.I1_CLIENT_SIGNATURE
SERVER_OFFER = v.I1_SERVER_EPHEMERAL_PUBLIC + v.I1_SERVER_SIGNATURE


def test_transcribed_key_pairs_are_consistent():
    assert ec.public_key_bytes(CLIENT_SIGN) == v.I2_CLIENT_SIGNING_PUBLIC
    assert ec.public_key_bytes(SERVER_SIGN) == v.I1_SERVER_SIGNING_PUBLIC
    assert ec.public_key_bytes(CLIENT_EPH) == v.I1_CLIENT_EPHEMERAL_PUBLIC
    assert ec.public_key_bytes(SERVER_EPH) == v.I1_SERVER_EPHEMERAL_PUBLIC


def test_client_offer_verifies_with_the_key_id_prefix_only():
    point = keyagreement.open_offer(CLIENT_SIGN.public_key(), SUITE, 0, CLIENT_OFFER)
    assert ec.public_key_bytes(point) == v.I1_CLIENT_EPHEMERAL_PUBLIC
    with pytest.raises(AuthenticationError):  # bare X || Y (the one-pass DH form)
        ec.ecdsa_verify(
            CLIENT_SIGN.public_key(), v.I1_CLIENT_EPHEMERAL_PUBLIC, v.I1_CLIENT_SIGNATURE
        )
    with pytest.raises(AuthenticationError):  # signed for key id 0, not 1
        keyagreement.open_offer(CLIENT_SIGN.public_key(), SUITE, 1, CLIENT_OFFER)


def test_server_offer_z_and_unicast_key():
    peer = keyagreement.open_offer(SERVER_SIGN.public_key(), SUITE, 0, SERVER_OFFER)
    z = ec.ecdh_shared_secret(CLIENT_EPH, peer)
    assert z == v.I1_Z
    assert ec.ecdh_shared_secret(SERVER_EPH, CLIENT_EPH.public_key()) == v.I1_Z
    key = keyagreement.derive_key(SUITE, 0, z, v.I1_CLIENT_TITLE, v.I1_SERVER_TITLE)
    assert key == v.I1_UNICAST_KEY
    # PartyUInfo is the client title: swapping the titles gives another key.
    assert keyagreement.derive_key(SUITE, 0, z, v.I1_SERVER_TITLE, v.I1_CLIENT_TITLE) != key


def test_action_request_reproduces_with_the_table_signature():
    parameter = keyagreement.key_agreement_data({KeyId.GLOBAL_UNICAST_ENCRYPTION: CLIENT_OFFER})
    method = xdlms.MethodDescriptor(ClassId.SECURITY_SETUP, ObisCode.parse("0.0.43.0.0.255"), 3)
    assert xdlms.ActionRequestNormal(0x40, method, parameter).to_bytes() == v.I1_ACTION_REQUEST


def test_agree_reads_the_annex_response():
    response = xdlms.decode_apdu(v.I1_ACTION_RESPONSE)
    keys = keyagreement.agree(
        SUITE,
        {0: CLIENT_EPH},
        SERVER_SIGN.public_key(),
        response.return_data.data,
        v.I1_CLIENT_TITLE,
        v.I1_SERVER_TITLE,
    )
    assert keys == {KeyId.GLOBAL_UNICAST_ENCRYPTION: v.I1_UNICAST_KEY}


@pytest.mark.parametrize("suite", [1, 2])
def test_make_offer_round_trip(suite):
    signer = ec.generate_private_key(suite)
    ephemeral, data = keyagreement.make_offer(signer, suite, KeyId.AUTHENTICATION)
    assert len(data) == {1: 128, 2: 192}[suite]
    peer = keyagreement.open_offer(signer.public_key(), suite, 2, data)
    assert ec.public_key_bytes(peer) == ec.public_key_bytes(ephemeral)
    other = ec.generate_private_key(suite)
    with pytest.raises(AuthenticationError):
        keyagreement.open_offer(other.public_key(), suite, 2, data)


@pytest.mark.parametrize("suite", [1, 2])
def test_both_sides_derive_the_same_keys(suite):
    client, server = ec.generate_private_key(suite), ec.generate_private_key(suite)
    ids = [KeyId.GLOBAL_UNICAST_ENCRYPTION, KeyId.GLOBAL_BROADCAST_ENCRYPTION, KeyId.AUTHENTICATION]
    ephemeral, offers = keyagreement.offers_for(client, suite, ids)
    answer = {}
    server_keys = {}
    for key_id, data in offers.items():
        peer = keyagreement.open_offer(client.public_key(), suite, key_id, data)
        eph, answer[key_id] = keyagreement.make_offer(server, suite, key_id)
        z = ec.ecdh_shared_secret(eph, peer)
        server_keys[key_id] = keyagreement.derive_key(suite, key_id, z, b"CLIENT01", b"SERVER01")
    keys = keyagreement.agree(
        suite,
        ephemeral,
        server.public_key(),
        keyagreement.key_agreement_data(answer),
        b"CLIENT01",
        b"SERVER01",
    )
    assert keys == server_keys
    assert list(keys) == ids
    assert {len(k) for k in keys.values()} == {16 if suite == 1 else 32}


def _answer(data: bytes, key_id: int = 0) -> DlmsData:
    return keyagreement.key_agreement_data({key_id: data})


def _agree(answer, ephemeral=None):
    return keyagreement.agree(
        SUITE,
        ephemeral or {0: CLIENT_EPH},
        SERVER_SIGN.public_key(),
        answer,
        v.I1_CLIENT_TITLE,
        v.I1_SERVER_TITLE,
    )


@pytest.mark.parametrize("position", range(len(SERVER_OFFER)))
def test_tampered_server_offer_byte_is_rejected(position):
    tampered = bytearray(SERVER_OFFER)
    tampered[position] ^= 0x01
    with pytest.raises(AuthenticationError):
        _agree(_answer(bytes(tampered)))


@pytest.mark.parametrize("length", [0, 64, 127, 129, 192])
def test_wrong_length_is_rejected(length):
    data = (SERVER_OFFER * 2)[:length]
    with pytest.raises(AuthenticationError, match="octets"):
        _agree(_answer(data))


def test_off_curve_point_is_rejected_even_when_signed():
    point = v.I1_SERVER_EPHEMERAL_PUBLIC[:-1] + bytes([v.I1_SERVER_EPHEMERAL_PUBLIC[-1] ^ 1])
    signature = ec.ecdsa_sign(SERVER_SIGN, b"\x00" + point)
    with pytest.raises(AuthenticationError, match="curve"):
        _agree(_answer(point + signature))


def test_offer_signed_for_another_key_id_is_rejected():
    signature = ec.ecdsa_sign(SERVER_SIGN, b"\x01" + v.I1_SERVER_EPHEMERAL_PUBLIC)
    with pytest.raises(AuthenticationError):
        _agree(_answer(v.I1_SERVER_EPHEMERAL_PUBLIC + signature))


def test_unsolicited_key_id_is_rejected():
    answer = keyagreement.key_agreement_data({0: SERVER_OFFER, 2: SERVER_OFFER})
    with pytest.raises(SecurityError, match="not offered"):
        _agree(answer)
    with pytest.raises(SecurityError, match="not offered"):
        _agree(_answer(SERVER_OFFER, key_id=1))


def test_missing_key_id_is_rejected():
    with pytest.raises(SecurityError, match="lacks"):
        _agree(_answer(SERVER_OFFER), ephemeral={0: CLIENT_EPH, 1: CLIENT_EPH})
    with pytest.raises(SecurityError, match="lacks"):
        _agree(DlmsData.array([]))


@pytest.mark.parametrize(
    "answer",
    [
        None,
        DlmsData.null(),
        DlmsData.octet_string(SERVER_OFFER),
        DlmsData.array([DlmsData.octet_string(SERVER_OFFER)]),
        DlmsData.array([DlmsData.structure([DlmsData.enum(0)])]),
        DlmsData.array([DlmsData.structure([DlmsData.uint8(0), DlmsData.octet_string(b"")])]),
        DlmsData.array([DlmsData.structure([DlmsData.enum(9), DlmsData.octet_string(b"")])]),
        DlmsData.array(
            [
                DlmsData.structure([DlmsData.enum(0), DlmsData.octet_string(SERVER_OFFER)]),
                DlmsData.structure([DlmsData.enum(0), DlmsData.octet_string(SERVER_OFFER)]),
            ]
        ),
    ],
    ids=["none", "null", "octets", "flat", "short", "not-enum", "unknown-id", "twice"],
)
def test_malformed_answer_is_a_decode_error(answer):
    with pytest.raises(DecodeError):
        _agree(answer)


def test_master_key_and_suite_0_are_refused():
    with pytest.raises(ValueError, match="MASTER"):
        keyagreement.make_offer(CLIENT_SIGN, SUITE, KeyId.MASTER)
    with pytest.raises(ValueError, match="AlgorithmID"):
        ec.algorithm_id(SUITE, 3)
    with pytest.raises(SecurityError, match="suite 1 or 2"):
        keyagreement.make_offer(CLIENT_SIGN, 0, 0)
    with pytest.raises(SecurityError, match="secp384r1"):
        keyagreement.make_offer(CLIENT_SIGN, 2, 0)  # a P-256 key for suite 2
    with pytest.raises(ValueError, match="twice"):
        keyagreement.offers_for(CLIENT_SIGN, SUITE, [0, 0])
    with pytest.raises(ValueError, match="no key ids"):
        keyagreement.offers_for(CLIENT_SIGN, SUITE, [])


def test_algorithm_ids_follow_table_8():
    # Table 8 via cB-Sigma 26360a1: AES-GCM-128 for suite 1, -256 for suite 2.
    for key_id in (None, 0, 1, 2):
        assert ec.algorithm_id(1, key_id) == bytes.fromhex("60857405080300")
        assert ec.algorithm_id(2, key_id) == bytes.fromhex("60857405080301")


# --- DlmsClient.agree_keys end to end ---------------------------------------------------


@pytest.fixture
def annex_meter():
    from pydlms.security.hls import Mechanism
    from pydlms.security.suites import SecuritySuite
    from pydlms.simulator import ClientProfile, example_meter, serve

    sim = example_meter(encryption_key=EK, authentication_key=AK, system_title=v.I1_SERVER_TITLE)
    sim.clients[16] = ClientProfile(Mechanism.NONE, ciphered=True)
    sim.security.suite = SecuritySuite(1)
    sim.add_object(ClassId.SECURITY_SETUP, "0.0.43.0.0.255", {2: DlmsData.enum(0)}, version=1)
    seen = []

    def key_agreement(meter, params):
        # The meter checks our offer as the annex's server would.
        for key_id, data in keyagreement.parse_key_agreement_data(params).items():
            keyagreement.open_offer(CLIENT_SIGN.public_key(), SUITE, key_id, data)
            seen.append((key_id, data))
        return xdlms.decode_apdu(v.I1_ACTION_RESPONSE).return_data.data

    sim.add_method(ClassId.SECURITY_SETUP, "0.0.43.0.0.255", 3, key_agreement)
    server = serve(sim)
    sim.seen = seen
    sim.address = server.server_address
    yield sim
    server.shutdown()
    server.server_close()


def _context(**kw):
    from pydlms.security.context import SecurityContext

    settings = {
        "client_system_title": v.I1_CLIENT_TITLE,
        "suite": 1,
        "signing_key": CLIENT_SIGN,
        "peer_signing_key": SERVER_SIGN.public_key(),
    }
    settings.update(kw)
    return SecurityContext(EK, AK, **settings)


def _client(meter, security):
    from pydlms.client import DlmsClient

    host, port = meter.address
    return DlmsClient.tcp(host, port, timeout=3, security=security)


def test_agree_keys_reproduces_the_annex_key(annex_meter, monkeypatch, caplog):
    from pydlms.debug import TRACE

    monkeypatch.setattr(keyagreement, "_generate_ephemeral", lambda suite: CLIENT_EPH)
    caplog.set_level(TRACE, logger="pydlms")
    security = _context()
    with _client(annex_meter, security) as meter:
        keys = meter.agree_keys([KeyId.GLOBAL_UNICAST_ENCRYPTION])
    assert keys == {KeyId.GLOBAL_UNICAST_ENCRYPTION: v.I1_UNICAST_KEY}
    # The request carried the annex's ephemeral key, signed by our key.
    assert [(k, d[:64]) for k, d in annex_meter.seen] == [(0, v.I1_CLIENT_EPHEMERAL_PUBLIC)]
    # The context is untouched and the key never reaches the log.
    assert security.encryption_key == EK
    assert v.I1_UNICAST_KEY.hex() not in caplog.text.replace(" ", "").lower()
    assert v.I1_Z.hex() not in caplog.text.replace(" ", "").lower()


def test_agree_keys_rejects_another_signer(annex_meter):
    other = ec.generate_private_key(1)
    with _client(annex_meter, _context(peer_signing_key=other.public_key())) as meter:
        with pytest.raises(AuthenticationError):
            meter.agree_keys([0])


def test_agree_keys_rejects_an_unsolicited_key(annex_meter):
    with _client(annex_meter, _context()) as meter:
        with pytest.raises(SecurityError, match="not offered|lacks"):
            meter.agree_keys([KeyId.AUTHENTICATION])


@pytest.mark.parametrize(
    "missing,match",
    [
        ({"signing_key": None}, "signing_key"),
        ({"peer_signing_key": None}, "peer_signing_key"),
        ({"client_system_title": None}, "system titles"),
    ],
)
def test_agree_keys_needs_keys_and_titles_before_sending(annex_meter, missing, match):
    with _client(annex_meter, _context(**missing)) as meter:
        before = len(annex_meter.requests)
        with pytest.raises(KeyMissingError, match=match):
            meter.agree_keys([0])
        assert len(annex_meter.requests) == before


def test_agree_keys_refuses_the_master_key_before_sending(annex_meter):
    with _client(annex_meter, _context()) as meter:
        before = len(annex_meter.requests)
        with pytest.raises(ValueError, match="MASTER"):
            meter.agree_keys([KeyId.MASTER])
        with pytest.raises(ValueError, match="no key ids"):
            meter.agree_keys([])
        assert len(annex_meter.requests) == before
