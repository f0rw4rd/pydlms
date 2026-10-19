"""X.509 certificates for suites 1/2.

Certificates are generated in-test with ``cryptography``'s x509 builder
(self-signed, subject CN = the system title as 16 hex characters).
"""

from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec as cec
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

from pydlms.exceptions import AuthenticationError, DecodeError, KeyMissingError, SecurityError
from pydlms.security import DlmsCertificate, load_certificate
from pydlms.security import ec as dlms_ec
from pydlms.security.certificates import system_title_from_certificate
from pydlms.security.context import SecurityContext
from pydlms.security.general import verify_general_signing, wrap_general_signing
from pydlms.security.suites import SecuritySuite
from tests.crypto.vectors import GB_PLAINTEXT

S1 = SecuritySuite.ECDH_ECDSA_AES_GCM_128_SHA256
S2 = SecuritySuite.ECDH_ECDSA_AES_GCM_256_SHA384
SERVER_TITLE = bytes.fromhex("4D4D4D0000BC614E")
CLIENT_TITLE = b"CLIENT01"
SERVER_CN = SERVER_TITLE.hex().upper()
CURVES = {S1: cec.SECP256R1(), S2: cec.SECP384R1()}


def make_cert(key, common_names=(SERVER_CN,), key_usage=None):
    attributes = [x509.NameAttribute(NameOID.COMMON_NAME, cn) for cn in common_names]
    attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, "pydlms test"))
    name = x509.Name(attributes)
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(0x1234)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
    )
    if key_usage is not None:
        builder = builder.add_extension(key_usage, critical=True)
    algorithm = None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    return builder.sign(key, algorithm)


def _usage(digital_signature: bool, key_agreement: bool) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=digital_signature,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=key_agreement,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )


@pytest.fixture(params=[S1, S2], ids=["suite1", "suite2"])
def suite(request):
    return request.param


@pytest.fixture
def server_key(suite):
    return cec.generate_private_key(CURVES[suite])


@pytest.mark.parametrize("encoding", ["pem", "pem-str", "der", "object"])
def test_load_pem_and_der(suite, server_key, encoding):
    cert = make_cert(server_key)
    pem = cert.public_bytes(serialization.Encoding.PEM)
    data = {
        "pem": pem,
        "pem-str": pem.decode("ascii"),
        "der": cert.public_bytes(serialization.Encoding.DER),
        "object": cert,
    }[encoding]
    loaded = load_certificate(data, suite)
    assert isinstance(loaded, DlmsCertificate)
    assert loaded.system_title == SERVER_TITLE
    assert loaded.suite == suite
    assert dlms_ec.public_key_bytes(loaded.public_key) == dlms_ec.public_key_bytes(server_key)
    assert loaded.can_sign and loaded.can_agree
    # The suite is inferred from the curve when not given.
    assert load_certificate(data).suite == suite
    assert SERVER_TITLE.hex() in repr(loaded)


def test_lowercase_hex_common_name():
    key = cec.generate_private_key(cec.SECP256R1())
    cert = make_cert(key, common_names=(SERVER_TITLE.hex(),))
    assert load_certificate(cert, S1).system_title == SERVER_TITLE


@pytest.mark.parametrize(
    "cert_curve,suite",
    [(cec.SECP384R1(), S1), (cec.SECP256R1(), S2), (cec.SECP521R1(), S2)],
)
def test_wrong_curve_rejected(cert_curve, suite):
    cert = make_cert(cec.generate_private_key(cert_curve))
    with pytest.raises(SecurityError, match="curve"):
        load_certificate(cert, suite)


def test_curve_of_no_suite_rejected():
    cert = make_cert(cec.generate_private_key(cec.SECP521R1()))
    with pytest.raises(SecurityError, match="no DLMS security suite"):
        load_certificate(cert)


def test_suite_0_rejected():
    cert = make_cert(cec.generate_private_key(cec.SECP256R1()))
    with pytest.raises(SecurityError, match="does not use certificates"):
        load_certificate(cert, SecuritySuite.AES_GCM_128)


def test_non_ec_key_rejected():
    cert = make_cert(ed25519.Ed25519PrivateKey.generate())
    with pytest.raises(SecurityError, match="EC key"):
        load_certificate(cert, S1)


@pytest.mark.parametrize(
    "common_names",
    [
        (),  # no CommonName at all
        ("4D4D4D0000BC61",),  # 7 octets
        ("4D4D4D0000BC614E00",),  # 9 octets
        ("4D4D4D0000BC614G",),  # not hex
        ("4D4D4D 0000BC614",),  # space
        ("meter.example",),  # a host name, not a title
        ("4D4D4D0000BC614E", "4D4D4D0000BC614F"),  # ambiguous
    ],
)
def test_missing_or_invalid_common_name_rejected(common_names):
    cert = make_cert(cec.generate_private_key(cec.SECP256R1()), common_names=common_names)
    with pytest.raises(DecodeError):
        load_certificate(cert, S1)
    with pytest.raises(DecodeError):
        system_title_from_certificate(cert)


@pytest.mark.parametrize("data", [b"", b"\x30\x03\x02\x01\x00", b"-----BEGIN CERTIFICATE-----\n"])
def test_garbage_rejected(data):
    with pytest.raises(DecodeError):
        load_certificate(data, S1)


def test_unparseable_extension_is_a_decode_error():
    """An AuthorityKeyIdentifier with an issuer but no serial (RFC 5280
    4.2.1.1 forbids it; the Gurux template server certificates carry one):
    cryptography raises a bare ValueError when the extensions are read, which
    escaped from DlmsCertificate.can_sign. Now load_certificate refuses it."""
    from cryptography.x509.oid import ExtensionOID

    key = dlms_ec.generate_private_key(S1)
    issuer_only = bytes.fromhex("3006" "a104" "a4023000")  # [1] { directoryName: {} }
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, SERVER_CN)])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(5)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.UnrecognizedExtension(ExtensionOID.AUTHORITY_KEY_IDENTIFIER, issuer_only),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    with pytest.raises(DecodeError, match="extensions"):
        load_certificate(der, S1)
    with pytest.raises(DecodeError, match="extensions"):
        SecurityContext(bytes(16), bytes(16), suite=S1, peer_certificate=der)


def _contexts(suite, server_key, client_key, **client_kw):
    n = 32 if suite == S2 else 16
    server = SecurityContext(
        bytes(n),
        bytes(16),
        suite=suite,
        signing_key=server_key,
        certificate=make_cert(server_key),
    )
    client = SecurityContext(
        bytes(n),
        bytes(16),
        client_system_title=CLIENT_TITLE,
        suite=suite,
        signing_key=client_key,
        peer_certificate=make_cert(server_key).public_bytes(serialization.Encoding.DER),
        **client_kw,
    )
    return server, client


def test_end_to_end_general_signing_with_certificate_key(suite, server_key):
    client_key = cec.generate_private_key(CURVES[suite])
    server, client = _contexts(suite, server_key, client_key)
    # Own certificate: the system title comes from it.
    assert server.client_system_title == SERVER_TITLE
    assert server.certificate.system_title == SERVER_TITLE
    # Peer certificate: peer signing key and server title come from it.
    assert client.peer_certificate.system_title == SERVER_TITLE
    assert client.server_system_title == SERVER_TITLE
    assert dlms_ec.public_key_bytes(client.peer_signing_key) == dlms_ec.public_key_bytes(server_key)
    signed = wrap_general_signing(server, GB_PLAINTEXT, CLIENT_TITLE)
    originator, content = verify_general_signing(client, signed)
    assert originator == SERVER_TITLE and content == GB_PLAINTEXT
    # A signature by any other key fails against the certificate's key.
    impostor = SecurityContext(
        bytes(32 if suite == S2 else 16),
        suite=suite,
        client_system_title=SERVER_TITLE,
        signing_key=cec.generate_private_key(CURVES[suite]),
    )
    with pytest.raises(AuthenticationError):
        verify_general_signing(client, wrap_general_signing(impostor, GB_PLAINTEXT, CLIENT_TITLE))


def test_peer_certificate_must_match_explicit_peer_key(suite, server_key):
    other = cec.generate_private_key(CURVES[suite]).public_key()
    with pytest.raises(SecurityError, match="does not match peer_signing_key"):
        _contexts(suite, server_key, None, peer_signing_key=other)
    # The same key given twice is consistent.
    _, client = _contexts(suite, server_key, None, peer_signing_key=server_key.public_key())
    assert client.peer_certificate is not None


def test_peer_certificate_must_match_explicit_server_title(suite, server_key):
    with pytest.raises(SecurityError, match="system title"):
        _contexts(suite, server_key, None, server_system_title=b"OTHER001")
    _, client = _contexts(suite, server_key, None, server_system_title=SERVER_TITLE)
    assert client.server_system_title == SERVER_TITLE


def test_own_certificate_checks(suite, server_key):
    n = 32 if suite == S2 else 16
    cert = make_cert(server_key)
    with pytest.raises(KeyMissingError, match="signing_key"):
        SecurityContext(bytes(n), suite=suite, certificate=cert)
    with pytest.raises(SecurityError, match="does not match signing_key"):
        SecurityContext(
            bytes(n),
            suite=suite,
            signing_key=cec.generate_private_key(CURVES[suite]),
            certificate=cert,
        )
    with pytest.raises(SecurityError, match="system title"):
        SecurityContext(
            bytes(n),
            suite=suite,
            client_system_title=CLIENT_TITLE,
            signing_key=server_key,
            certificate=cert,
        )


def test_certificate_on_suite_0_context_rejected():
    cert = make_cert(cec.generate_private_key(cec.SECP256R1()))
    with pytest.raises(SecurityError, match="suite 0"):
        SecurityContext(bytes(16), peer_certificate=cert)


def test_wrong_curve_for_context_suite_rejected():
    cert = make_cert(cec.generate_private_key(cec.SECP384R1()))
    with pytest.raises(SecurityError, match="curve"):
        SecurityContext(bytes(16), suite=S1, peer_certificate=cert)


def test_key_agreement_only_certificate_rejected_as_signing_key():
    key = cec.generate_private_key(cec.SECP256R1())
    cert = make_cert(key, key_usage=_usage(digital_signature=False, key_agreement=True))
    loaded = load_certificate(cert, S1)
    assert loaded.can_agree and not loaded.can_sign
    with pytest.raises(SecurityError, match="digitalSignature"):
        SecurityContext(bytes(16), suite=S1, peer_certificate=cert)
    signing_only = make_cert(key, key_usage=_usage(digital_signature=True, key_agreement=False))
    assert not load_certificate(signing_only, S1).can_agree


def test_dlms_certificate_object_accepted_and_repr_has_no_keys(server_key, suite):
    n = 32 if suite == S2 else 16
    ek = bytes(range(n))
    loaded = load_certificate(make_cert(server_key), suite)
    ctx = SecurityContext(ek, suite=suite, peer_certificate=loaded)
    assert ctx.peer_certificate.system_title == SERVER_TITLE
    assert ek.hex() not in repr(ctx)
    assert "encryption_key=***" in repr(ctx)


# --- key-agreement certificate ---------------------------------------------------------


def test_peer_agreement_certificate_supplies_key_agreement_key(suite):
    server_ka = cec.generate_private_key(CURVES[suite])
    cert = make_cert(server_ka, key_usage=_usage(False, True))
    ctx = SecurityContext(
        bytes(dlms_key_len(suite)), bytes(16), suite=suite, peer_agreement_certificate=cert
    )
    assert dlms_ec.public_key_bytes(ctx.peer_key_agreement_key) == dlms_ec.public_key_bytes(
        server_ka.public_key()
    )
    assert ctx.server_system_title == SERVER_TITLE
    assert ctx.peer_agreement_certificate.system_title == SERVER_TITLE


def test_peer_agreement_certificate_requires_key_agreement_usage():
    key = cec.generate_private_key(CURVES[S1])
    with pytest.raises(SecurityError, match="keyAgreement"):
        SecurityContext(
            bytes(16),
            bytes(16),
            suite=S1,
            peer_agreement_certificate=make_cert(key, key_usage=_usage(True, False)),
        )


def test_peer_certificates_must_name_the_same_meter():
    sign = cec.generate_private_key(CURVES[S1])
    agree = cec.generate_private_key(CURVES[S1])
    with pytest.raises(SecurityError, match="system title"):
        SecurityContext(
            bytes(16),
            bytes(16),
            suite=S1,
            peer_certificate=make_cert(sign),
            peer_agreement_certificate=make_cert(
                agree, common_names=("4F54484552000001",), key_usage=_usage(False, True)
            ),
        )


def test_peer_agreement_certificate_conflicting_key_rejected():
    agree = cec.generate_private_key(CURVES[S1])
    other = cec.generate_private_key(CURVES[S1])
    with pytest.raises(SecurityError, match="does not match"):
        SecurityContext(
            bytes(16),
            bytes(16),
            suite=S1,
            peer_key_agreement_key=other.public_key(),
            peer_agreement_certificate=make_cert(agree, key_usage=_usage(False, True)),
        )


def test_one_pass_dh_to_a_key_from_an_agreement_certificate():
    from pydlms.security.general import KeyInfo, unwrap_general_ciphering, wrap_general_ciphering

    server_ka = cec.generate_private_key(CURVES[S1])
    client_sign = cec.generate_private_key(CURVES[S1])
    client = SecurityContext(
        bytes(16),
        bytes(16),
        client_system_title=CLIENT_TITLE,
        suite=S1,
        signing_key=client_sign,
        peer_agreement_certificate=make_cert(server_ka, key_usage=_usage(False, True)),
    )
    apdu = wrap_general_ciphering(
        client, GB_PLAINTEXT, client.server_system_title, KeyInfo("agreed")
    )
    server = SecurityContext(
        bytes(16),
        bytes(16),
        client_system_title=SERVER_TITLE,
        suite=S1,
        key_agreement_key=server_ka,
        peer_signing_key=client_sign.public_key(),
    )
    assert unwrap_general_ciphering(server, apdu).plaintext == GB_PLAINTEXT


def dlms_key_len(suite):
    return 16 if suite == S1 else 32
