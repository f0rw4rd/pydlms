"""Security Setup certificate methods 4-8 (IC 64 version 1).

* ``CertificateSelector``: the certificate_identification CHOICE, fixed
  bytes for both alternatives (layout as cB-Sigma 26360a1 and the Gurux
  .NET client build it), round trip and malformed input.
* ``load_certificate_request``: a CSR made by ``cryptography`` passes; every
  byte of its signature BIT STRING tampered, a tampered subject, the wrong
  curve or hash, garbage, and an ECDSA INTEGER without its sign octet (what
  the Gurux server emits) fail.
* ``DlmsClient`` methods end to end against the simulator; exported
  certificates are never installed as ``peer_certificate``.
"""

from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.x509.oid import NameOID

from pydlms.cosem.data import DlmsData, decode_data, encode_data
from pydlms.cosem.interface_classes import ClassId
from pydlms.cosem.model import KeyType
from pydlms.exceptions import AuthenticationError, DecodeError, SecurityError
from pydlms.security import ec
from pydlms.security.certificates import (
    CertificateEntity,
    CertificateSelector,
    CertificateType,
    DlmsCertificate,
    load_certificate_request,
)
from tests.crypto.test_certificates import _usage, make_cert

TITLE = bytes.fromhex("4752580000000001")
SS = "0.0.43.0.0.255"


# --- selector ----------------------------------------------------------------------------


def test_selector_by_entity_bytes():
    sel = CertificateSelector.by_entity_type(
        CertificateEntity.SERVER, CertificateType.DIGITAL_SIGNATURE, TITLE
    )
    assert encode_data(sel.to_data()) == bytes.fromhex("0202160002031600160009084752580000000001")
    assert CertificateSelector.from_data(decode_data(encode_data(sel.to_data()))[0]) == sel


def test_selector_by_serial_bytes():
    serial = bytes.fromhex("02030F5A72")  # DER INTEGER as Gurux lists it in attribute 6
    issuer = bytes.fromhex("300D310B300906035504061302464900")[:-1]
    sel = CertificateSelector.by_serial_issuer(serial, issuer)
    assert encode_data(sel.to_data()) == (
        bytes.fromhex("0202160102020905") + serial + bytes([9, len(issuer)]) + issuer
    )
    assert CertificateSelector.from_data(sel.to_data()) == sel


@pytest.mark.parametrize(
    "data",
    [
        DlmsData.enum(0),
        DlmsData.structure([DlmsData.enum(0)]),
        DlmsData.structure([DlmsData.uint8(0), DlmsData.structure([])]),
        DlmsData.structure([DlmsData.enum(0), DlmsData.octet_string(b"")]),
        DlmsData.structure([DlmsData.enum(0), DlmsData.structure([DlmsData.enum(0)])]),
        DlmsData.structure([DlmsData.enum(1), DlmsData.structure([DlmsData.octet_string(b"")])]),
        DlmsData.structure([DlmsData.enum(2), DlmsData.structure([])]),
    ],
)
def test_selector_malformed(data):
    with pytest.raises(DecodeError):
        CertificateSelector.from_data(data)


def test_selector_arguments_checked():
    with pytest.raises(ValueError):
        CertificateSelector.by_entity_type(0, 0, b"short")
    with pytest.raises(ValueError):
        CertificateSelector.by_serial_issuer(b"", b"x")


# --- certificate request ----------------------------------------------------------------


def make_csr(key, cn: str = TITLE.hex().upper(), algorithm=None):
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .sign(key, algorithm or hashes.SHA256())
    )


KEY = ec.generate_private_key(1)


def _fixed_length_csr() -> bytes:
    """A CSR whose DER signature is 72 octets (both INTEGERs padded), so the
    tamper test below has the same positions on every run."""
    while True:
        csr = make_csr(KEY)
        if len(csr.signature) == 72:
            return csr.public_bytes(serialization.Encoding.DER)


CSR_DER = _fixed_length_csr()


def _signature_span(der: bytes) -> range:
    """Offsets of the signature BIT STRING contents (the last element)."""
    csr = x509.load_der_x509_csr(der)
    signature = csr.signature
    start = der.rindex(signature)
    return range(start, start + len(signature))


def test_csr_accepted_for_its_suite():
    csr = load_certificate_request(CSR_DER, 1)
    assert ec.public_key_bytes(csr.public_key()) == ec.public_key_bytes(KEY)
    pem = make_csr(KEY).public_bytes(serialization.Encoding.PEM)
    assert load_certificate_request(pem, 1).subject == csr.subject
    key2 = ec.generate_private_key(2)
    load_certificate_request(make_csr(key2, algorithm=hashes.SHA384()), 2)


@pytest.mark.parametrize("position", _signature_span(CSR_DER))
def test_tampered_csr_signature_byte_is_rejected(position):
    tampered = bytearray(CSR_DER)
    tampered[position] ^= 0x01
    with pytest.raises((AuthenticationError, DecodeError)):
        load_certificate_request(bytes(tampered), 1)


def test_tampered_csr_subject_is_rejected():
    der = CSR_DER.replace(TITLE.hex().upper().encode(), b"4752580000000002")
    with pytest.raises(AuthenticationError, match="self-signature"):
        load_certificate_request(der, 1)


def test_unpadded_ecdsa_integer_is_rejected():
    """The Gurux server writes r and s without the 00 octet a high bit needs,
    which is not DER; pydlms refuses such a request."""
    while True:
        csr = make_csr(KEY)
        r, s = utils.decode_dss_signature(csr.signature)
        if s >> 255:
            break
    good = csr.signature
    rb = good[4 : 4 + good[3]]
    bad_s = s.to_bytes(32, "big")
    bad = bytes([0x30, 2 + len(rb) + 2 + 32, 0x02, len(rb)]) + rb + bytes([0x02, 32]) + bad_s
    der = csr.public_bytes(serialization.Encoding.DER)
    # rebuild the outer SEQUENCE with the shorter BIT STRING (lengths < 256);
    # the forged request still parses, only its signature is not DER
    tbs = csr.tbs_certrequest_bytes
    header = 2 + (der[1] & 0x7F if der[1] & 0x80 else 0)
    assert der[header : header + len(tbs)] == tbs
    algorithm = der[header + len(tbs) : der.rindex(good) - 3]
    bitstring = bytes([0x03, len(bad) + 1, 0x00]) + bad
    body = tbs + algorithm + bitstring
    forged = bytes([0x30, 0x81, len(body)]) + body
    with pytest.raises(AuthenticationError):
        load_certificate_request(forged, 1)


def test_csr_wrong_curve_hash_or_garbage():
    with pytest.raises(SecurityError, match="curve"):
        load_certificate_request(CSR_DER, 2)
    with pytest.raises(SecurityError, match="signature algorithm"):
        load_certificate_request(make_csr(KEY, algorithm=hashes.SHA384()), 1)
    with pytest.raises(DecodeError):
        load_certificate_request(b"\x30\x03\x02\x01\x00", 1)
    with pytest.raises(SecurityError, match="does not use"):
        load_certificate_request(CSR_DER, 0)


# --- client methods end to end --------------------------------------------------------------


@pytest.fixture
def meter():
    from pydlms.client import DlmsClient
    from pydlms.simulator import ActionFailure, example_meter, serve

    sim = example_meter()
    sim.add_object(
        ClassId.SECURITY_SETUP, SS, {2: DlmsData.enum(0), 3: DlmsData.enum(1)}, version=1
    )
    server_sign = ec.generate_private_key(1)
    store = {"server_sign": server_sign, "certs": [], "calls": []}
    server_cert = make_cert(
        server_sign, common_names=(TITLE.hex().upper(),), key_usage=_usage(True, False)
    )
    store["certs"].append(server_cert)

    def generate(meter, params):
        store["calls"].append(("generate", params.value))
        store["server_sign"] = ec.generate_private_key(1)

    def request(meter, params):
        store["calls"].append(("request", params.value))
        if params.value != KeyType.DIGITAL_SIGNATURE:
            raise ActionFailure(3)
        csr = store.get("csr") or make_csr(store["server_sign"])
        if isinstance(csr, bytes):
            return DlmsData.octet_string(csr)
        return DlmsData.octet_string(csr.public_bytes(serialization.Encoding.DER))

    def import_(meter, params):
        store["certs"].append(x509.load_der_x509_certificate(params.value))

    def export(meter, params):
        sel = CertificateSelector.from_data(params)
        store["calls"].append(("export", sel))
        return DlmsData.octet_string(
            store.get("export") or store["certs"][0].public_bytes(serialization.Encoding.DER)
        )

    def remove(meter, params):
        store["calls"].append(("remove", CertificateSelector.from_data(params)))

    for method, fn in ((4, generate), (5, request), (6, import_), (7, export), (8, remove)):
        sim.add_method(ClassId.SECURITY_SETUP, SS, method, fn)
    server = serve(sim)
    host, port = server.server_address
    store["client"] = lambda **kw: DlmsClient.tcp(host, port, timeout=3, **kw)
    store["sim"] = sim
    yield store
    server.shutdown()
    server.server_close()


def test_generate_key_pair_and_request(meter):
    with meter["client"]() as m:
        m.generate_key_pair(KeyType.DIGITAL_SIGNATURE)
        csr = m.certificate_request(KeyType.DIGITAL_SIGNATURE)
        with pytest.raises(ValueError):
            m.generate_key_pair(7)
    assert ec.public_key_bytes(csr.public_key()) == ec.public_key_bytes(meter["server_sign"])
    assert meter["calls"][:2] == [("generate", 0), ("request", 0)]


def test_certificate_request_rejects_a_bad_signature(meter):
    der = bytearray(make_csr(meter["server_sign"]).public_bytes(serialization.Encoding.DER))
    der[-1] ^= 0x01
    meter["csr"] = bytes(der)
    with meter["client"]() as m:
        with pytest.raises((AuthenticationError, DecodeError)):
            m.certificate_request(KeyType.DIGITAL_SIGNATURE)
        meter["csr"] = make_csr(ec.generate_private_key(2), algorithm=hashes.SHA384())
        with pytest.raises(SecurityError, match="curve"):
            m.certificate_request(KeyType.DIGITAL_SIGNATURE)  # suite 1 read from attr 3


def test_import_export_remove(meter):
    client_key = ec.generate_private_key(1)
    ours = make_cert(client_key, common_names=("50594432434C4E54",), key_usage=_usage(True, False))
    sel = CertificateSelector.by_entity_type(
        CertificateEntity.SERVER, CertificateType.DIGITAL_SIGNATURE, TITLE
    )
    with meter["client"]() as m:
        m.import_certificate(ours)
        m.import_certificate(ours.public_bytes(serialization.Encoding.PEM))
        with pytest.raises(DecodeError):
            m.import_certificate(b"not a certificate")
        cert = m.export_certificate(sel)
        m.remove_certificate(sel)
    assert [c.serial_number for c in meter["certs"][1:]] == [ours.serial_number] * 2
    assert isinstance(cert, DlmsCertificate)
    assert cert.system_title == TITLE
    assert ("export", sel) in meter["calls"] and ("remove", sel) in meter["calls"]


def test_export_is_never_installed_as_peer_certificate():
    """A suite 1 ciphered association: the exported certificate (the meter's
    own) comes back to the caller and the context is left alone."""
    from pydlms.client import DlmsClient
    from pydlms.security.context import SecurityContext
    from pydlms.security.hls import Mechanism
    from pydlms.security.suites import SecuritySuite
    from pydlms.simulator import ClientProfile, example_meter, serve

    ek, ak = bytes(range(16)), bytes(range(16, 32))
    sim = example_meter(encryption_key=ek, authentication_key=ak, system_title=TITLE)
    sim.clients[16] = ClientProfile(Mechanism.NONE, ciphered=True)
    sim.security.suite = SecuritySuite(1)
    sim.add_object(ClassId.SECURITY_SETUP, SS, {2: DlmsData.enum(0)}, version=1)
    cert = make_cert(ec.generate_private_key(1), common_names=(TITLE.hex(),))
    der = cert.public_bytes(serialization.Encoding.DER)
    sim.add_method(ClassId.SECURITY_SETUP, SS, 7, lambda meter, p: DlmsData.octet_string(der))
    security = SecurityContext(ek, ak, client_system_title=b"PYDCLNT1", suite=1)
    server = serve(sim)
    try:
        host, port = server.server_address
        with DlmsClient.tcp(host, port, timeout=3, security=security) as m:
            exported = m.export_certificate(CertificateSelector.by_entity_type(0, 0, TITLE))
    finally:
        server.shutdown()
        server.server_close()
    assert exported.certificate == cert
    assert security.peer_certificate is None and security.peer_signing_key is None


@pytest.mark.parametrize(
    "title,usage,match",
    [
        (bytes.fromhex("4752580000000002"), _usage(True, False), "requested"),
        (TITLE, _usage(False, True), "KeyUsage"),
    ],
)
def test_export_must_match_the_selector(meter, title, usage, match):
    other = make_cert(ec.generate_private_key(1), common_names=(title.hex(),), key_usage=usage)
    meter["export"] = other.public_bytes(serialization.Encoding.DER)
    sel = CertificateSelector.by_entity_type(0, CertificateType.DIGITAL_SIGNATURE, TITLE)
    with meter["client"]() as m:
        with pytest.raises(SecurityError, match=match):
            m.export_certificate(sel)


def test_export_rejects_garbage_and_wrong_curve(meter):
    meter["export"] = b"\x30\x00"
    sel = CertificateSelector.by_serial_issuer(b"\x02\x01\x01", b"\x30\x00")
    with meter["client"]() as m:
        with pytest.raises(DecodeError):
            m.export_certificate(sel)
        key = ec.generate_private_key(2)
        meter["export"] = make_cert(key, common_names=(TITLE.hex(),)).public_bytes(
            serialization.Encoding.DER
        )
        with pytest.raises(SecurityError, match="curve"):
            m.export_certificate(sel)
