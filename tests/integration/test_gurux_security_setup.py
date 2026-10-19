"""Security Setup methods (IC 64 v1, methods 1 and 3-8) against the Gurux server.

Suite 1 association of the Gurux template (client SAP 44, ECDSA
authentication, glo ciphering, security setup 0.0.43.0.1.255) with a
test-generated client identity (``gurux_ecdsa.py``); the template's method
access for the security setup is opened (it ships as no access). A fresh
container per test: after a failed method the Gurux server denies further
GETs on the object.

What the Gurux server (6f263019, behaviour only) does, pinned here:

* ``security_activate``: version 1 is read from the view; re-activating the
  current policy works, a weaker one is refused by pydlms before sending.
* ``key_agreement``: always answers object-class-inconsistent. Its handler
  casts the key id it just read to the key data (``GXDLMSSecuritySetup.cs``
  ``InvokeKeyAgreement``), never returns its own signed offer and leaves the
  signature check as a TODO, so no key can be agreed and the planned "agree,
  then reassociate with the agreed key" cannot run against it. The
  agreement itself is pinned by the annex I.1 known answer
  (``tests/crypto/test_key_agreement.py``).
* ``generate_key_pair`` and ``generate_certificate_request`` work, but the
  request's ECDSA signature INTEGERs lack the 00 octet a set high bit needs
  (not DER) about three times in four; pydlms rejects those and accepts the
  well-formed ones.
* ``import_certificate`` and ``export_certificate`` (by entity, and by the
  serial and issuer attribute 6 lists) work for a certificate we import.
  The template's own server certificates carry an AuthorityKeyIdentifier
  with an issuer but no serial, which RFC 5280 4.2.1.1 forbids;
  ``cryptography`` refuses its extensions, so pydlms raises DecodeError.
* ``remove_certificate`` fails for both selector forms (its handler reads a
  fourth element of the three-element entity structure and decodes the
  serial differently from how it lists it).
"""

from __future__ import annotations

import shutil
import subprocess
import time

import pytest

x509 = pytest.importorskip("cryptography.x509")

from pydlms.client import DlmsClient
from pydlms.cosem.interface_classes import ClassId
from pydlms.cosem.model import KeyType
from pydlms.exceptions import AuthenticationError, DecodeError, SecurityError, ServiceError
from pydlms.security.hls import Mechanism
from tests.docker_ready import wait_listening

pytestmark = pytest.mark.integration
IMAGE = "pydlms-gurux-sim"
EK = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
AK = bytes.fromhex("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF")
SS = "0.0.43.0.1.255"
SERVER_TITLE = bytes.fromhex("4752580000000001")


def _docker(*args: str) -> str:
    return subprocess.run(  # noqa: S603,S607
        ["docker", *args], check=True, capture_output=True, text=True, timeout=120
    ).stdout.strip()


@pytest.fixture
def gurux(tmp_path):
    pytest.importorskip("cryptography")
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    try:
        _docker("image", "inspect", IMAGE)
    except subprocess.CalledProcessError:
        pytest.skip(f"image {IMAGE} missing: docker build -t {IMAGE} tests/integration/gurux")
    from tests.integration.gurux_ecdsa import build

    template = _docker(
        "run",
        "--rm",
        "--entrypoint",
        "cat",
        IMAGE,
        "/templates/GMacWithAuthenticationEncyption.xml",
    )
    tmp_path.chmod(0o755)
    ident = build(template, tmp_path, ciphered_context=True)
    text = ident.template.read_text(encoding="utf-8")
    ident.template.write_text(
        text.replace(
            "<MethodAccess>00000000</MethodAccess>", "<MethodAccess>11111111</MethodAccess>"
        ),
        encoding="utf-8",
    )
    cid = _docker(
        "run",
        "-d",
        "--rm",
        "-p",
        "127.0.0.1::4060",
        "-v",
        f"{tmp_path}:/custom:ro",
        "-e",
        "SIM_TEMPLATE=/custom/ecdsa.xml",
        IMAGE,
    )
    try:
        port = int(_docker("port", cid, "4060").splitlines()[0].rsplit(":", 1)[1])
        for _ in range(180):
            logs = subprocess.run(  # noqa: S603,S607
                ["docker", "logs", cid], capture_output=True, text=True
            ).stdout
            if "simulator start in" in logs:
                break
            time.sleep(0.5)
        wait_listening(port, "Gurux simulator")
        yield ident, port
    finally:
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True)  # noqa: S603,S607


def _client(ident, port) -> tuple[DlmsClient, object]:
    from pydlms.security.context import SecurityContext
    from tests.integration.gurux_ecdsa import CLIENT_TITLE

    security = SecurityContext(
        EK,
        AK,
        client_system_title=CLIENT_TITLE,
        suite=1,
        invocation_counter=1000,
        signing_key=ident.signing_key,
        peer_signing_key=ident.server_signing_public,
    )
    client = DlmsClient.tcp(
        "127.0.0.1",
        port,
        client_sap=44,
        mechanism=Mechanism.HLS_ECDSA,
        signing_key=ident.signing_key,
        server_public_key=ident.server_signing_public,
        client_system_title=CLIENT_TITLE,
        timeout=15,
        security=security,
        protection="glo",
    )
    return client, security


def test_security_activate_version_from_view(gurux):
    ident, port = gurux
    client, _ = _client(ident, port)
    with client as m:
        assert m.get(SS, ClassId.SECURITY_SETUP, 2).value == 0xFC
        with pytest.raises(SecurityError, match="weaken"):
            m.security_activate(0x0C, security_setup=SS, refuse_weakening=True)
        m.security_activate(0xFC, security_setup=SS, refuse_weakening=True)
        assert m.get(SS, ClassId.SECURITY_SETUP, 2).value == 0xFC


def test_key_agreement_refused_by_gurux(gurux):
    ident, port = gurux
    client, security = _client(ident, port)
    with client as m:
        with pytest.raises(ServiceError, match="OBJECT_CLASS_INCONSISTENT"):
            m.agree_keys([0], security_setup=SS)
    assert security.encryption_key == EK


def test_certificate_request(gurux):
    from pydlms.security import ec

    ident, port = gurux
    client, _ = _client(ident, port)
    with client as m:
        m.generate_key_pair(KeyType.DIGITAL_SIGNATURE, security_setup=SS)
        accepted, rejected = None, 0
        for _ in range(40):
            try:
                accepted = m.certificate_request(KeyType.DIGITAL_SIGNATURE, security_setup=SS)
                break
            except AuthenticationError:
                rejected += 1  # non-DER ECDSA INTEGER, see the module doc
        assert accepted is not None, f"{rejected} requests, none with a DER signature"
    subject = accepted.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    assert subject == SERVER_TITLE.hex().upper()
    # the key pair generated above, not the template's
    assert ec.public_key_bytes(accepted.public_key()) != ec.public_key_bytes(
        ident.server_signing_public
    )


def test_import_export_and_remove(gurux):
    from pydlms.security import ec
    from pydlms.security.certificates import (
        CertificateEntity,
        CertificateSelector,
        CertificateType,
    )
    from tests.integration.gurux_ecdsa import _cert

    ident, port = gurux
    client, security = _client(ident, port)
    ours = _cert(ec.generate_private_key(1), b"PYDLMS01", "sign")
    with client as m:
        m.import_certificate(ours, security_setup=SS)
        by_entity = CertificateSelector.by_entity_type(
            CertificateEntity.CLIENT, CertificateType.DIGITAL_SIGNATURE, b"PYDLMS01"
        )
        assert m.export_certificate(by_entity, security_setup=SS).certificate == ours
        entry = next(
            e.value
            for e in m.get(SS, ClassId.SECURITY_SETUP, 6).value
            if int.from_bytes(e.value[2].value[2:], "big") == ours.serial_number
        )
        by_serial = CertificateSelector.by_serial_issuer(entry[2].value, entry[3].value)
        assert m.export_certificate(by_serial, security_setup=SS).certificate == ours
        # The template's own server certificate has an AuthorityKeyIdentifier
        # with an issuer but no serial (RFC 5280 4.2.1.1): refused.
        server = CertificateSelector.by_entity_type(
            CertificateEntity.SERVER, CertificateType.DIGITAL_SIGNATURE, SERVER_TITLE
        )
        with pytest.raises(DecodeError, match="extensions"):
            m.export_certificate(server, security_setup=SS)
        with pytest.raises(ServiceError, match="OBJECT_CLASS_INCONSISTENT"):
            m.remove_certificate(by_entity, security_setup=SS)
    assert security.peer_certificate is None
