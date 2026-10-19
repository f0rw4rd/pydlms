"""Build a Gurux template that trusts a test-generated client ECDSA identity.

The shipped Gurux template trusts client certificates whose private keys are
not distributed. For interop tests we generate our own P-256 signing and
key-agreement keys, issue self-signed certificates with the client system
title as CN (the field the Gurux server uses to find a peer's key), and put
them in place of the template's client certificates. The server's own keys
stay as shipped; its public keys are read from the template.
"""

from __future__ import annotations

import base64
import datetime as dt
import re
from dataclasses import dataclass
from pathlib import Path

CLIENT_TITLE = b"GXClient"  # system title the template's ECDSA association expects
SERVER_TITLE = bytes.fromhex("4752580000000001")


@dataclass
class EcdsaIdentity:
    signing_key: object
    agreement_key: object
    server_signing_public: object
    server_agreement_public: object
    template: Path


def _cert(private_key, title: bytes, usage: str):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, title.hex().upper())])
    now = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
    key_usage = x509.KeyUsage(
        digital_signature=usage == "sign",
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=usage == "agree",
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=36500))
        .add_extension(key_usage, critical=False)
        .sign(private_key, hashes.SHA256())
    )


def build(template_text: str, out_dir: Path, ciphered_context: bool = False) -> EcdsaIdentity:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    signing = ec.generate_private_key(ec.SECP256R1())
    agreement = ec.generate_private_key(ec.SECP256R1())
    block_match = re.search(
        r"(<GXDLMSSecuritySetup>\s*<LN>0\.0\.43\.0\.1\.255</LN>.*?</GXDLMSSecuritySetup>)",
        template_text,
        re.S,
    )
    if block_match is None:
        raise ValueError("template has no suite-1 security setup 0.0.43.0.1.255")
    block = block_match.group(1)
    server_signing = serialization.load_der_private_key(
        base64.b64decode(re.search(r"<SigningKey>(.*?)</SigningKey>", block).group(1)), None
    )
    server_agreement = serialization.load_der_private_key(
        base64.b64decode(re.search(r"<KeyAgreement>(.*?)</KeyAgreement>", block).group(1)), None
    )
    kept = []
    for cert_b64 in re.findall(r"<Cert>(.*?)</Cert>", block):
        cert = x509.load_der_x509_certificate(base64.b64decode(cert_b64))
        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        if cn.upper() != CLIENT_TITLE.hex().upper():
            kept.append(cert_b64)  # server certificates stay
    ours = [
        base64.b64encode(
            _cert(key, CLIENT_TITLE, usage).public_bytes(serialization.Encoding.DER)
        ).decode()
        for key, usage in ((signing, "sign"), (agreement, "agree"))
    ]
    certs = "".join(f"<Cert>{c}</Cert>" for c in ours + kept)
    new_block = re.sub(
        r"<ServerCertificates>.*?</ServerCertificates>",
        f"<ServerCertificates>{certs}</ServerCertificates>",
        block,
        flags=re.S,
    )
    text = template_text.replace(block, new_block)
    # The shipped ECDSA association (0.0.40.0.9.255) has an empty object list,
    # and the Gurux server resolves the association's security setup through
    # that list - so as shipped its keys are never loaded and mechanism 7
    # fails for every client. List the security setup and a readable object.
    assoc = re.search(r"<LN>0\.0\.40\.0\.9\.255</LN>.*?<ObjectList />", text, re.S)
    if assoc is None:
        raise ValueError("template has no empty object list for 0.0.40.0.9.255")
    objects = (
        "<ObjectList>"
        "<GXDLMSData><LN>0.0.42.0.0.255</LN><Access>11</Access></GXDLMSData>"
        "<GXDLMSSecuritySetup><LN>0.0.43.0.1.255</LN><Access>133333</Access>"
        "<MethodAccess>00000000</MethodAccess></GXDLMSSecuritySetup>"
        "</ObjectList>"
    )
    text = text[: assoc.end() - len("<ObjectList />")] + objects + text[assoc.end() :]
    if ciphered_context:
        # Declare the suite-1 association as LN with ciphering (context id 3);
        # the Gurux server only protects its responses in ciphered contexts.
        sap = text.index("<ClientSAP>44</ClientSAP>")
        end = text.index("</GXDLMSAssociationLogicalName>", sap)
        part = text[sap:end].replace("<ContextId>1</ContextId>", "<ContextId>3</ContextId>", 1)
        text = text[:sap] + part + text[end:]
    path = out_dir / "ecdsa.xml"
    path.write_text(text, encoding="utf-8")
    path.chmod(0o644)
    return EcdsaIdentity(
        signing, agreement, server_signing.public_key(), server_agreement.public_key(), path
    )
