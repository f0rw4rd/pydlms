"""X.509 certificates for security suites 1 and 2.

Suites 1/2 bind each ECDSA / ECDH public key to a DLMS system title through
an X.509 certificate. This module loads one (PEM or DER) with
``cryptography``, checks that its key is EC on the curve the suite requires
(suite 1 P-256, suite 2 P-384) and exposes the public key and the system
title.

System title: the DLMS certificate profile puts the 8-octet system title in
the subject CommonName as 16 hexadecimal characters (Gurux
``GXx509Certificate`` does the same; consulted as a behavioural reference
only). **Unverified:** not checked against the Green Book clause text; seen
in that one implementation. Upper and lower case hex are accepted; anything
else, an absent CommonName or more than one is rejected.

Only parsing and the checks above happen here. Chain building, validity
period and revocation are the caller's policy; this module does not decide
whether a certificate is trusted.

Security Setup (IC 64 version 1) certificate methods use two more pieces
defined here: :class:`CertificateSelector`, the ``certificate_identification``
parameter of ``export_certificate`` / ``remove_certificate`` (methods 7/8),
and :func:`load_certificate_request` for the PKCS #10 request
``generate_certificate_request`` (method 5) returns.

Sources for the enumerations and the selector layout: cB-Sigma dlms
(Apache-2.0) ``cosem/securitysetup.go`` at 26360a1 and the Gurux .NET
server (GPL, behaviour only, 6f263019), which agree; the Blue Book clause was
not read (*unverified*).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Any

from pydlms.cosem.data import DlmsData
from pydlms.cosem.enums import DataType
from pydlms.exceptions import AuthenticationError, DecodeError, SecurityError
from pydlms.security.suites import SecuritySuite

__all__ = [
    "DlmsCertificate",
    "load_certificate",
    "system_title_from_certificate",
    "CertificateEntity",
    "CertificateType",
    "CertificateSelector",
    "load_certificate_request",
]


class CertificateEntity(IntEnum):
    """Security Setup ``certificate_entity`` (see module doc for sources)."""

    SERVER = 0
    CLIENT = 1
    CERTIFICATION_AUTHORITY = 2
    OTHER = 3


class CertificateType(IntEnum):
    """Security Setup ``certificate_type`` (see module doc for sources)."""

    DIGITAL_SIGNATURE = 0
    KEY_AGREEMENT = 1
    TLS = 2
    OTHER = 3


@dataclass(frozen=True)
class CertificateSelector:
    """``certificate_identification`` of export/remove_certificate::

        structure {
          certificate_identification_type  enum (0 by entity, 1 by serial),
          certificate_identification_options CHOICE {
            structure { certificate_entity enum, certificate_type enum,
                        system_title octet-string },
            structure { serial_number octet-string, issuer octet-string } } }

    Build one with :meth:`by_entity` or :meth:`by_serial`. ``serial_number``
    and ``issuer`` are sent verbatim: give the octet strings the meter
    lists for the certificate in attribute 6 (``certificates``). The Gurux
    server lists and expects the DER INTEGER (``02 len value``) and the DER
    issuer Name; cB-Sigma sends the bare serial octets. Which one the Blue
    Book means is *unverified*, so pydlms does not re-encode.
    """

    by_serial: bool
    entity: CertificateEntity | int | None = None
    certificate_type: CertificateType | int | None = None
    system_title: bytes | None = None
    serial_number: bytes | None = None
    issuer: bytes | None = None

    @classmethod
    def by_entity_type(
        cls,
        entity: CertificateEntity | int,
        certificate_type: CertificateType | int,
        system_title: bytes,
    ) -> CertificateSelector:
        if len(system_title) != 8:
            raise ValueError("system_title must be 8 octets")
        return cls(
            False,
            entity=_enum(CertificateEntity, entity),
            certificate_type=_enum(CertificateType, certificate_type),
            system_title=bytes(system_title),
        )

    @classmethod
    def by_serial_issuer(cls, serial_number: bytes, issuer: bytes) -> CertificateSelector:
        if not serial_number or not issuer:
            raise ValueError("serial_number and issuer must not be empty")
        return cls(True, serial_number=bytes(serial_number), issuer=bytes(issuer))

    def to_data(self) -> DlmsData:
        if self.by_serial:
            option = DlmsData.structure(
                [
                    DlmsData.octet_string(self.serial_number or b""),
                    DlmsData.octet_string(self.issuer or b""),
                ]
            )
        else:
            option = DlmsData.structure(
                [
                    DlmsData.enum(int(self.entity or 0)),
                    DlmsData.enum(int(self.certificate_type or 0)),
                    DlmsData.octet_string(self.system_title or b""),
                ]
            )
        return DlmsData.structure([DlmsData.enum(1 if self.by_serial else 0), option])

    @classmethod
    def from_data(cls, data: DlmsData) -> CertificateSelector:
        """Decode the parameter (strictly: tags and element counts)."""
        if data.tag != DataType.STRUCTURE or len(data.value) != 2:
            raise DecodeError("certificate_identification is not a structure of two")
        kind, option = data.value
        if kind.tag != DataType.ENUM or option.tag != DataType.STRUCTURE:
            raise DecodeError("certificate_identification is not {enum, structure}")
        fields = option.value
        if kind.value == 0:
            tags = [f.tag for f in fields]
            if tags != [DataType.ENUM, DataType.ENUM, DataType.OCTET_STRING]:
                raise DecodeError("certificate_identification_entity has the wrong shape")
            return cls(
                False,
                entity=_enum(CertificateEntity, fields[0].value),
                certificate_type=_enum(CertificateType, fields[1].value),
                system_title=bytes(fields[2].value),
            )
        if kind.value == 1:
            if [f.tag for f in fields] != [DataType.OCTET_STRING, DataType.OCTET_STRING]:
                raise DecodeError("certificate_identification_serial has the wrong shape")
            return cls(True, serial_number=bytes(fields[0].value), issuer=bytes(fields[1].value))
        raise DecodeError(f"unknown certificate_identification_type {kind.value}")


def _enum(kind, value: int):
    try:
        return kind(value)
    except ValueError:
        return int(value)  # a value a newer edition defines is passed through


_CURVE_FOR_SUITE = {
    SecuritySuite.ECDH_ECDSA_AES_GCM_128_SHA256: "secp256r1",
    SecuritySuite.ECDH_ECDSA_AES_GCM_256_SHA384: "secp384r1",
}


@dataclass(frozen=True)
class DlmsCertificate:
    """A parsed certificate: the X.509 object, its EC key and system title."""

    #: ``cryptography.x509.Certificate``
    certificate: Any
    #: ``cryptography`` ``EllipticCurvePublicKey`` (P-256 or P-384)
    public_key: Any
    system_title: bytes
    suite: SecuritySuite

    @property
    def can_sign(self) -> bool:
        """False only when a KeyUsage extension omits digitalSignature."""
        return self._key_usage("digital_signature")

    @property
    def can_agree(self) -> bool:
        """False only when a KeyUsage extension omits keyAgreement."""
        return self._key_usage("key_agreement")

    def _key_usage(self, name: str) -> bool:
        from cryptography import x509

        try:
            usage = self.certificate.extensions.get_extension_for_class(x509.KeyUsage)
        except x509.ExtensionNotFound:
            return True
        return bool(getattr(usage.value, name))

    def __repr__(self) -> str:
        return (
            f"DlmsCertificate(system_title={self.system_title.hex()}, suite={int(self.suite)}, "
            f"serial={self.certificate.serial_number:x})"
        )


def system_title_from_certificate(certificate: Any) -> bytes:
    """The 8-octet system title from the subject CommonName (16 hex chars)."""
    from cryptography.x509.oid import NameOID

    names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not names:
        raise DecodeError("certificate subject has no CommonName (DLMS system title)")
    if len(names) > 1:
        raise DecodeError("certificate subject has more than one CommonName")
    cn = names[0].value
    if isinstance(cn, bytes):
        cn = cn.decode("ascii", "replace")
    if len(cn) != 16 or any(c not in "0123456789abcdefABCDEF" for c in cn):
        raise DecodeError(
            f"certificate CommonName {cn!r} is not a system title (16 hex characters)"
        )
    return bytes.fromhex(cn)


def _parse(data: bytes | str) -> Any:
    from cryptography import x509

    raw = data.encode("ascii") if isinstance(data, str) else bytes(data)
    try:
        if raw.lstrip().startswith(b"-----BEGIN"):
            return x509.load_pem_x509_certificate(raw)
        return x509.load_der_x509_certificate(raw)
    except ValueError as exc:
        raise DecodeError(f"not a PEM or DER X.509 certificate: {exc}") from None


def load_certificate(data: bytes | str | Any, suite: int | None = None) -> DlmsCertificate:
    """Load a certificate and check it is usable for ``suite``.

    ``data`` is PEM (bytes or str), DER bytes or an already parsed
    ``cryptography.x509.Certificate``. Without ``suite`` the suite is taken
    from the curve. Raises :class:`DecodeError` for unparseable data or a
    missing/invalid system title and :class:`SecurityError` for a key that
    is not EC on the suite's curve. Extensions are parsed here too, so a
    malformed one (e.g. an AuthorityKeyIdentifier with an issuer but no
    serial) is a :class:`DecodeError` at load time.
    """
    from cryptography.hazmat.primitives.asymmetric import ec

    certificate = data if hasattr(data, "public_key") else _parse(data)
    try:
        # parsed lazily; read now so can_sign/can_agree cannot fail later
        len(certificate.extensions)
    except ValueError as exc:
        raise DecodeError(f"certificate extensions do not parse: {exc}") from None
    public_key = certificate.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise SecurityError(
            f"certificate key is {type(public_key).__name__}, suites 1/2 need an EC key"
        )
    curve = public_key.curve.name
    if suite is None:
        matches = [s for s, name in _CURVE_FOR_SUITE.items() if name == curve]
        if not matches:
            raise SecurityError(f"certificate curve {curve} belongs to no DLMS security suite")
        resolved = matches[0]
    else:
        resolved = SecuritySuite(suite)
        expected = _CURVE_FOR_SUITE.get(resolved)
        if expected is None:
            raise SecurityError(f"security suite {int(resolved)} does not use certificates")
        if curve != expected:
            raise SecurityError(
                f"certificate curve {curve} does not match suite {int(resolved)} ({expected})"
            )
    return DlmsCertificate(
        certificate=certificate,
        public_key=public_key,
        system_title=system_title_from_certificate(certificate),
        suite=resolved,
    )


_SIGNATURE_FOR_SUITE = {
    SecuritySuite.ECDH_ECDSA_AES_GCM_128_SHA256: "ECDSA_WITH_SHA256",
    SecuritySuite.ECDH_ECDSA_AES_GCM_256_SHA384: "ECDSA_WITH_SHA384",
}


def load_certificate_request(data: bytes | str | Any, suite: int) -> Any:
    """Parse a PKCS #10 request (DER or PEM) and check it for ``suite``.

    Returns the ``cryptography.x509.CertificateSigningRequest`` after
    checking that its key is EC on the suite's curve (:class:`SecurityError`),
    that it is signed with ECDSA and the suite's hash (:class:`SecurityError`)
    and that the self-signature verifies under its own key
    (:class:`AuthenticationError`; a signature that is not valid DER, as
    the Gurux server emits about half of the time, fails here too).
    Unparseable data raises :class:`DecodeError`. A valid self-signature only
    proves possession of the key, not who holds it.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec

    if hasattr(data, "is_signature_valid"):
        request = data
    else:
        raw = data.encode("ascii") if isinstance(data, str) else bytes(data)
        try:
            if raw.lstrip().startswith(b"-----BEGIN"):
                request = x509.load_pem_x509_csr(raw)
            else:
                request = x509.load_der_x509_csr(raw)
        except ValueError as exc:
            raise DecodeError(f"not a PEM or DER certificate request: {exc}") from None
    resolved = SecuritySuite(suite)
    expected = _CURVE_FOR_SUITE.get(resolved)
    if expected is None:
        raise SecurityError(f"security suite {int(resolved)} does not use certificates")
    try:
        public_key = request.public_key()
    except ValueError as exc:
        raise DecodeError(f"certificate request key does not parse: {exc}") from None
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise SecurityError(f"certificate request key is {type(public_key).__name__}, not EC")
    if public_key.curve.name != expected:
        raise SecurityError(
            f"certificate request curve {public_key.curve.name} does not match suite "
            f"{int(resolved)} ({expected})"
        )
    wanted = getattr(x509.oid.SignatureAlgorithmOID, _SIGNATURE_FOR_SUITE[resolved])
    if request.signature_algorithm_oid != wanted:
        raise SecurityError(
            f"certificate request signature algorithm {request.signature_algorithm_oid.dotted_string}"
            f" is not {_SIGNATURE_FOR_SUITE[resolved]}, which suite {int(resolved)} needs"
        )
    try:
        valid = request.is_signature_valid
    except ValueError:
        valid = False
    if not valid:
        raise AuthenticationError("certificate request self-signature does not verify")
    return request
