"""Exception hierarchy for pydlms.

Every error the library raises on purpose derives from :class:`DlmsError`.
Decode-side errors additionally derive from :class:`ValueError` so existing
callers that catch ``ValueError`` around the codec keep working.

Meter data is untrusted, so the split matters to callers:

* :class:`DecodeError` / :class:`FramingError` / :class:`ChecksumError`: the
  bytes are malformed; retrying the same bytes will not help.
* :class:`AuthenticationError` / :class:`ReplayError`: the bytes are well-formed
  but failed a security check; they must never be acted upon.
* :class:`ServiceError` / :class:`AssociationError`: the meter answered and
  refused (a result code), so the protocol worked but the request did not.
* :class:`TransportError` / :class:`DlmsTimeoutError`: the link failed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydlms.hdlc.frmr import FrameReject

__all__ = [
    "DlmsError",
    "DecodeError",
    "FramingError",
    "ChecksumError",
    "SecurityError",
    "AuthenticationError",
    "ReplayError",
    "KeyMissingError",
    "CryptoProviderError",
    "AssociationError",
    "ServiceError",
    "InvocationCounterError",
    "ProtocolError",
    "FrameRejectError",
    "LinkLostError",
    "TransportError",
    "DlmsTimeoutError",
]


class DlmsError(Exception):
    """Base class of every error pydlms raises deliberately."""


class DecodeError(DlmsError, ValueError):
    """Bytes could not be decoded as the expected structure."""


class FramingError(DecodeError):
    """A frame (HDLC, wrapper, M-Bus) is malformed or truncated."""


class ChecksumError(FramingError):
    """A frame checksum (HCS/FCS/M-Bus CS) did not verify."""


class SecurityError(DlmsError):
    """Base class of security-layer failures."""


class AuthenticationError(SecurityError):
    """An authentication tag, HLS response or signature failed to verify.

    Raised *instead of* returning any plaintext from an authenticated mode.
    """


class ReplayError(SecurityError):
    """An invocation counter was stale (inbound) or would be reused (outbound)."""


class KeyMissingError(SecurityError):
    """The operation needs key material the security context does not hold."""


class CryptoProviderError(SecurityError):
    """A pluggable crypto provider misbehaved or lacks an operation.

    Raised by the guard around every provider
    (:mod:`pydlms.security.provider`) when an output has the wrong type or
    length (a short tag, a flag instead of plaintext), or when a key needs
    an operation the provider does not implement. Never means "the tag
    did not verify": that is :class:`AuthenticationError`.
    """


class ProtocolError(DlmsError):
    """The peer violated the protocol sequence (unexpected APDU/frame type)."""


class FrameRejectError(ProtocolError):
    """The meter answered with HDLC FRMR (frame reject); the link is down.

    ``reject`` is the decoded :class:`~pydlms.hdlc.frmr.FrameReject`, or
    ``None`` when the information field was too short to read; ``info`` is
    the field as received.
    """

    def __init__(self, message: str, reject: FrameReject | None = None, info: bytes = b""):
        super().__init__(message)
        self.reject = reject
        self.info = info


class LinkLostError(ProtocolError):
    """The link is gone without an answer saying so, e.g. the meter's HDLC
    inactivity time-out has run. The link is DISCONNECTED; nothing was sent
    and nothing reconnects by itself: call ``connect()`` (and associate)
    again."""


class AssociationError(DlmsError):
    """The association (AARQ/AARE, HLS pass 3/4, release) was refused."""

    def __init__(self, message: str, result: object = None, diagnostic: object = None):
        super().__init__(message)
        self.result = result
        self.diagnostic = diagnostic


class InvocationCounterError(AssociationError):
    """The meter refused our invocation counter as stale.

    ``expected`` is the counter the meter reported (continue from
    ``expected + 1``), or ``None`` if it did not say.
    """

    def __init__(self, message: str, expected: int | None = None):
        super().__init__(message)
        self.expected = expected


class ServiceError(DlmsError):
    """A GET/SET/ACTION/READ/WRITE returned a non-success result code."""

    def __init__(self, message: str, result: object = None):
        super().__init__(message)
        self.result = result


class TransportError(DlmsError, OSError):
    """The underlying link (socket, serial port) failed."""


class DlmsTimeoutError(TransportError, TimeoutError):
    """No (complete) answer arrived within the configured timeout."""
