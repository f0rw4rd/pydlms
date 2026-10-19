"""Security context: keys, system titles and invocation counters.

:class:`SecurityContext` owns everything the ciphering layer needs and
enforces the counter policy:

* **Outbound**: :meth:`next_invocation_counter` hands out strictly increasing
  values and refuses to wrap or repeat, so an ``(EK, IV)`` pair can never be
  used twice by construction.
* **Inbound**: :meth:`check_inbound_counter` rejects a counter that is not
  strictly greater than the last accepted one *for that peer system title
  and key* (``"unicast"``, ``"broadcast"``, ``"dedicated"``, and the
  general-ciphering ``"wrapped"``/``"agreed"`` content keys). An IV only has
  to be unique per key, so a meter may count each key on its own; a new
  dedicated key starts a new counter.
  The check is on by default; turning it off (``replay_protection=False``) is
  for offline analysis of captures only, and is logged. Only a counter whose
  APDU was authenticated (tag verified) is stored: an unauthenticated one
  (encryption-only, or tag not verified) is checked but never advances the
  store, else a forged APDU with a huge counter would make every genuine
  APDU after it look stale. The price: under an encryption-only policy a
  replayed APDU is caught only while an authenticated one has advanced the
  store; enc-only counters are not authenticated, so they cannot do better.

general-ciphering AAD and general-signing signed data have two readings in
the field. ``general_aad`` and
``signing_form`` pick one per context, used both ways; the defaults are the
Gurux forms and a non-default one is logged as a WARNING at construction.

Key material never appears in ``repr``/``str`` and is registered with the
debug :class:`~pydlms.debug.RedactingFilter`.

Every key field may hold a key reference of ``provider`` (a
:class:`~pydlms.security.provider.CryptoProvider`, default
:class:`~pydlms.security.provider.SoftwareProvider` with raw bytes): an
HSM or KMS handle keeps the key bytes out of this process. Raw keys are
length-checked here; a handle's length is the provider's business. The
counter, replay and policy checks below are the same either way.

Suites 1/2 can take X.509 certificates (:mod:`pydlms.security.certificates`):
``peer_certificate`` supplies ``peer_signing_key`` and the server system
title, ``certificate`` is checked against ``signing_key`` and supplies the
client system title, ``peer_agreement_certificate`` (KeyUsage
keyAgreement) supplies ``peer_key_agreement_key``. A certificate that
disagrees with an explicitly given key or title, or with the other peer
certificate's title, raises :class:`~pydlms.exceptions.SecurityError`.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from collections.abc import Callable

from pydlms.debug import get_logger, register_secret
from pydlms.exceptions import KeyMissingError, ReplayError, SecurityError
from pydlms.security.general import GeneralAad, SigningForm
from pydlms.security.provider import SoftwareProvider, is_raw_key, resolve
from pydlms.security.suites import SecurityPolicy, SecuritySuite, key_length

__all__ = ["SecurityContext"]

log = get_logger("security")

_SECRET_FIELDS = (
    "encryption_key",
    "authentication_key",
    "broadcast_key",
    "master_key",
    "dedicated_key",
)


class SecurityContext:
    """Keys and counters of one client/server security relationship."""

    #: How many verified general-signing APDUs with plain content (no
    #: invocation counter) are remembered to refuse exact replays. Older
    #: ones, and ones verified by another context (an earlier session), are
    #: not detected: that needs a transaction-id or date-time the signer
    #: binds, which pydlms does not yet require.
    signed_replay_window = 1024

    def __init__(
        self,
        encryption_key: bytes | None = None,
        authentication_key: bytes | None = None,
        client_system_title: bytes | None = None,
        server_system_title: bytes | None = None,
        invocation_counter: int = 0,
        suite: int = SecuritySuite.AES_GCM_128,
        policy: SecurityPolicy = SecurityPolicy.AUTHENTICATED_ENCRYPTED,
        broadcast_key: bytes | None = None,
        master_key: bytes | None = None,
        replay_protection: bool = True,
        allow_unverified_auth: bool = False,
        signing_key=None,
        key_agreement_key=None,
        peer_signing_key=None,
        peer_key_agreement_key=None,
        certificate=None,
        peer_certificate=None,
        peer_agreement_certificate=None,
        general_aad: GeneralAad | str = GeneralAad.SC_AK,
        signing_form: SigningForm | str = SigningForm.CONTENT,
        decompressor: Callable[[bytes], bytes] | None = None,
        provider=None,
    ) -> None:
        self.suite = SecuritySuite(suite)
        #: The :class:`~pydlms.security.provider.CryptoProvider` the key
        #: fields are references of.
        self.provider = provider if provider is not None else SoftwareProvider()
        resolve(self.provider)  # refuse a non-provider now, not at first use
        expected = key_length(self.suite)
        for name, key in (
            ("encryption_key", encryption_key),
            ("broadcast_key", broadcast_key),
            ("master_key", master_key),
        ):
            if is_raw_key(key) and len(key) != expected:
                raise ValueError(f"{name} must be {expected} octets for suite {self.suite}")
        if is_raw_key(authentication_key) and len(authentication_key) not in (16, 32):
            raise ValueError("authentication_key must be 16 or 32 octets")
        client_title_given = client_system_title is not None
        if client_system_title is None:
            client_system_title = b"\x00" * 8
        if len(client_system_title) != 8:
            raise ValueError("client system title must be 8 octets")
        if server_system_title is not None and len(server_system_title) != 8:
            raise ValueError("server system title must be 8 octets")
        self.encryption_key = encryption_key
        self.authentication_key = authentication_key
        self.broadcast_key = broadcast_key
        self.master_key = master_key
        self.dedicated_key = None
        self.client_system_title = bytes(client_system_title)
        #: Whether our own title was configured (not the all-zero default),
        #: so a general-ciphering recipient can be checked against it.
        self.own_title_known = client_title_given
        self.server_system_title = server_system_title
        #: Whether the meter's title was configured (here or by a peer
        #: certificate) rather than learnt from an AARE. A configured title
        #: pins the meter: an association refuses an AARE from another one
        #: and never overwrites it.
        self.peer_title_pinned = server_system_title is not None
        self.policy = SecurityPolicy(policy)
        self.replay_protection = replay_protection
        #: Suites 1/2: own ECDSA signing and ECDH key-agreement private keys,
        #: and the peer's public keys (cryptography EC key objects).
        self.signing_key = signing_key
        self.key_agreement_key = key_agreement_key
        self.peer_signing_key = peer_signing_key
        self.peer_key_agreement_key = peer_key_agreement_key
        self.allow_unverified_auth = allow_unverified_auth
        #: general-ciphering AAD and general-signing signed data: exactly one
        #: form each, outbound and inbound (never a fallback to the other).
        self.general_aad = GeneralAad(general_aad)
        self.signing_form = SigningForm(signing_form)
        if decompressor is not None and not callable(decompressor):
            raise TypeError("decompressor must be a callable taking and returning bytes")
        #: Opt-in hook for SC bit 7 (compressed APDUs): called with the
        #: protected data only after its tag verified, for suites 1/2 in a
        #: general-glo/-ded/-ciphering envelope (see
        #: :mod:`pydlms.security.ciphering`). None (the default) refuses bit 7.
        self.decompressor = decompressor
        #: Own and peer :class:`~pydlms.security.certificates.DlmsCertificate`.
        self.certificate = None
        self.peer_certificate = None
        self.peer_agreement_certificate = None
        if certificate is not None:
            self._apply_certificate(certificate, own=True, title_given=client_title_given)
        if peer_certificate is not None:
            self._apply_certificate(
                peer_certificate, own=False, title_given=server_system_title is not None
            )
        if peer_agreement_certificate is not None:
            self._apply_agreement_certificate(peer_agreement_certificate)
        self._next_ic = invocation_counter
        self._ic_exhausted = False
        self._last_inbound: dict[tuple[bytes, str], int] = {}
        self._signed_seen: OrderedDict[bytes, None] = OrderedDict()
        self._lock = threading.Lock()
        for name in _SECRET_FIELDS:
            register_secret(getattr(self, name))
        if not replay_protection:
            log.warning("inbound replay protection is DISABLED for this security context")
        if self.general_aad is not GeneralAad.SC_AK:
            log.warning(
                "general-ciphering AAD is %s (cB-Sigma reading, no standard example "
                "verifies it); peers using SC || AK fail closed",
                self.general_aad.value,
            )
        if self.signing_form is not SigningForm.CONTENT:
            log.warning(
                "general-signing signed data is %s (cB-Sigma reading, no standard example "
                "verifies it); peers signing the bare content fail closed",
                self.signing_form.value,
            )

    # -- certificates ------------------------------------------------------------
    def _apply_certificate(self, certificate, own: bool, title_given: bool) -> None:
        from pydlms.security.certificates import DlmsCertificate, load_certificate
        from pydlms.security.ec import public_key_bytes

        who = "certificate" if own else "peer_certificate"
        if self.suite == SecuritySuite.AES_GCM_128:
            raise SecurityError(f"{who}: security suite 0 does not use certificates")
        if isinstance(certificate, DlmsCertificate):
            certificate = certificate.certificate
        cert = load_certificate(certificate, self.suite)
        if not cert.can_sign:
            raise SecurityError(f"{who}: KeyUsage does not allow digitalSignature")
        key_name = "signing_key" if own else "peer_signing_key"
        key = getattr(self, key_name)
        if key is None:
            if own:
                raise KeyMissingError("certificate given without the matching signing_key")
            self.peer_signing_key = cert.public_key
        elif public_key_bytes(self._public_of(key)) != public_key_bytes(cert.public_key):
            raise SecurityError(f"{who} public key does not match {key_name}")
        title_name = "client_system_title" if own else "server_system_title"
        if title_given and getattr(self, title_name) != cert.system_title:
            raise SecurityError(
                f"{who} system title {cert.system_title.hex()} does not match "
                f"{title_name} {getattr(self, title_name).hex()}"
            )
        setattr(self, title_name, cert.system_title)
        if own:
            self.own_title_known = True
            self.certificate = cert
        else:
            self.peer_title_pinned = True
            self.peer_certificate = cert

    def _public_of(self, key):
        """A key object ``public_key_bytes`` takes: software keys as they are,
        a provider handle through ``provider.public_key`` (a provider without
        it fails closed with :class:`~pydlms.exceptions.CryptoProviderError`)."""
        if hasattr(key, "public_numbers") or hasattr(key, "private_numbers"):
            return key
        return resolve(self.provider).public_key(key)

    def _apply_agreement_certificate(self, certificate) -> None:
        from pydlms.security.certificates import DlmsCertificate, load_certificate
        from pydlms.security.ec import public_key_bytes

        who = "peer_agreement_certificate"
        if self.suite == SecuritySuite.AES_GCM_128:
            raise SecurityError(f"{who}: security suite 0 does not use certificates")
        if isinstance(certificate, DlmsCertificate):
            certificate = certificate.certificate
        cert = load_certificate(certificate, self.suite)
        if not cert.can_agree:
            raise SecurityError(f"{who}: KeyUsage does not allow keyAgreement")
        key = self.peer_key_agreement_key
        if key is None:
            self.peer_key_agreement_key = cert.public_key
        elif public_key_bytes(key) != public_key_bytes(cert.public_key):
            raise SecurityError(f"{who} public key does not match peer_key_agreement_key")
        if self.server_system_title is not None and self.server_system_title != cert.system_title:
            raise SecurityError(
                f"{who} system title {cert.system_title.hex()} does not match "
                f"server_system_title {self.server_system_title.hex()}"
            )
        self.server_system_title = cert.system_title
        self.peer_title_pinned = True
        self.peer_agreement_certificate = cert

    # -- redaction -------------------------------------------------------------
    def __repr__(self) -> str:
        held = [n for n in _SECRET_FIELDS if getattr(self, n) is not None]
        return (
            f"SecurityContext(suite={int(self.suite)}, policy={self.policy.name}, "
            f"client_system_title={self.client_system_title.hex()}, "
            f"server_system_title={self.server_system_title.hex() if self.server_system_title else None}, "
            f"invocation_counter={self._next_ic}, keys=[{', '.join(f'{n}=***' for n in held)}]"
            f"{self._forms_repr()}{self._provider_repr()})"
        )

    def _provider_repr(self) -> str:
        # The provider's type only: its own repr could show handles.
        if type(self.provider) is SoftwareProvider:
            return ""
        return f", provider={type(self.provider).__name__}"

    def _forms_repr(self) -> str:
        parts = []
        if self.general_aad is not GeneralAad.SC_AK:
            parts.append(f", general_aad={self.general_aad.value}")
        if self.signing_form is not SigningForm.CONTENT:
            parts.append(f", signing_form={self.signing_form.value}")
        return "".join(parts)

    __str__ = __repr__

    def set_dedicated_key(self, key) -> None:
        if is_raw_key(key) and len(key) != key_length(self.suite):
            raise ValueError("dedicated key length does not match the suite")
        self.dedicated_key = key
        register_secret(key)
        with self._lock:  # a new key, a new counter
            for entry in [e for e in self._last_inbound if e[1] == "dedicated"]:
                del self._last_inbound[entry]

    # -- key lookup --------------------------------------------------------------
    def require_encryption_key(self, broadcast: bool = False, dedicated: bool = False):
        """The key reference (raw bytes, or a provider handle)."""
        key = (
            self.dedicated_key
            if dedicated
            else (self.broadcast_key if broadcast else self.encryption_key)
        )
        if key is None:
            which = "dedicated" if dedicated else ("broadcast" if broadcast else "global unicast")
            raise KeyMissingError(f"no {which} encryption key in the security context")
        return key

    def require_authentication_key(self):
        if self.authentication_key is None:
            raise KeyMissingError("no authentication key in the security context")
        return self.authentication_key

    # -- invocation counters -------------------------------------------------------
    @property
    def invocation_counter(self) -> int:
        """The next outbound invocation counter (not yet used)."""
        return self._next_ic

    def next_invocation_counter(self) -> int:
        """Reserve and return the next outbound IC; never repeats."""
        with self._lock:
            if self._ic_exhausted:
                raise ReplayError("invocation counter exhausted; the key must be renewed")
            ic = self._next_ic
            if ic > 0xFFFFFFFF:
                raise ReplayError("invocation counter exhausted; the key must be renewed")
            if ic == 0xFFFFFFFF:
                self._ic_exhausted = True
            else:
                self._next_ic = ic + 1
            return ic

    def set_invocation_counter(self, value: int) -> None:
        """Move the outbound counter (e.g. after reading it from the meter).

        Only forward: going backwards would reuse IVs.
        """
        with self._lock:
            if value < self._next_ic:
                raise ReplayError(
                    f"refusing to move the invocation counter back from {self._next_ic} to {value}"
                )
            self._next_ic = value

    def check_inbound_counter(
        self, system_title: bytes, ic: int, commit: bool = True, key: str = "unicast"
    ) -> None:
        """Accept ``ic`` from ``system_title`` under ``key`` or raise :class:`ReplayError`.

        ``commit=False`` checks without storing ``ic``: for APDUs whose
        counter is not authenticated.
        """
        entry = (bytes(system_title), key)
        with self._lock:
            last = self._last_inbound.get(entry)
            if last is not None and ic <= last:
                if self.replay_protection:
                    raise ReplayError(
                        f"stale invocation counter {ic} from {system_title.hex()} "
                        f"({key} key, last {last})"
                    )
                log.warning(
                    "accepting stale IC %d from %s (replay protection off)", ic, system_title.hex()
                )
                return
            if commit:
                self._last_inbound[entry] = ic

    def check_signed_replay(self, token: bytes) -> None:
        """Refuse a general-signing APDU (by :func:`signing_replay_token`) seen before.

        Bounded by :attr:`signed_replay_window`; see there for the limits.
        """
        with self._lock:
            if token in self._signed_seen:
                if self.replay_protection:
                    raise ReplayError("general-signing APDU replayed (already verified)")
                log.warning("accepting a replayed general-signing APDU (replay protection off)")
                return
            self._signed_seen[token] = None
            while len(self._signed_seen) > self.signed_replay_window:
                self._signed_seen.popitem(last=False)

    def last_inbound_counter(self, system_title: bytes, key: str = "unicast") -> int | None:
        return self._last_inbound.get((bytes(system_title), key))
