"""Application association: AARQ/AARE, HLS passes 3 and 4, ciphering, release.

:class:`Association` sits on an :class:`~pydlms.link.ApduLink` and owns the
:class:`~pydlms.security.context.SecurityContext`. After :meth:`associate`
every :meth:`request` transparently

1. ciphers the outbound APDU (``glo-``/``ded-``) when the association is ciphered,
2. reassembles a general-block-transfer response (acknowledging blocks),
3. deciphers the response and checks its invocation counter,
4. turns ExceptionResponse / ConfirmedServiceError into exceptions.

Sequence for HLS (mechanisms 3..7)::

    AARQ(CtoS) -> AARE(StoC, accepted with diagnostic authentication-required)
    ACTION 15/0.0.40.0.0.255/m1 (f(StoC)) -> ACTION-Response (f(CtoS)), verified
"""

from __future__ import annotations

import dataclasses
import enum
import hmac
import logging
import os
from collections.abc import Callable
from dataclasses import dataclass

from pydlms.apdu import xdlms
from pydlms.apdu.acse import AARE, AARQ, RLRE, RLRQ, ApplicationContext
from pydlms.apdu.gbt import GbtTransfer, decode_gbt, gbt_overhead
from pydlms.apdu.tags import UNSOLICITED_TAGS, Tag, tag_name
from pydlms.apdu.xdlms import Conformance, InitiateRequest, InitiateResponse
from pydlms.cosem.enums import result_name
from pydlms.debug import (
    TRACE,
    get_logger,
    hexstr,
    payloads_sensitive,
    register_secret,
    sensitive_payloads,
)
from pydlms.exceptions import (
    AssociationError,
    AuthenticationError,
    DecodeError,
    DlmsTimeoutError,
    InvocationCounterError,
    KeyMissingError,
    ProtocolError,
    SecurityError,
    ServiceError,
)
from pydlms.link import ApduLink
from pydlms.obis import ObisCode
from pydlms.security.hls import (
    Mechanism,
    hash_response,
    hls_ecdsa_sign,
    hls_ecdsa_verify,
    hls_gmac,
    hls_manufacturer_aes,
    hls_sha256,
    verify_hls_gmac,
)

__all__ = ["AssociationSettings", "Association", "AssociationState"]

log = get_logger("association")

ASSOCIATION_LN_OBIS = ObisCode(0, 0, 40, 0, 0, 255)
ASSOCIATION_SN_BASE = 0xFA00

#: InitiateResponse vaa-name: 0x0007 for LN referencing, the Association SN
#: base name 0xFA00 for SN (Green Book xDLMS InitiateResponse; the same pair
#: is checked by Gurux.DLMS.Net GXAPDU and GuruxDLMS.c apdu.c).
VAA_NAME_LN = 0x0007
VAA_NAME_SN = ASSOCIATION_SN_BASE
#: DLMS version this client proposes and accepts (version 6 is the only one
#: defined for xDLMS; Gurux.DLMS.Net refuses any other).
DLMS_VERSION = 6
#: Smallest server-max-receive-pdu-size accepted. No Green Book minimum was
#: verified; 13 octets is the smallest request pydlms sends (an unprotected
#: GET-Request-Normal), so a smaller server PDU cannot carry any request.
#: Gurux refuses anything below 64. 0 is kept as "not limited", as before.
MIN_SERVER_MAX_PDU = 13
#: AARE result-source-diagnostic (acse-service-user) authentication-required.
DIAGNOSTIC_AUTHENTICATION_REQUIRED = 14


# Upper bounds of the protection envelopes (pydlms.security.ciphering and
# .general): tag, BER length (<= 3), security control, invocation counter and
# the 12-octet GCM tag, plus the system titles and key information of the
# general forms and the P-384 signature (96 octets) of general-signing.
_GLO_OVERHEAD = 1 + 3 + 1 + 4 + 12
_GENERAL_GLO_OVERHEAD = 1 + 1 + 8 + 3 + 1 + 4 + 12
_GENERAL_CIPHERING_OVERHEAD = 1 + 9 + 9 + 9 + 1 + 1 + 3 + 1 + 4 + 12
_KEY_INFO_OVERHEAD = {"none": 1, "identified": 3, "wrapped": 3 + 1 + 40, "agreed": 4 + 3 + 192}
_GENERAL_SIGNING_OVERHEAD = 1 + 9 + 9 + 9 + 1 + 1 + 3 + 3 + 96


#: APDUs that are not the response, accepted while waiting for it: late
#: responses with a foreign invoke-id (dropped) and authentic notifications
#: (queued for ``read_push``), counted together.
MAX_STALE_RESPONSES = 4

# LN service request tags and the response tag carrying the same invoke-id.
_RESPONSE_FOR = {
    Tag.GET_REQUEST: Tag.GET_RESPONSE,
    Tag.SET_REQUEST: Tag.SET_RESPONSE,
    Tag.ACTION_REQUEST: Tag.ACTION_RESPONSE,
}


def _invoke_id_matches(request: bytes, response: bytes) -> bool:
    """Compare the invoke-id (low 4 bits of Invoke-Id-And-Priority, octet 2)
    of an LN GET/SET/ACTION response with its request, and the 24-bit
    invoke-id of a Long-Invoke-Id-And-Priority (octets 1..4) of an ACCESS
    response with its request. Other APDUs (exception responses, SN
    services, GBT acks) carry none and match."""
    if request[:1] == bytes([Tag.ACCESS_REQUEST]) and len(request) >= 5:
        if response[:1] != bytes([Tag.ACCESS_RESPONSE]) or len(response) < 5:
            return True  # a truncated response fails to decode, not as stale
        return _long_id(request) == _long_id(response)
    expected = _RESPONSE_FOR.get(request[0]) if len(request) > 2 else None
    if expected is None or len(response) < 3 or response[0] != expected:
        return True
    return (request[2] & 0x0F) == (response[2] & 0x0F)


def _long_id(apdu: bytes) -> int:
    """The 24-bit invoke-id of the Long-Invoke-Id-And-Priority at octet 1."""
    return int.from_bytes(apdu[1:5], "big") & xdlms.MAX_LONG_INVOKE_ID


def _invoke_id_text(apdu: bytes) -> str:
    if apdu[:1] in (bytes([Tag.ACCESS_REQUEST]), bytes([Tag.ACCESS_RESPONSE])):
        return str(_long_id(apdu)) if len(apdu) >= 5 else "?"
    return str(apdu[2] & 0x0F) if len(apdu) > 2 else "?"


#: Plaintext APDUs a server sends in answer to a client request.
_REPLY_TAGS = frozenset(
    {
        Tag.GET_RESPONSE,
        Tag.SET_RESPONSE,
        Tag.ACTION_RESPONSE,
        Tag.READ_RESPONSE,
        Tag.WRITE_RESPONSE,
        Tag.CONFIRMED_SERVICE_ERROR,
        Tag.EXCEPTION_RESPONSE,
        Tag.ACCESS_RESPONSE,
    }
)
#: What a server may send while a request is outstanding: a reply or a push.
_REPLY_OR_PUSH_TAGS = _REPLY_TAGS | UNSOLICITED_TAGS
_INITIATE_REPLY_TAGS = frozenset({Tag.INITIATE_RESPONSE, Tag.CONFIRMED_SERVICE_ERROR})
_RELEASE_REPLY_TAGS = frozenset({Tag.INITIATE_RESPONSE})

#: The invocation-counter retry ignores a meter hint at or above this value.
#: The hint arrives in an unauthenticated ExceptionResponse; following one
#: near 2**32 would exhaust the counter (and, through a CounterStore, keep
#: every later session with that key from associating). 16 counters of
#: headroom are kept so a session can still run after a genuine high hint.
IC_HINT_LIMIT = 0xFFFFFFF0


class AssociationState(enum.Enum):
    IDLE = "idle"
    ASSOCIATED_PENDING_HLS = "pending-hls"
    ASSOCIATED = "associated"


@dataclass
class AssociationSettings:
    """What the client proposes in the AARQ.

    ``secret`` is the LLS password (mechanism 1) or the HLS secret for
    mechanisms 2/3/4/6. GMAC (5) uses the security context keys; ECDSA (7)
    ``signing_key`` / ``server_public_key``. Mechanisms 6 and 7 also need the
    client system title: from the security context, or ``client_system_title``.

    ``signing_key`` and a mechanism-2 ``secret`` may be crypto provider
    handles (:mod:`pydlms.security.provider`), computed by the security
    context's provider, or by ``provider`` when there is no context.
    """

    mechanism: Mechanism = Mechanism.NONE
    secret: bytes | None = None
    logical_names: bool = True
    conformance: Conformance | None = None
    max_receive_pdu_size: int = 0xFFFF
    dlms_version: int = 6
    security: object | None = None  # SecurityContext; typed loosely to avoid import cycle
    use_dedicated_key: bool = False
    #: Envelope for protected service APDUs: "glo" (key-specific glo-/ded-),
    #: "general-glo", "general-ciphering", "general-signing" (plain APDU
    #: signed), "glo+signing" (glo-/ded- ciphered, then signed) or
    #: "general-ciphering+signing" (general-ciphered, then signed).
    protection: str = "glo"
    #: general-ciphering key-info (pydlms.security.general.KeyInfo);
    #: default: identified global unicast key.
    key_info: object | None = None
    #: Refuse unprotected responses in a protected association (default).
    #: Turning it off lets an active attacker strip protection from replies;
    #: only for meters that answer some requests in clear. Logged when used.
    require_protected_responses: bool = True
    #: Propose a ciphered application context; None = when security is set.
    ciphered_context: bool | None = None
    #: Retry the AARQ once from the counter the meter reports when it refuses
    #: ours with invocation-counter-error (see pydlms.counters). Opt-in.
    invocation_counter_retry: bool = False
    #: CtoS length; None = by mechanism (32 for ECDSA, else 16).
    challenge_length: int | None = None
    signing_key: object | None = None
    server_public_key: object | None = None
    #: Crypto provider for ``signing_key`` / a mechanism-2 ``secret`` when
    #: no security context is set (the context's provider wins otherwise).
    provider: object | None = None
    send_calling_ap_title: bool | None = None  # default: when ciphered or mech 5/6/7
    #: Client system title when no security context is used (mechanisms 6/7).
    client_system_title: bytes | None = None
    #: f(challenge, secret) for the manufacturer-specific mechanism 2; defaults
    #: to the common AES-128-ECB convention (see :func:`hls_manufacturer_aes`).
    hls2_function: Callable[[bytes, bytes], bytes] | None = None
    #: Our general-block-transfer receive window, advertised in every GBT
    #: block we send (the window field is the sender's receive window).
    gbt_window: int = 1
    #: Send requests longer than the server's max-receive-pdu-size with
    #: general-block-transfer, and prefer it to the service-specific SET /
    #: ACTION / SN blocks. Only effective when GBT was negotiated.
    use_gbt: bool = True
    #: Propose general-block-transfer in the conformance block (opt-in: the
    #: bit is added to the default or the configured conformance).
    propose_gbt: bool = False
    #: Propose the ACCESS service (conformance bit 17) the same way (opt-in);
    #: :meth:`pydlms.client.DlmsClient.access` needs it negotiated.
    propose_access: bool = False
    #: Lost GBT blocks recovered per request (rewinds on a low
    #: block-number-ack, recovery acknowledgements, timeouts) before
    #: ProtocolError.
    gbt_max_retransmissions: int = 3
    #: Library cap on data reassembled from GBT, GET datablocks, ACTION
    #: pblocks and SN block reads (the peer is untrusted).
    max_block_transfer_size: int = 16 * 1024 * 1024
    #: Pin the meter: the 8-octet system title its AARE must carry as
    #: responding-AP-title. A mismatch, or no title, raises AssociationError
    #: before the user-information is opened or HLS pass 3 is sent. An
    #: explicitly configured ``SecurityContext.server_system_title`` (or a
    #: peer certificate) pins the same way; the two must agree.
    expected_server_system_title: bytes | None = None
    #: Raise AuthenticationError from :meth:`Association.release` when the
    #: RLRE answering a ciphered RLRQ is not verified (``release_status``
    #: "unverified" or "failed"). The association is IDLE either way. Off by
    #: default: some servers send malformed RLREs (Gurux.DLMS.Net).
    require_verified_release: bool = False
    #: Third-party protection layers (IEC 62056-5-3:2023 annex J,
    #: :class:`pydlms.security.thirdparty.ThirdParty`): the third party's
    #: general-signing / general-ciphering go inside the client's own
    #: protection of every service request, and the meter's layers for the
    #: third party are verified and removed from every reply. None (the
    #: default) applies none. Needs suite 1 or 2 and protection
    #: "general-glo" (general-ded with a dedicated key), "general-ciphering"
    #: or "general-ciphering+signing".
    third_party: object | None = None

    def __post_init__(self) -> None:
        if not 1 <= self.gbt_window <= 63:
            raise ValueError("gbt_window must be 1..63 (a 6-bit field)")
        if self.gbt_max_retransmissions < 0:
            raise ValueError("gbt_max_retransmissions must not be negative")
        title = self.expected_server_system_title
        if title is not None:
            if not isinstance(title, (bytes, bytearray)) or len(title) != 8:
                raise ValueError("expected_server_system_title must be 8 octets")
            self.expected_server_system_title = bytes(title)

    def __repr__(self) -> str:  # never show the secret
        secret = "***" if self.secret else None
        return (
            f"AssociationSettings(mechanism={self.mechanism.name}, secret={secret}, "
            f"logical_names={self.logical_names}, ciphered={self.security is not None})"
        )


class Association:
    """One client association over an APDU link."""

    def __init__(self, link: ApduLink, settings: AssociationSettings | None = None) -> None:
        self.link = link
        self.settings = settings or AssociationSettings()
        self.security = self.settings.security
        # The LLS password / HLS secret is masked in logs like a key.
        register_secret(self.settings.secret)
        self.state = AssociationState.IDLE
        self.negotiated_conformance = Conformance(0)
        self.server_max_pdu = 0
        self.aare: AARE | None = None
        self._ctos: bytes | None = None
        #: Plaintext InitiateRequest of the last AARQ (re-ciphered in the RLRQ).
        self._initiate_plain: bytes | None = None
        self._invoke_id = 0
        #: 24-bit invoke-id counter of the Long-Invoke-Id-And-Priority (ACCESS).
        self._long_invoke_id = 0
        self._access_coerce_logged = False
        self._sent_dedicated_key = False
        self.server_system_title: bytes | None = None
        #: Outcome of the last :meth:`release`: "plain" (no ciphered context,
        #: nothing to verify), "verified" (the RLRE carried an authenticated
        #: InitiateResponse from the meter), "unverified" (an RLRE without
        #: authenticated user-information) or "failed" (no RLRE, a malformed
        #: one, or one that failed a security check). None until released.
        self.release_status: str | None = None
        #: The meter's GBT receive window, as last seen in one of its blocks,
        #: and the last block number it used (some meters number on).
        self._gbt_peer_window = 1
        self._gbt_peer_last = 0
        self._server_title_pin()  # contradicting pins are refused here
        self._check_third_party()

    #: Protections whose own layer carries the third party's layers: a
    #: ciphering envelope with an invocation counter (the third party's
    #: agreed keys count nothing, so replay protection is the client's).
    #: glo-/ded- name the plaintext APDU in their tag, general-signing alone
    #: has no counter.
    _THIRD_PARTY_PROTECTIONS = ("general-glo", "general-ciphering", "general-ciphering+signing")

    def _check_third_party(self) -> None:
        tp = self.settings.third_party
        if tp is None:
            return
        from pydlms.security.thirdparty import ThirdParty

        if not isinstance(tp, ThirdParty):
            raise TypeError("settings.third_party must be a pydlms.security.thirdparty.ThirdParty")
        if not self.ciphered or int(self.security.suite) not in (1, 2):
            raise ValueError("third party layers need a security context of suite 1 or 2")
        if self.settings.protection not in self._THIRD_PARTY_PROTECTIONS or (
            not self.protects_services
        ):
            raise ValueError(
                f"third party layers need protection {', '.join(self._THIRD_PARTY_PROTECTIONS)} "
                f"on protected services, not {self.settings.protection!r}"
            )

    def _server_title_pin(self) -> tuple[bytes, str] | None:
        """The system title the meter must answer with, and where it was set.

        ``settings.expected_server_system_title`` and a title configured in
        the security context (explicitly or by a peer certificate) both pin;
        when both are set they must agree (:class:`SecurityError`).
        """
        expected = self.settings.expected_server_system_title
        configured = None
        if self.ciphered and getattr(self.security, "peer_title_pinned", False):
            configured = self.security.server_system_title
        source = "SecurityContext.server_system_title"
        if configured is not None and (
            getattr(self.security, "peer_certificate", None) is not None
            or getattr(self.security, "peer_agreement_certificate", None) is not None
        ):
            source = "the peer certificate"
        if expected is not None and configured is not None:
            if not hmac.compare_digest(expected, configured):
                raise SecurityError(
                    f"expected_server_system_title {expected.hex()} contradicts {source} "
                    f"({configured.hex()})"
                )
        if expected is not None:
            return expected, "expected_server_system_title"
        if configured is not None:
            return configured, source
        return None

    # -- helpers ---------------------------------------------------------------
    def _record(self, direction: str, apdu: bytes) -> None:
        """Add a plaintext APDU to the transport's session recorder, if any.

        Deciphered service APDUs make a ciphered session replayable
        (:mod:`pydlms.replay`) without keeping the keys. HLS pass 3/4 is never
        recorded, and the AARE only without its StoC challenge.
        """
        recorder = getattr(getattr(self.link, "transport", None), "recorder", None)
        if recorder is not None:
            recorder.record(direction, apdu)

    @property
    def ciphered(self) -> bool:
        return self.security is not None

    @property
    def ciphered_context(self) -> bool:
        """Whether the AARQ proposes a ciphered application context.

        Defaults to "a security context is configured"; some suite 1/2
        associations use a plain context yet protect every APDU with
        general-ciphering/-signing (``settings.ciphered_context=False``).
        """
        if self.settings.ciphered_context is not None:
            return self.settings.ciphered_context and self.ciphered
        return self.ciphered

    @property
    def protects_services(self) -> bool:
        """Whether service APDUs are protected in this association.

        In a ciphered application context always. In a non-ciphered one (LN/SN
        without ciphering) only the suite 1/2 general-ciphering/-signing
        protections apply; key-specific glo-/ded- and general-glo/-ded
        ciphering belong to the ciphered contexts (the Gurux server answers
        in clear there), so APDUs travel in clear, and a security context
        present for HLS-GMAC keys alone does not cipher them.
        """
        if not self.ciphered:
            return False
        if self.ciphered_context:
            return True
        return self.settings.protection not in ("glo", "general-glo")

    @property
    def application_context(self) -> ApplicationContext:
        ln = self.settings.logical_names
        if self.ciphered_context:
            return ApplicationContext.LN_CIPHERED if ln else ApplicationContext.SN_CIPHERED
        return ApplicationContext.LN if ln else ApplicationContext.SN

    def next_invoke_id(self) -> int:
        self._invoke_id = (self._invoke_id + 1) % 16
        return xdlms.invoke_id_byte(self._invoke_id)

    def next_long_invoke_id(
        self,
        *,
        break_on_error: bool = False,
        confirmed: bool = True,
        high_priority: bool = True,
    ) -> int:
        """The next Long-Invoke-Id-And-Priority of an ACCESS request: a
        24-bit counter (wrapping after 0xFFFFFF) with the given flags."""
        self._long_invoke_id = (self._long_invoke_id + 1) & xdlms.MAX_LONG_INVOKE_ID
        return xdlms.long_invoke_id(
            self._long_invoke_id,
            high_priority=high_priority,
            confirmed=confirmed,
            processing_option=(
                xdlms.ProcessingOption.BREAK_ON_ERROR
                if break_on_error
                else xdlms.ProcessingOption.CONTINUE_ON_ERROR
            ),
        )

    @property
    def access_negotiated(self) -> bool:
        """Whether the AARE granted the ACCESS service (conformance bit 17)."""
        return bool(self.negotiated_conformance & Conformance.ACCESS)

    def _initiate_request(self) -> bytes:
        """The AARQ user-information: a new InitiateRequest (drawing a fresh
        dedicated key when one is used), ciphered for a ciphered context."""
        raw = self._initiate_plain = self._build_initiate_request()
        if self.ciphered_context:
            raw = self._wrap_initiate(raw)
        return raw

    def _wrap_initiate(self, raw: bytes) -> bytes:
        """Cipher an InitiateRequest; one carrying a dedicated key is key
        material and always travels authenticated and encrypted, whatever the
        policy (IEC 62056-5-3:2023 5.5.1 as cited by cB-Sigma dlms; clause
        text not checked here)."""
        from pydlms.security.ciphering import wrap
        from pydlms.security.suites import SecurityControl, SecurityPolicy

        sc = (
            SecurityControl.for_policy(
                SecurityPolicy.AUTHENTICATED_ENCRYPTED, int(self.security.suite)
            )
            if self._sent_dedicated_key
            else None
        )
        return wrap(self.security, raw, sc=sc)

    def _build_initiate_request(self) -> bytes:
        conformance = self.settings.conformance or (
            Conformance.default_ln() if self.settings.logical_names else Conformance.default_sn()
        )
        if self.ciphered and self.settings.conformance is None:
            conformance |= Conformance.GENERAL_PROTECTION
        if self.settings.propose_gbt:
            conformance |= Conformance.GENERAL_BLOCK_TRANSFER
        if self.settings.propose_access:
            conformance |= Conformance.ACCESS
        dedicated = None
        if self.ciphered_context and self.settings.use_dedicated_key:
            import os

            from pydlms.security.suites import key_length

            dedicated = os.urandom(key_length(int(self.security.suite)))
            self.security.set_dedicated_key(dedicated)
        request = InitiateRequest(
            conformance=conformance,
            max_receive_pdu_size=self.settings.max_receive_pdu_size,
            dlms_version=self.settings.dlms_version,
            dedicated_key=dedicated,
        )
        log.debug(
            "InitiateRequest: conformance=%s max_pdu=%d",
            ",".join(conformance.names()),
            request.max_receive_pdu_size,
        )
        self._sent_dedicated_key = dedicated is not None
        return request.to_bytes()

    def _calling_auth_value(self) -> bytes | None:
        mech = self.settings.mechanism
        if mech == Mechanism.NONE:
            return None
        if mech == Mechanism.LLS:
            if self.settings.secret is None:
                raise KeyMissingError("LLS needs a password (settings.secret)")
            return self.settings.secret
        from pydlms.security.hls import default_challenge_length, generate_challenge

        length = self.settings.challenge_length or default_challenge_length(mech)
        self._ctos = generate_challenge(length, mech)
        return self._ctos

    # -- association -------------------------------------------------------------
    def associate(self) -> None:
        """Send the AARQ, process the AARE and, for HLS, run passes 3 and 4.

        With ``settings.invocation_counter_retry`` a stale-counter refusal is
        retried once from the counter the meter reports.
        """
        self.release_status = None
        try:
            self._associate()
        except InvocationCounterError as exc:
            if not (
                self.settings.invocation_counter_retry
                and self.ciphered
                and exc.expected is not None
            ):
                raise
            if exc.expected >= IC_HINT_LIMIT:
                raise InvocationCounterError(
                    f"meter claims to expect an invocation counter above {exc.expected}; "
                    "following that unauthenticated hint would exhaust the counter, not retrying",
                    exc.expected,
                ) from exc
            log.warning("meter expects an invocation counter above %d; retrying once", exc.expected)
            self.security.set_invocation_counter(
                max(exc.expected + 1, self.security.invocation_counter)
            )
            self._associate()

    def _associate(self) -> None:
        # GBT state learned from the meter belongs to one association.
        self._gbt_peer_window = 1
        self._gbt_peer_last = 0
        mech = self.settings.mechanism
        send_title = self.settings.send_calling_ap_title
        if send_title is None:
            send_title = self.ciphered or mech in (
                Mechanism.HLS_SHA256,
                Mechanism.HLS_ECDSA,
                Mechanism.HLS_GMAC,
            )
        title = None
        if send_title:
            title = self.client_system_title
            if title is None:
                raise KeyMissingError(f"{mech.name} needs a client system title")
        aarq = AARQ(
            application_context=self.application_context,
            user_information=self._initiate_request(),
            mechanism=int(mech) or None,
            calling_authentication_value=self._calling_auth_value(),
            calling_ap_title=title,
        )
        log.info("associating: context=%s mechanism=%s", aarq.application_context.name, mech.name)
        raw = self.link.request(aarq.to_bytes())
        if not raw or raw[0] != Tag.AARE:
            if raw and raw[0] == Tag.EXCEPTION_RESPONSE:
                exc = xdlms.decode_apdu(raw, strict=False)
                message = f"meter answered AARQ with ExceptionResponse {exc.describe()}"
                if exc.service_error == xdlms.ExceptionServiceError.INVOCATION_COUNTER_ERROR:
                    raise InvocationCounterError(message, exc.invocation_counter)
                raise AssociationError(message)
            raise ProtocolError(f"expected AARE, got {tag_name(raw[0]) if raw else 'nothing'}")
        aare = AARE.from_bytes(raw)
        self.aare = aare
        log.debug(
            "AARE: result=%d diagnostic=%s title=%s mech=%s",
            aare.result,
            aare.diagnostic_name(),
            aare.responding_ap_title.hex() if aare.responding_ap_title else None,
            aare.mechanism,
        )
        self._check_server_title(aare)
        if aare.responding_ap_title:
            if len(aare.responding_ap_title) != 8:
                raise AssociationError("responding-AP-title is not an 8-octet system title")
            own = self.client_system_title
            if own is not None and hmac.compare_digest(aare.responding_ap_title, own):
                # Our own title back: the "meter" would cipher with our IVs and
                # compute HLS-SHA256/-GMAC answers that are ours (reflection).
                raise AssociationError(
                    f"responding-AP-title {own.hex()} is our own system title (reflection?)"
                )
            peer_cert = getattr(self.security, "peer_certificate", None)
            if peer_cert is not None and peer_cert.system_title != aare.responding_ap_title:
                # The certificate pins which meter we trust; an AARE from a
                # different system title is not that meter.
                raise AssociationError(
                    f"responding-AP-title {aare.responding_ap_title.hex()} does not match the "
                    f"peer certificate's system title {peer_cert.system_title.hex()}"
                )
            self.server_system_title = aare.responding_ap_title
            if self.ciphered:
                self.security.server_system_title = aare.responding_ap_title
        user_info = aare.user_information
        if (
            user_info
            and self.ciphered
            and user_info[0]
            in (
                Tag.GLO_INITIATE_RESPONSE,
                Tag.DED_INITIATE_RESPONSE,
                Tag.GLO_CONFIRMED_SERVICE_ERROR,
            )
        ):
            from pydlms.security.ciphering import unwrap

            result = unwrap(self.security, user_info)
            if self._sent_dedicated_key and not (
                result.security_control.authenticated and result.security_control.encrypted
            ):
                raise AuthenticationError(
                    "the answer to an InitiateRequest carrying a dedicated key must be "
                    f"authenticated and encrypted, got {result.security_control.describe()}"
                )
            user_info = self._check_reply(result, _INITIATE_REPLY_TAGS)
        elif aare.accepted and self._sent_dedicated_key:
            raise AuthenticationError(
                "the meter answered an InitiateRequest carrying a dedicated key without "
                "ciphering the InitiateResponse"
            )
        if not aare.accepted:
            detail = ""
            if user_info and user_info[0] == Tag.CONFIRMED_SERVICE_ERROR:
                detail = f"; {xdlms.decode_apdu(user_info, strict=False).describe()}"
            raise AssociationError(
                f"association rejected: result={aare.result} diagnostic={aare.diagnostic_name()}"
                f"{detail}",
                result=aare.result,
                diagnostic=aare.diagnostic,
            )
        if not user_info:
            raise AssociationError("AARE carries no InitiateResponse")
        if user_info[0] == Tag.CONFIRMED_SERVICE_ERROR:
            raise AssociationError(
                f"initiate failed: {xdlms.decode_apdu(user_info, strict=False).describe()}"
            )
        initiate = InitiateResponse.from_bytes(user_info)
        self._check_aare(aare, initiate)
        self._record(
            "RX-APDU",
            dataclasses.replace(
                aare, responding_authentication_value=None, user_information=user_info
            ).to_bytes(),
        )
        self.negotiated_conformance = initiate.conformance
        self.server_max_pdu = initiate.max_receive_pdu_size
        log.info(
            "associated: server max PDU %d, conformance %s",
            self.server_max_pdu,
            ",".join(initiate.conformance.names()),
        )
        if mech.is_hls:
            self.state = AssociationState.ASSOCIATED_PENDING_HLS
            self._hls_pass_3_4(aare)
        self.state = AssociationState.ASSOCIATED

    def _check_server_title(self, aare: AARE) -> None:
        """Refuse an AARE that is not from the pinned meter, before anything in
        it is opened or answered (no unwrap, no HLS pass 3)."""
        pin = self._server_title_pin()
        if pin is None:
            return
        expected, source = pin
        title = aare.responding_ap_title
        if not title:
            if not aare.accepted:
                # A refusal need not name the meter; report it as such, but do
                # not open its user-information from an unidentified peer.
                raise AssociationError(
                    f"association rejected: result={aare.result} "
                    f"diagnostic={aare.diagnostic_name()} (no responding-AP-title)",
                    result=aare.result,
                    diagnostic=aare.diagnostic,
                )
            raise AssociationError(
                f"AARE carries no responding-AP-title; the meter is pinned to "
                f"{expected.hex()} ({source})"
            )
        if not hmac.compare_digest(title, expected):
            raise AssociationError(
                f"responding-AP-title {title.hex()} is not the pinned meter "
                f"{expected.hex()} ({source})"
            )

    def _check_aare(self, aare: AARE, initiate: InitiateResponse) -> None:
        """Refuse an accepted AARE that does not answer what was proposed."""
        proposed = self.application_context
        if aare.application_context != proposed:
            raise AssociationError(
                f"AARE accepted application context {aare.application_context.name}, "
                f"but {proposed.name} was proposed"
            )
        expected_vaa = VAA_NAME_LN if self.settings.logical_names else VAA_NAME_SN
        if initiate.vaa_name != expected_vaa:
            raise AssociationError(
                f"InitiateResponse VAA name 0x{initiate.vaa_name:04X} does not match "
                f"{'LN' if self.settings.logical_names else 'SN'} referencing "
                f"(expected 0x{expected_vaa:04X})"
            )
        if initiate.dlms_version != DLMS_VERSION:
            raise AssociationError(
                f"meter negotiated DLMS version {initiate.dlms_version}; only "
                f"{DLMS_VERSION} is supported"
            )
        if 0 < initiate.max_receive_pdu_size < MIN_SERVER_MAX_PDU:
            raise AssociationError(
                f"server max receive PDU size {initiate.max_receive_pdu_size} is below "
                f"{MIN_SERVER_MAX_PDU} octets; no request fits"
            )
        if self.settings.mechanism.is_hls and not (
            aare.diagnostic_source == 1 and aare.diagnostic == DIAGNOSTIC_AUTHENTICATION_REQUIRED
        ):
            # Green Book HLS: the server accepts with authentication-required
            # and passes 3 and 4 follow. Whether another diagnostic forbids
            # pass 3 was not verified, so it still runs.
            log.warning(
                "HLS association accepted with diagnostic %s, not authentication-required; "
                "running pass 3 anyway",
                aare.diagnostic_name(),
            )

    # -- HLS ---------------------------------------------------------------------
    @property
    def client_system_title(self) -> bytes | None:
        if self.ciphered:
            return self.security.client_system_title
        return self.settings.client_system_title

    def _f(self, received: bytes, sent: bytes, own: bytes | None, peer: bytes | None) -> bytes:
        """f(received) for the secret-based mechanisms 2, 3, 4 and 6.

        ``own``/``peer`` are the computing party's and the other party's system
        titles (only mechanism 6 uses them).
        """
        mech = self.settings.mechanism
        secret = self.settings.secret
        if secret is None:
            raise KeyMissingError(f"{mech.name} needs settings.secret")
        if mech == Mechanism.HLS:
            if self.settings.hls2_function is not None:
                return self.settings.hls2_function(received, secret)
            return hls_manufacturer_aes(received, secret, provider=self._provider)
        if mech in (Mechanism.HLS_MD5, Mechanism.HLS_SHA1):
            return hash_response(mech, received, secret)
        if mech == Mechanism.HLS_SHA256:
            if own is None or peer is None:
                raise KeyMissingError(
                    "HLS-SHA256 needs both system titles (client_system_title setting and the "
                    "AARE responding-AP-title)"
                )
            return hls_sha256(secret, own, peer, received, sent)
        raise NotImplementedError(mech.name)

    @property
    def _provider(self):
        """The security context's crypto provider, else ``settings.provider``."""
        if self.security is not None:
            return getattr(self.security, "provider", None)
        return self.settings.provider

    def _hls_pass_3_4(self, aare: AARE) -> None:
        mech = self.settings.mechanism
        stoc = aare.responding_authentication_value
        if not stoc:
            raise AssociationError("HLS association but the AARE carries no StoC challenge")
        assert self._ctos is not None
        if hmac.compare_digest(stoc, self._ctos):
            # A meter that does not know the secret can answer our CtoS as its
            # StoC and return our own f(StoC) as f(CtoS) (IEC 62056-5-3:2023
            # 5.2.2.2.4 as cited by cB-Sigma dlms; clause text not checked
            # here). Refuse before f(StoC) is computed or sent.
            self.state = AssociationState.IDLE
            raise AssociationError(
                "HLS: the meter's StoC equals our CtoS (reflection); association aborted"
            ) from AuthenticationError("StoC == CtoS")
        client_title, server_title = self.client_system_title, self.server_system_title
        if mech == Mechanism.HLS_GMAC:
            if not self.ciphered:
                raise KeyMissingError("HLS-GMAC needs a security context")
            reply = hls_gmac(
                self.security.require_encryption_key(),
                self.security.require_authentication_key(),
                self.security.client_system_title,
                self.security.next_invocation_counter(),
                stoc,
                int(self.security.suite),
                provider=self._provider,
            )
        elif mech == Mechanism.HLS_ECDSA:
            if self.settings.signing_key is None or client_title is None or server_title is None:
                raise KeyMissingError("HLS-ECDSA needs settings.signing_key and both system titles")
            reply = hls_ecdsa_sign(
                self.settings.signing_key,
                client_title,
                server_title,
                stoc,
                self._ctos,
                provider=self._provider,
            )
        else:
            reply = self._f(stoc, self._ctos, client_title, server_title)
        log.debug("HLS pass 3: sending f(StoC) (%d octets)", len(reply))
        from pydlms.cosem.data import DlmsData

        try:
            with sensitive_payloads():
                if self.settings.logical_names:
                    result = self.action_raw(
                        xdlms.MethodDescriptor(15, ASSOCIATION_LN_OBIS, 1),
                        DlmsData.octet_string(reply),
                    )
                else:
                    result = self.sn_action_raw(
                        ASSOCIATION_SN_BASE + 0x58, DlmsData.octet_string(reply)
                    )
        except ServiceError as exc:
            self.state = AssociationState.IDLE
            raise AssociationError(
                f"HLS pass 3 rejected by the meter (wrong secret or key?): {exc}"
            ) from exc
        if result is None or result.value is None:
            raise AssociationError("HLS pass 4: the meter returned no f(CtoS)")
        server_reply = bytes(result.value)
        try:
            self._verify_server_reply(stoc, server_reply)
        except AuthenticationError as exc:
            self.state = AssociationState.IDLE
            raise AssociationError(f"HLS pass 4 failed: the meter is not authentic: {exc}") from exc
        log.info("HLS %s authentication completed (both directions)", mech.name)

    def _verify_server_reply(self, stoc: bytes, server_reply: bytes) -> None:
        mech = self.settings.mechanism
        assert self._ctos is not None
        if mech == Mechanism.HLS_GMAC:
            verify_hls_gmac(
                self.security.require_encryption_key(),
                self.security.require_authentication_key(),
                self.security.server_system_title,
                self._ctos,
                server_reply,
                suite=int(self.security.suite),
                provider=self._provider,
            )
            return
        if mech == Mechanism.HLS_ECDSA:
            if self.settings.server_public_key is None:
                raise KeyMissingError("HLS-ECDSA needs settings.server_public_key")
            hls_ecdsa_verify(
                self.settings.server_public_key,
                self.server_system_title,
                self.client_system_title,
                self._ctos,
                stoc,
                server_reply,
            )
            return
        # The server computes f(CtoS) from its own point of view.
        expected = self._f(self._ctos, stoc, self.server_system_title, self.client_system_title)
        if not hmac.compare_digest(expected, server_reply):
            raise AuthenticationError("f(CtoS) from the meter does not match")

    def release(self) -> None:
        """Send RLRQ, wait for the RLRE and record :attr:`release_status`.

        In a ciphered context the RLRQ re-ciphers the AARQ's InitiateRequest
        and the RLRE must answer with a glo-/ded-InitiateResponse that opens
        under the policy and the inbound counter check (authenticated and
        encrypted when a dedicated key was sent). Errors are logged; only
        ``settings.require_verified_release`` raises
        :class:`AuthenticationError`, and only after the association is IDLE.
        """
        if self.state == AssociationState.IDLE:
            return
        protected = self.ciphered_context and self._initiate_plain is not None
        status, error = "failed", None
        try:
            user_info = b""
            if protected:
                # The AARQ's InitiateRequest ciphered under the next counter;
                # building a new one would draw and install another
                # dedicated key as a side effect of releasing.
                user_info = self._wrap_initiate(self._initiate_plain)
            raw = self.link.request(RLRQ(0, user_info).to_bytes())
            status = self._check_rlre(raw, protected)
        except Exception as exc:  # noqa: BLE001 - release must not mask the caller's error
            error = exc
            log.warning("release failed: %s", exc)
        finally:
            self.state = AssociationState.IDLE
            self.release_status = status
        if protected and status != "verified" and self.settings.require_verified_release:
            raise AuthenticationError(
                f"release {status}: the RLRE was not verified as the meter's answer"
            ) from error

    def _check_rlre(self, raw: bytes, protected: bool) -> str:
        """Check the answer to our RLRQ; returns the release status or raises."""
        if not raw or raw[0] != Tag.RLRE:
            raise ProtocolError(f"expected RLRE, got {tag_name(raw[0]) if raw else 'nothing'}")
        rlre = RLRE.from_bytes(raw)
        log.info("released: reason=%s", rlre.reason)
        if not protected:
            return "plain"
        user_info = rlre.user_information
        if not user_info:
            log.warning("RLRE carries no user-information; the release is not authenticated")
            return "unverified"
        if user_info[0] not in (Tag.GLO_INITIATE_RESPONSE, Tag.DED_INITIATE_RESPONSE):
            raise AuthenticationError(
                f"RLRE user-information is {tag_name(user_info[0])}, "
                "not a ciphered InitiateResponse"
            )
        from pydlms.security.ciphering import unwrap

        result = unwrap(self.security, user_info)
        if self._sent_dedicated_key and not (
            result.security_control.authenticated and result.security_control.encrypted
        ):
            raise AuthenticationError(
                "the RLRE answering an InitiateRequest carrying a dedicated key must be "
                f"authenticated and encrypted, got {result.security_control.describe()}"
            )
        InitiateResponse.from_bytes(self._check_reply(result, _RELEASE_REPLY_TAGS))
        if not result.authenticated:
            log.warning("RLRE InitiateResponse is not authenticated; the release is unverified")
            return "unverified"
        return "verified"

    # -- service exchange ----------------------------------------------------------
    @property
    def max_request_size(self) -> int:
        """Largest APDU the server accepts, envelope included: its negotiated
        max-receive-pdu-size (0xFFFF before or without negotiation)."""
        return self.server_max_pdu or 0xFFFF

    @property
    def gbt_negotiated(self) -> bool:
        """Whether the AARE granted general-block-transfer."""
        return bool(self.negotiated_conformance & Conformance.GENERAL_BLOCK_TRANSFER)

    @property
    def uses_gbt(self) -> bool:
        """Long requests go in GBT blocks: negotiated and ``settings.use_gbt``."""
        return self.settings.use_gbt and self.gbt_negotiated

    def gbt_block_size(self) -> int:
        """Block-data octets per GBT request block: the server's max PDU
        minus the GBT header and length."""
        limit = self.max_request_size
        return limit - gbt_overhead(limit)

    def _protection_for(self, tag: int | None) -> str:
        """The envelope :meth:`_protect` uses for an APDU with this tag.

        ACCESS has no key-specific (glo-/ded-) ciphered form; it is protected
        with general-glo / general-ded or the suite 1/2 general envelopes
        only. ``protection="glo"`` therefore sends ACCESS as general-glo
        (general-ded with a dedicated key); ``"glo+signing"`` cannot carry
        it (see :meth:`_protect`).
        """
        protection = self.settings.protection
        if tag == Tag.ACCESS_REQUEST and protection == "glo":
            return "general-glo"
        return protection

    def protection_overhead(self, tag: int | None = None) -> int:
        """Upper bound of the octets :meth:`_protect` adds to a service APDU
        with the configured protection, so callers can size requests and
        datablocks to fit :attr:`max_request_size`. ``tag`` names the APDU
        when its envelope differs from the configured one (ACCESS)."""
        if not self.ciphered:
            return 0
        protection = self._protection_for(tag)
        overhead = 0
        if protection in ("glo", "glo+signing"):
            overhead += _GLO_OVERHEAD
        elif protection == "general-glo":
            overhead += _GENERAL_GLO_OVERHEAD
        elif protection in ("general-ciphering", "general-ciphering+signing"):
            kind = getattr(self.settings.key_info, "kind", "identified")
            overhead += _GENERAL_CIPHERING_OVERHEAD + _KEY_INFO_OVERHEAD.get(kind, 199)
        if protection.endswith("signing"):
            overhead += _GENERAL_SIGNING_OVERHEAD
        tp = self.settings.third_party
        if tp is not None:
            from pydlms.security import thirdparty

            overhead += thirdparty.SIGNING_OVERHEAD if tp.sign else 0
            overhead += thirdparty.CIPHERING_OVERHEAD if tp.policy else 0
        return overhead

    def max_plain_request(self, tag: int | None = None) -> int:
        """Largest plaintext service APDU that still fits the server's
        max-receive-pdu-size once protected (``tag`` as for
        :meth:`protection_overhead`)."""
        return self.max_request_size - self.protection_overhead(tag)

    def _protect(self, apdu: bytes) -> bytes:
        if not self.protects_services:
            return apdu
        protection = self._protection_for(apdu[0] if apdu else None)
        if apdu and apdu[0] == Tag.ACCESS_REQUEST:
            if protection == "glo+signing":
                raise ProtocolError(
                    "ACCESS_REQUEST has no glo-/ded- ciphered form, so protection "
                    "'glo+signing' cannot carry it; use general-glo, general-ciphering "
                    "or general-ciphering+signing"
                )
            if protection != self.settings.protection and not self._access_coerce_logged:
                self._access_coerce_logged = True
                log.info(
                    "ACCESS has no glo-/ded- ciphered form: sending it with %s (protection=%r)",
                    "general-ded" if self._dedicated_in_use() else "general-glo",
                    self.settings.protection,
                )
        tp = self.settings.third_party
        if tp is not None and self.state == AssociationState.ASSOCIATED:
            # The third party's layers first; the client's go around them
            # (IEC 62056-5-3:2023 5.7.3, annex J).
            from pydlms.security.thirdparty import nest

            apdu = nest(tp, self.security, apdu, self._meter_title())
        if protection == "glo+signing":
            # Key-specific glo-/ded- ciphering inside general-signing: the form
            # suite 1/2 servers produce and expect (e.g. Gurux).
            from pydlms.security.ciphering import wrap
            from pydlms.security.general import wrap_general_signing

            recipient = self.security.server_system_title or self.server_system_title
            if recipient is None:
                raise KeyMissingError("general-signing needs the server system title")
            dedicated = self.settings.use_dedicated_key and self.security.dedicated_key is not None
            return wrap_general_signing(
                self.security, wrap(self.security, apdu, dedicated=dedicated), recipient
            )
        if protection in ("general-ciphering", "general-ciphering+signing", "general-signing"):
            from pydlms.security.general import (
                STATIC_UNIFIED_MODEL,
                KeyInfo,
                wrap_general_ciphering,
                wrap_general_signing,
            )

            recipient = self.security.server_system_title or self.server_system_title
            if recipient is None:
                raise KeyMissingError("general-ciphering needs the server system title")
            if protection != "general-signing":
                key_info = self.settings.key_info or KeyInfo("identified")
                # The static unified model has no ephemeral key: a fresh
                # transaction-id in the KDF input gives each APDU its own key.
                transaction_id = (
                    os.urandom(8)
                    if key_info.kind == "agreed" and key_info.scheme == STATIC_UNIFIED_MODEL
                    else b""
                )
                apdu = wrap_general_ciphering(
                    self.security, apdu, recipient, key_info, transaction_id=transaction_id
                )
            if protection != "general-ciphering":
                apdu = wrap_general_signing(self.security, apdu, recipient)
            return apdu
        from pydlms.security.ciphering import wrap, wrap_general_glo

        dedicated = self._dedicated_in_use()
        if protection == "general-glo":
            return wrap_general_glo(self.security, apdu, dedicated=dedicated)
        if protection != "glo":
            raise ValueError(f"unknown protection {protection!r}")
        return wrap(self.security, apdu, dedicated=dedicated)

    def _meter_title(self) -> bytes:
        title = self.security.server_system_title or self.server_system_title
        if title is None:
            raise KeyMissingError("third party layers need the server system title")
        return title

    def _dedicated_in_use(self) -> bool:
        return bool(self.settings.use_dedicated_key and self.security.dedicated_key is not None)

    def _unprotect(self, apdu: bytes):
        """Return ``(plaintext, unwrapped)`` for an inbound service APDU.

        ``unwrapped`` is the :class:`~pydlms.security.ciphering.CipheredApdu`
        of a ciphered one, else None. Besides replies, an authentic
        notification passes (:data:`~pydlms.apdu.tags.UNSOLICITED_TAGS`); the
        caller diverts it. Unprotected notifications in a protected
        association are refused like any other unprotected APDU.
        """
        from pydlms.security.ciphering import is_ciphered_apdu

        if not is_ciphered_apdu(apdu):
            if (
                self.protects_services
                and self.settings.require_protected_responses
                and apdu
                and apdu[0] not in (Tag.EXCEPTION_RESPONSE, Tag.CONFIRMED_SERVICE_ERROR)
            ):
                raise ProtocolError(
                    f"ciphered association received an unprotected {tag_name(apdu[0])} "
                    f"APDU: {hexstr(apdu, 32)}"
                )
            if (
                self.protects_services
                and apdu
                and apdu[0] not in (Tag.EXCEPTION_RESPONSE, Tag.CONFIRMED_SERVICE_ERROR)
            ):
                log.warning(
                    "accepting UNPROTECTED %s in a protected association "
                    "(require_protected_responses=False)",
                    tag_name(apdu[0]),
                )
            return apdu, None
        if not self.ciphered:
            raise KeyMissingError("received a ciphered APDU but no security context is configured")
        from pydlms.security.ciphering import unwrap

        result = unwrap(self.security, apdu, max_decompressed=self._decompress_limit())
        tp = self.settings.third_party
        if (
            tp is not None
            and self.state == AssociationState.ASSOCIATED
            and not (result.plaintext and result.plaintext[0] in UNSOLICITED_TAGS)
        ):
            # Every reply carries the meter's layers for the third party
            # inside ours; a push is the meter's to us and carries none.
            from pydlms.security.thirdparty import unnest

            if result.system_title != self._meter_title():
                raise AuthenticationError(
                    f"{tag_name(result.tag)} from system title {result.system_title.hex()}, "
                    f"the meter is {self._meter_title().hex()}"
                )
            inner = unnest(tp, self.security, result.plaintext, self._meter_title())
            result = dataclasses.replace(result, plaintext=inner)
        return self._check_reply(result, _REPLY_OR_PUSH_TAGS), result

    def _decompress_limit(self) -> int:
        """Cap on a decompressed APDU (SC bit 7, ``SecurityContext.decompressor``).

        Uncompressed, the APDU would have had to fit what this client
        accepts: its max-receive-pdu-size, or the block transfer cap when
        general-block-transfer was negotiated (GBT is reassembled first).
        """
        if self.gbt_negotiated:
            return self.settings.max_block_transfer_size
        return self.settings.max_receive_pdu_size or 0xFFFF

    def _check_reply(self, result, allowed: frozenset[int]) -> bytes:
        """Refuse a deciphered APDU that is not an answer from the meter.

        The envelope tag is outside the authenticated data, so a key-specific
        envelope must name a reply and hold exactly the APDU it names; a
        general-glo/-ded envelope must come from the meter's system title
        (our own APDUs reflected back carry ours) and hold a reply.
        """
        from pydlms.apdu.tags import PLAIN_FOR_CIPHERED

        plain = result.plaintext
        got = tag_name(plain[0]) if plain else "nothing"
        if result.tag in PLAIN_FOR_CIPHERED:
            named = PLAIN_FOR_CIPHERED[result.tag][0]
            if named not in allowed:
                raise AuthenticationError(
                    f"{tag_name(result.tag)} is a request-direction envelope, not a reply"
                )
            if not plain or plain[0] != named:
                raise AuthenticationError(
                    f"{tag_name(result.tag)} must hold {tag_name(named)}, it holds {got}"
                )
            return plain
        expected = self.security.server_system_title
        if expected is not None and result.system_title != expected:
            raise AuthenticationError(
                f"{tag_name(result.tag)} from system title {result.system_title.hex()}, "
                f"the meter is {expected.hex()}"
            )
        if not plain or plain[0] not in allowed:
            raise AuthenticationError(f"{tag_name(result.tag)} holds {got}, not a reply")
        return plain

    def _open_link_pushes(self) -> None:
        """Check the pushes the link queued by itself (HDLC UI frames, wrapper
        push wPorts) before the reply they preceded is deciphered.

        Deciphered later, at ``read_push``, a ciphered push would carry an
        invocation counter below the reply's and fail the replay check. So
        each is opened here, in arrival order, under the same rules as an
        in-band push: it must be a notification, unprotected only where an
        unprotected reply would be accepted. A push that fails is removed
        from the queue and its error raised. General-block-transfer pushes
        are left for ``read_push`` to reassemble.
        """
        queue = self.link.push_queue()
        if all(p.checked for p in queue):
            return
        from pydlms.link import QueuedPush

        kept = list(queue)
        queue.clear()
        for index, push in enumerate(kept):
            apdu = push.apdu
            if push.checked or not apdu or apdu[0] == Tag.GENERAL_BLOCK_TRANSFER:
                queue.append(push)
                continue
            try:
                plain, unwrapped = self._unprotect(apdu)
                if not plain or plain[0] not in UNSOLICITED_TAGS:
                    got = tag_name(plain[0]) if plain else "nothing"
                    raise ProtocolError(f"pushed APDU holds {got}, not a notification")
            except Exception:
                queue.extend(kept[index + 1 :])
                raise
            queue.append(QueuedPush(plain, unwrapped, checked=True))

    @staticmethod
    def _check_unconfirmed(apdu: bytes) -> None:
        """Refuse an APDU that is not an unconfirmed service request.

        LN GET/SET/ACTION carry the service class in bit 6 of their
        Invoke-Id-And-Priority (octet 2) and ACCESS in bit 30 of its
        Long-Invoke-Id-And-Priority (octet 1), 1 = confirmed; SN
        UnconfirmedWriteRequest is unconfirmed by its tag. Everything else
        expects an answer (or is no client request) and is refused.
        """
        tag = apdu[0] if apdu else None
        if tag == Tag.UNCONFIRMED_WRITE_REQUEST:
            return
        if tag in (Tag.GET_REQUEST, Tag.SET_REQUEST, Tag.ACTION_REQUEST) and len(apdu) > 2:
            if not apdu[2] & 0x40:
                return
            raise ProtocolError(
                f"{tag_name(tag)} has the confirmed service class; use request() for it"
            )
        if tag == Tag.ACCESS_REQUEST and len(apdu) > 4:
            if not apdu[1] & 0x40:
                return
            raise ProtocolError("ACCESS_REQUEST has the confirmed service class")
        what = tag_name(tag) if tag is not None else "an empty APDU"
        raise ProtocolError(f"{what} is not an unconfirmed service request")

    def send_unconfirmed(self, apdu: bytes) -> None:
        """Send a plaintext unconfirmed service APDU and return at once.

        Only unconfirmed service requests are taken (GET/SET/ACTION or
        ACCESS with the unconfirmed service class, SN UnconfirmedWrite); a
        confirmed one raises :class:`ProtocolError`, as no answer would ever
        be read for it. The APDU is protected like a request (it uses up an
        invocation counter in a ciphered association) and must fit the
        server's max-receive-pdu-size. Nothing is read: the meter sends no
        response.
        """
        if self.state == AssociationState.IDLE:
            raise ProtocolError("not associated")
        self._check_unconfirmed(apdu)
        log.debug("APDU TX unconfirmed %s (%d octets)", tag_name(apdu[0]), len(apdu))
        log.log(TRACE, "APDU TX %s", hexstr(apdu))
        protected = self._protect(apdu)
        if len(protected) > self.max_request_size:
            raise ProtocolError(
                f"{tag_name(apdu[0])} of {len(protected)} octets exceeds the server's "
                f"max-receive-pdu-size {self.max_request_size}"
            )
        self.link.send_unconfirmed(protected)
        if self.state == AssociationState.ASSOCIATED:
            self._record("TX-APDU", apdu)

    def send_broadcast(self, apdu: bytes) -> None:
        """Cipher an unconfirmed service APDU with the global broadcast key and
        send it to every server on the link; return at once.

        Takes LN GET/SET/ACTION with the unconfirmed service class and SN
        UnconfirmedWrite (ACCESS and confirmed services raise
        :class:`ProtocolError`). The association must protect its services
        with ``glo`` or ``general-glo`` ciphering, else :class:`ProtocolError`;
        a missing broadcast or (for an authenticating policy) authentication
        key raises :class:`KeyMissingError`. Every check runs before an
        invocation counter is drawn. The security control is the context's
        policy and suite with the broadcast-key bit set; the IC comes from the
        context's single outbound counter, shared with unicast APDUs, so no IV
        repeats across the two keys' streams. The dedicated key is never used.
        The link sends to its all-station address (wrapper wPort 0x007F, an
        HDLC UI frame to the all-station server address); links without one
        raise :class:`ProtocolError`. Nothing is read.

        Every meter holding the broadcast key can read and forge what is sent
        with it: a broadcast authenticates the group, not this client.
        """
        if self.state == AssociationState.IDLE:
            raise ProtocolError("not associated")
        self._check_unconfirmed(apdu)
        if apdu[0] == Tag.ACCESS_REQUEST:
            raise ProtocolError(
                "ACCESS_REQUEST has no key-specific ciphered form; broadcast GET/SET/ACTION "
                "or an SN UnconfirmedWrite"
            )
        if not self.protects_services or self.security is None:
            raise ProtocolError("a broadcast needs a ciphered association (none is protected)")
        protection = self.settings.protection
        if protection not in ("glo", "general-glo"):
            raise ProtocolError(
                f"a broadcast is sent with glo or general-glo ciphering, not {protection!r}"
            )
        from pydlms.security.ciphering import wrap, wrap_general_glo
        from pydlms.security.suites import SecurityControl

        security = self.security
        sc = SecurityControl.for_policy(security.policy, int(security.suite), broadcast=True)
        if not (sc.authenticated or sc.encrypted):
            raise ProtocolError("the security policy protects nothing; no clear broadcast")
        security.require_encryption_key(broadcast=True)
        if sc.authenticated:
            security.require_authentication_key()
        if len(apdu) > self.max_plain_request():
            raise ProtocolError(
                f"{tag_name(apdu[0])} of {len(apdu)} octets exceeds the server's "
                f"max-receive-pdu-size {self.max_request_size} once protected"
            )
        log.debug("APDU TX broadcast %s (%d octets)", tag_name(apdu[0]), len(apdu))
        sensitive = payloads_sensitive()
        log.log(TRACE, "APDU TX %s", "(withheld)" if sensitive else hexstr(apdu))
        cipher = wrap_general_glo if protection == "general-glo" else wrap
        protected = cipher(security, apdu, sc=sc)
        self.link.send_unconfirmed(protected, broadcast=True)
        if self.state == AssociationState.ASSOCIATED:
            self._record("TX-APDU", apdu)

    def _new_transfer(self) -> GbtTransfer:
        return GbtTransfer(
            window=self.settings.gbt_window,
            max_retransmissions=self.settings.gbt_max_retransmissions,
            max_size=self.settings.max_block_transfer_size,
            peer_window=self._gbt_peer_window,
            peer_last=self._gbt_peer_last,
        )

    def _gbt_read(self, transfer: GbtTransfer) -> bytes:
        """The next APDU from the link. A timeout while GBT blocks are owed
        sends one recovery (our unacknowledged window again, or an
        acknowledgement of the last block received in order) and waits
        once more; a second timeout raises :class:`DlmsTimeoutError`."""
        try:
            return self.link.receive_apdu()
        except DlmsTimeoutError:
            recovery = transfer.on_timeout()
            if not recovery:
                raise
            log.warning(
                "GBT: no answer from the meter; sending %d recovery block(s)", len(recovery)
            )
            for block in recovery:
                self.link.send_apdu(block)
            return self.link.receive_apdu()

    def _receive_gbt(self, first: bytes, transfer: GbtTransfer) -> bytes:
        """Feed GBT APDUs to ``transfer`` until one completes an APDU, and
        return it. Acknowledgements and our next windows are sent on the
        way. A non-GBT APDU read meanwhile is returned as it is."""
        raw = first
        while True:
            step = transfer.receive(decode_gbt(raw))
            for block in step.send:
                self.link.send_apdu(block)
            if step.apdu is not None:
                return step.apdu
            raw = self._gbt_read(transfer)
            if not raw or raw[0] != Tag.GENERAL_BLOCK_TRANSFER:
                return raw

    def _check_transfer_size(self, size: int) -> None:
        limit = self.settings.max_block_transfer_size
        if size > limit:
            raise ProtocolError(
                f"block transfer exceeds {limit} octets (AssociationSettings.max_block_transfer_size)"
            )

    def request(self, apdu: bytes) -> bytes:
        """Send a plaintext service APDU; return the plaintext response APDU."""
        if self.state == AssociationState.IDLE:
            raise ProtocolError("not associated")
        if log.isEnabledFor(logging.DEBUG):
            log.debug("APDU TX %s (%d octets)", tag_name(apdu[0]), len(apdu))
        sensitive = payloads_sensitive()
        log.log(TRACE, "APDU TX %s", "(HLS pass 3/4, withheld)" if sensitive else hexstr(apdu))
        protected = self._protect(apdu)
        transfer = self._new_transfer()
        if len(protected) <= self.max_request_size:
            transfer.count_block()  # the request is our block 1
            raw = self.link.request(protected)
        elif self.uses_gbt:
            blocks = transfer.send(protected, self.gbt_block_size())
            log.debug(
                "%s of %d octets in %d-octet GBT blocks",
                tag_name(apdu[0]),
                len(protected),
                self.gbt_block_size(),
            )
            for block in blocks:
                self.link.send_apdu(block)
            raw = self._gbt_read(transfer)
        else:
            raise ProtocolError(
                f"{tag_name(apdu[0])} of {len(protected)} octets exceeds the server's "
                f"max-receive-pdu-size {self.max_request_size}"
                + ("" if self.gbt_negotiated else " (general-block-transfer not negotiated)")
            )
        skipped = 0
        while True:
            if raw and raw[0] == Tag.GENERAL_BLOCK_TRANSFER:
                raw = self._receive_gbt(raw, transfer)
            self._open_link_pushes()
            plain, unwrapped = self._unprotect(raw)
            if not plain:
                raise DecodeError("empty response APDU")
            if plain[0] in UNSOLICITED_TAGS:
                # A push on the association's connection (it carries a long
                # invoke id, never matched against ours). It passed every
                # check a reply would; queue the plaintext, since deciphering
                # it again would trip the replay check.
                log.info("queueing %s received while awaiting a response", tag_name(plain[0]))
                self.link.queue_push(plain, unwrapped, checked=True)
            elif _invoke_id_matches(apdu, plain):
                break
            else:
                # A late answer to an earlier request (after a timeout): drop
                # it and wait for ours.
                log.warning(
                    "discarding %s with invoke-id %s (expected %s)",
                    tag_name(plain[0]),
                    _invoke_id_text(plain),
                    _invoke_id_text(apdu),
                )
            skipped += 1
            if skipped > MAX_STALE_RESPONSES:
                raise ProtocolError(
                    f"{skipped} APDUs that are not the response to {tag_name(apdu[0])} "
                    "(pushes or a wrong invoke-id)"
                )
            raw = self._gbt_read(transfer)
        self._gbt_peer_window = transfer.peer_window
        self._gbt_peer_last = transfer.peer_last
        log.debug("APDU RX %s (%d octets)", tag_name(plain[0]), len(plain))
        log.log(TRACE, "APDU RX %s", "(HLS pass 3/4, withheld)" if sensitive else hexstr(plain))
        if self.state == AssociationState.ASSOCIATED:  # not HLS pass 3/4
            self._record("TX-APDU", apdu)
            self._record("RX-APDU", plain)
        if plain[0] == Tag.EXCEPTION_RESPONSE:
            exc = xdlms.decode_apdu(plain, strict=False)
            raise ServiceError(f"meter returned ExceptionResponse: {exc.describe()}", exc)
        if plain[0] == Tag.CONFIRMED_SERVICE_ERROR:
            err = xdlms.decode_apdu(plain, strict=False)
            raise ServiceError(f"confirmed service error: {err.describe()}", err)
        return plain

    def action_raw(self, method: xdlms.MethodDescriptor, parameters=None):
        """Run one ACTION request (parameters in one APDU); returns the return
        data or None. Return data the meter sends in pblocks is collected."""
        invoke = self.next_invoke_id()
        response = xdlms.decode_apdu(
            self.request(xdlms.ActionRequestNormal(invoke, method, parameters).to_bytes())
        )
        return self.action_result(invoke, response, method)

    def action_result(self, invoke: int, response, method):
        """Turn the final ACTION response into return data (or None).

        ``Action-Response-With-Pblock`` carries the return parameters in
        blocks the client fetches with ``Action-Request-Next-Pblock``; the
        reassembled octets are the return Data itself (no result field: a
        block-transferred response implies success)."""
        from pydlms.cosem.enums import ActionResult

        if isinstance(response, xdlms.ActionResponseWithPblock):
            return self._collect_action_pblocks(invoke, response, method)
        if not isinstance(response, xdlms.ActionResponseNormal):
            raise ProtocolError(f"unexpected ACTION response {type(response).__name__}")
        if response.result != ActionResult.SUCCESS:
            raise ServiceError(
                f"ACTION {method} failed: {result_name(response.result)}", response.result
            )
        if response.return_data is None:
            return None
        if not response.return_data.ok:
            raise ServiceError(
                f"ACTION {method} returned {result_name(response.return_data.error)}",
                response.return_data.error,
            )
        return response.return_data.data

    def _collect_action_pblocks(self, invoke: int, block, method):
        from pydlms.cosem.data import decode_data

        buffer = bytearray()
        expected = 1
        while True:
            if block.block_number != expected:
                raise ProtocolError(
                    f"ACTION {method} pblock {block.block_number} out of sequence "
                    f"(expected {expected})"
                )
            buffer += block.raw_data
            self._check_transfer_size(len(buffer))
            log.debug(
                "ACTION %s return pblock %d (%d octets, last=%s)",
                method,
                block.block_number,
                len(block.raw_data),
                block.last_block,
            )
            if block.last_block:
                break
            block = xdlms.decode_apdu(
                self.request(xdlms.ActionRequestNextPblock(invoke, block.block_number).to_bytes())
            )
            if not isinstance(block, xdlms.ActionResponseWithPblock):
                raise ProtocolError(f"expected an ACTION return pblock, got {type(block).__name__}")
            expected += 1
        value, end = decode_data(bytes(buffer))
        if end != len(buffer):
            raise DecodeError(f"{len(buffer) - end} trailing octets after ACTION return data")
        return value

    def sn_action_raw(self, address: int, parameters):
        """Invoke an SN method: a ReadRequest with parameterized access
        (selector 0, the method parameters) on the method's address.

        The return data comes back in the ReadResponse. This is the form
        GuruxDLMS.c, jDLMS and cB-Sigma use; Gurux.DLMS.Net sends a
        WriteRequest instead, which this client does not. Parameters too
        long for the server's PDU go in read-data-block-access blocks
        (:meth:`sn_request`); return data in data-block-results is fetched.
        """
        from pydlms.apdu.sn import ParameterizedAccess, ReadRequest

        response = self.sn_request(ReadRequest([ParameterizedAccess(address, 0, parameters)]))
        return self.sn_read_value(response, f"SN method at 0x{address:04X}")

    # -- short-name block transfer -----------------------------------------------------
    def sn_request(self, request):
        """Send an SN ``ReadRequest`` / ``WriteRequest`` and return the decoded
        response. A request longer than :meth:`max_plain_request` goes in
        general-block-transfer when GBT is in use (:attr:`uses_gbt`), else
        in read-/write-data-block-access blocks when block transfer with
        READ / WRITE was negotiated, else :class:`ProtocolError` is raised
        before anything is sent."""
        from pydlms.apdu.sn import decode_sn_apdu

        raw = request.to_bytes()
        if len(raw) <= self.max_plain_request() or self.uses_gbt:
            return decode_sn_apdu(self.request(raw))
        return self._sn_send_blocks(raw)

    def _sn_send_blocks(self, raw: bytes):
        """Send ``raw`` (a Read/WriteRequest) after its tag in data-block-access
        parts. Every part but the last must be acknowledged with its own
        block number; the reply to the last part answers the request."""
        from pydlms.apdu import sn
        from pydlms.cosem.data import DlmsData
        from pydlms.cosem.enums import DataAccessResult

        write = raw[0] == Tag.WRITE_REQUEST
        what = "WRITE" if write else "READ"
        bit = (
            Conformance.BLOCK_TRANSFER_WITH_SET_OR_WRITE
            if write
            else Conformance.BLOCK_TRANSFER_WITH_GET_OR_READ
        )
        if not self.negotiated_conformance & bit:
            raise ProtocolError(
                f"SN {what} request of {len(raw)} octets exceeds the server's "
                f"max-receive-pdu-size and {bit.name} was not negotiated"
            )

        def part(last: bool, number: int, chunk: bytes):
            if write:
                return sn.WriteRequest(
                    [sn.WriteDataBlockAccess(last, number)], [DlmsData.octet_string(chunk)]
                )
            return sn.ReadRequest([sn.ReadDataBlockAccess(last, number, chunk)])

        body = raw[1:]
        # 2 more octets cover the raw-data length growing from 1 to 3 octets.
        size = self.max_plain_request() - len(part(False, 1, b"").to_bytes()) - 2
        if size < 1:
            raise ProtocolError(
                f"server max PDU {self.max_request_size} leaves no room for block data"
            )
        chunks = [body[i : i + size] for i in range(0, len(body), size)]
        if len(chunks) > sn.MAX_SN_BLOCK_NUMBER:
            raise ProtocolError(
                f"SN {what} request needs {len(chunks)} blocks; block numbers are Unsigned16"
            )
        log.debug("SN %s request of %d octets in %d blocks", what, len(body), len(chunks))
        for number, chunk in enumerate(chunks, start=1):
            last = number == len(chunks)
            response = sn.decode_sn_apdu(self.request(part(last, number, chunk).to_bytes()))
            expected = sn.WriteResponse if write else sn.ReadResponse
            if not isinstance(response, expected) or len(response.results) != 1:
                raise ProtocolError(f"SN {what} block {number}: unexpected reply {response}")
            result = response.results[0]
            if isinstance(result, sn.WriteBlockNumber):
                acked = result.block_number
            elif isinstance(result, sn.ReadResult) and (
                result.data is None and result.error is None and result.raw_data is None
            ):
                acked = result.block_number
            else:
                acked = None
            if acked is not None and acked != number:
                raise ProtocolError(f"SN {what} block {number} acknowledged as block {acked}")
            if last:
                if acked is None:
                    return response
                if write:
                    # Some servers acknowledge the last part like the others.
                    log.debug("SN WRITE: last block acknowledged by number; taken as success")
                    return sn.WriteResponse([DataAccessResult.SUCCESS])
                raise ProtocolError(f"SN READ: last block {number} answered without data")
            if acked is None:
                error = result if write else result.error
                if error is not None and error != DataAccessResult.SUCCESS:
                    raise ServiceError(
                        f"SN {what} block {number} refused: {result_name(error)}", error
                    )
                raise ProtocolError(
                    f"SN {what} block {number} answered before the last block was sent"
                )
        raise AssertionError("unreachable")  # pragma: no cover

    def sn_read_value(self, response, what: str):
        """The data of a one-item SN ReadResponse, fetching the rest of a
        data-block-result with block-number-access; an error raises
        :class:`ServiceError`."""
        from pydlms.apdu import sn
        from pydlms.cosem.data import decode_data

        if not isinstance(response, sn.ReadResponse) or len(response.results) != 1:
            raise ProtocolError(f"{what}: expected a one-item ReadResponse, got {response}")
        result = response.results[0]
        if result.error is not None:
            raise ServiceError(f"{what} failed: {result_name(result.error)}", result.error)
        if result.raw_data is None:
            if result.data is None:
                raise ProtocolError(f"{what}: ReadResponse carries a bare block number")
            return result.data
        buffer = bytearray(result.raw_data)
        while not result.block_last:
            number = result.block_number
            response = sn.decode_sn_apdu(
                self.request(sn.ReadRequest([sn.BlockNumberAccess(number)]).to_bytes())
            )
            result = response.results[0] if len(response.results) == 1 else sn.ReadResult()
            if result.raw_data is None:
                if result.error is not None:
                    raise ServiceError(
                        f"{what}: block {number + 1} failed: {result_name(result.error)}",
                        result.error,
                    )
                raise ProtocolError("SN block transfer interrupted")
            if result.block_number != number + 1:
                raise ProtocolError(
                    f"{what}: block {result.block_number} out of sequence (expected {number + 1})"
                )
            buffer += result.raw_data
            self._check_transfer_size(len(buffer))
        value, end = decode_data(bytes(buffer))
        if end != len(buffer):
            raise DecodeError(f"{len(buffer) - end} trailing octets after block-transferred data")
        return value
