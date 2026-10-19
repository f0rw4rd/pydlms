"""The ciphered release: RLRQ re-ciphers the InitiateRequest, the RLRE is verified.

Known answers: IEC 62056-5-3:2023 annex E.7 (RLRQ) and E.8 (RLRE) via
cB-Sigma 26360a1 (see :mod:`tests.crypto.vectors`). The RLRE's
user-information must be a glo-/ded-InitiateResponse that opens under the
policy and inbound counter checks, authenticated and encrypted when a
dedicated key was sent; ``Association.release_status`` reports the outcome
and ``require_verified_release`` turns anything but "verified" into
:class:`AuthenticationError` (after the association is already IDLE).
"""

from __future__ import annotations

import os

import pytest

from pydlms.apdu.acse import AARE, RLRE, ApplicationContext
from pydlms.apdu.xdlms import Conformance
from pydlms.association import Association, AssociationSettings, AssociationState
from pydlms.exceptions import AuthenticationError
from pydlms.security.ciphering import wrap
from pydlms.security.context import SecurityContext
from pydlms.security.suites import SecurityControl, SecurityPolicy
from tests.crypto.vectors import (
    E2_DEDICATED_KEY,
    E2_INITIATE_REQUEST,
    E5_INITIATE_RESPONSE,
    E7_RLRQ,
    E8_RLRE,
    E8_USER_INFO,
    E_IC,
    E_SYSTEM_TITLE,
    GB_AK,
    GB_EK,
)
from tests.test_association import AARE_OK, ScriptedLink

CLIENT = b"CLIENT01"
SERVER = b"SERVER01"
AE = SecurityControl.from_byte(0x30)
#: The Gurux.DLMS.Net simulator's RLRE, wrong BER lengths and all
#: (tests/integration/gurux/README.md).
GURUX_RLRE = bytes.fromhex("6311800100BE0F040E0800065F1F040000001004000007")


def _meter(title: bytes, peer: bytes, ic: int = 1, **kw) -> SecurityContext:
    return SecurityContext(
        GB_EK,
        GB_AK,
        client_system_title=title,
        server_system_title=peer,
        invocation_counter=ic,
        **kw,
    )


def _associated(
    rlre,
    *,
    meter_title: bytes = E_SYSTEM_TITLE,
    meter_ic: int = 1,
    dedicated: bool = True,
    policy: SecurityPolicy = SecurityPolicy.AUTHENTICATED_ENCRYPTED,
    strict: bool = False,
):
    """A ciphered association with the meter ``meter_title``; the RLRQ is
    answered by ``rlre(meter_context)`` (or ``rlre`` itself when bytes)."""
    srv = _meter(meter_title, CLIENT, meter_ic, policy=policy)
    aare = AARE(
        ApplicationContext.LN_CIPHERED,
        0,
        responding_ap_title=meter_title,
        user_information=wrap(srv, E5_INITIATE_RESPONSE, sc=AE if dedicated else None),
    ).to_bytes()
    link = ScriptedLink([aare, rlre if isinstance(rlre, bytes) else (lambda _: rlre(srv))])
    ctx = SecurityContext(GB_EK, GB_AK, CLIENT, policy=policy)
    settings = AssociationSettings(
        security=ctx, use_dedicated_key=dedicated, require_verified_release=strict
    )
    assoc = Association(link, settings)
    assoc.associate()
    assert assoc.release_status is None
    return assoc, link


def _rlre(user_information: bytes) -> bytes:
    return RLRE(0, user_information).to_bytes()


# --- known answers -------------------------------------------------------------------------


def test_e7_is_our_rlrq(monkeypatch):
    """Our RLRQ at IC 0x01234567 re-ciphers the AARQ's InitiateRequest (the
    E.2 one, with its dedicated key) into exactly the annex E.7 bytes."""
    real = os.urandom
    monkeypatch.setattr(os, "urandom", lambda n: E2_DEDICATED_KEY if n == 16 else real(n))
    srv = _meter(SERVER, E_SYSTEM_TITLE)
    aare = AARE(
        ApplicationContext.LN_CIPHERED,
        0,
        responding_ap_title=SERVER,
        user_information=wrap(srv, E5_INITIATE_RESPONSE, sc=AE),
    ).to_bytes()
    link = ScriptedLink([aare, lambda _: _rlre(wrap(srv, E5_INITIATE_RESPONSE, sc=AE))])
    ctx = SecurityContext(GB_EK, GB_AK, E_SYSTEM_TITLE, invocation_counter=E_IC - 1)
    settings = AssociationSettings(
        security=ctx,
        use_dedicated_key=True,
        conformance=Conformance(0x007E1F),
        max_receive_pdu_size=0x04B0,
    )
    assoc = Association(link, settings)
    assoc.associate()
    assert assoc._initiate_plain == E2_INITIATE_REQUEST
    assoc.release()
    assert link.sent[-1] == E7_RLRQ
    assert assoc.release_status == "verified"


def test_e8_verifies_the_release():
    assoc, _ = _associated(E8_RLRE, strict=True)
    assoc.release()
    assert assoc.release_status == "verified"
    assert assoc.state == AssociationState.IDLE


# --- tamper and negative cases ----------------------------------------------------------


@pytest.mark.parametrize("position", range(E8_USER_INFO.stop - E8_USER_INFO.start))
def test_tampered_e8_fails(position):
    tampered = bytearray(E8_RLRE)
    tampered[E8_USER_INFO.start + position] ^= 0x01
    assoc, _ = _associated(bytes(tampered))
    assoc.release()  # the default never raises
    assert assoc.release_status == "failed"
    assert assoc.state == AssociationState.IDLE

    strict, _ = _associated(bytes(tampered), strict=True)
    with pytest.raises(AuthenticationError, match="failed"):
        strict.release()
    assert strict.release_status == "failed"
    assert strict.state == AssociationState.IDLE


def test_replayed_counter_fails():
    """The AARE used IC 0x01234567 already: the E.8 RLRE is a replay."""
    assoc, _ = _associated(E8_RLRE, meter_ic=E_IC, strict=True)
    with pytest.raises(AuthenticationError) as info:
        assoc.release()
    assert assoc.release_status == "failed"
    assert "stale invocation counter" in str(info.value.__cause__)


@pytest.mark.parametrize(
    ("policy", "sc"),
    [(SecurityPolicy.AUTHENTICATED, 0x10), (SecurityPolicy.ENCRYPTED, 0x20)],
    ids=["auth-only", "enc-only"],
)
def test_weaker_protection_after_a_dedicated_key_fails(policy, sc):
    def answer(srv):
        return _rlre(wrap(srv, E5_INITIATE_RESPONSE, sc=SecurityControl.from_byte(sc)))

    # The AARE answer is authenticated and encrypted, as the dedicated key requires.
    assoc, _ = _associated(answer, policy=policy, strict=True)
    with pytest.raises(AuthenticationError) as info:
        assoc.release()
    assert assoc.release_status == "failed"
    assert "dedicated key" in str(info.value.__cause__)


def test_auth_only_without_a_dedicated_key_verifies():
    def answer(srv):
        return _rlre(wrap(srv, E5_INITIATE_RESPONSE, sc=SecurityControl.from_byte(0x10)))

    assoc, _ = _associated(
        answer, policy=SecurityPolicy.AUTHENTICATED, dedicated=False, strict=True
    )
    assoc.release()
    assert assoc.release_status == "verified"


def test_encryption_only_is_unverified():
    """Nothing authenticates an encryption-only RLRE: not "verified"."""

    def answer(srv):
        return _rlre(wrap(srv, E5_INITIATE_RESPONSE))

    assoc, _ = _associated(answer, policy=SecurityPolicy.ENCRYPTED, dedicated=False)
    assoc.release()
    assert assoc.release_status == "unverified"


@pytest.mark.parametrize(
    "answer",
    [
        lambda srv: _rlre(E5_INITIATE_RESPONSE),  # plain InitiateResponse
        lambda srv: _rlre(wrap(srv, E2_INITIATE_REQUEST, sc=AE)),  # glo-initiateRequest
        lambda srv: _rlre(bytes([0x28]) + wrap(srv, bytes.fromhex("c4 01 c1 00 11 01"), sc=AE)[1:]),
        lambda srv: _rlre(
            wrap(srv, bytes.fromhex("0e 01 06 00"), sc=AE)
        ),  # glo-ConfirmedServiceError
        lambda srv: AARE_OK,  # not an RLRE at all
        lambda srv: GURUX_RLRE,  # malformed BER
    ],
    ids=["plain-initiate", "request-envelope", "tag-swap", "service-error", "aare", "gurux"],
)
def test_wrong_answers_fail(answer):
    assoc, _ = _associated(answer)
    assoc.release()
    assert assoc.release_status == "failed"
    strict, _ = _associated(answer, strict=True)
    with pytest.raises(AuthenticationError):
        strict.release()
    assert strict.state == AssociationState.IDLE


def test_rlre_without_user_information_is_unverified():
    assoc, _ = _associated(_rlre(b""))
    assoc.release()
    assert assoc.release_status == "unverified"
    strict, _ = _associated(_rlre(b""), strict=True)
    with pytest.raises(AuthenticationError, match="unverified"):
        strict.release()
    assert strict.state == AssociationState.IDLE


def test_no_answer_fails():
    assoc, link = _associated(E8_RLRE, strict=True)
    link.responses.clear()  # the link raises: no RLRE at all
    with pytest.raises(AuthenticationError, match="failed"):
        assoc.release()
    assert assoc.release_status == "failed"


def test_plain_context_release_is_plain():
    link = ScriptedLink([AARE_OK, _rlre(b""), AARE_OK, GURUX_RLRE])
    assoc = Association(link, AssociationSettings(require_verified_release=True))
    assoc.associate()
    assoc.release()  # nothing to verify in a plain context: never raises
    assert assoc.release_status == "plain"
    assoc.associate()
    assert assoc.release_status is None  # reset on associate
    assoc.release()
    assert assoc.release_status == "failed"


def test_release_status_is_reset_on_associate():
    assoc, link = _associated(E8_RLRE)
    assoc.release()
    assert assoc.release_status == "verified"
    srv = _meter(E_SYSTEM_TITLE, CLIENT, E_IC + 1)
    link.responses.append(
        AARE(
            ApplicationContext.LN_CIPHERED,
            0,
            responding_ap_title=E_SYSTEM_TITLE,
            user_information=wrap(srv, E5_INITIATE_RESPONSE, sc=AE),
        ).to_bytes()
    )
    assoc.associate()
    assert assoc.release_status is None
