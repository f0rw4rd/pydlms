"""Security checks of a ciphered client association against a scripted meter.

Each test drives :class:`Association` with replies built by a server-side
:class:`SecurityContext` holding the same keys, so every reply is genuinely
protected and only the property under test is wrong.
"""

from __future__ import annotations

import pytest

pytest.importorskip("cryptography")

from pydlms.apdu import xdlms  # noqa: E402
from pydlms.apdu.acse import AARE, ApplicationContext  # noqa: E402
from pydlms.association import Association, AssociationSettings  # noqa: E402
from pydlms.cosem.data import DlmsData  # noqa: E402
from pydlms.exceptions import AuthenticationError  # noqa: E402
from pydlms.security.ciphering import wrap, wrap_general_glo  # noqa: E402
from pydlms.security.context import SecurityContext  # noqa: E402
from tests.test_association import INITIATE_RESPONSE, ScriptedLink  # noqa: E402

EK, AK = bytes(range(16)), bytes(range(16, 32))
CLIENT = b"CLIENT01"
SERVER = b"SERVER01"
GET_RESPONSE = xdlms.GetResponseNormal(0xC1, xdlms.GetDataResult(data=DlmsData.uint8(1))).to_bytes()
SET_RESPONSE = bytes.fromhex("c5 01 c1 00")
GET_REQUEST = bytes.fromhex("c0 01 c1 0001 0000010000ff 02 00")


def meter() -> SecurityContext:
    """The meter's side: its own title outbound, ours as the peer."""
    return SecurityContext(EK, AK, client_system_title=SERVER, server_system_title=CLIENT)


def associate(srv: SecurityContext, *replies) -> tuple[Association, ScriptedLink]:
    aare = AARE(
        ApplicationContext.LN_CIPHERED,
        0,
        responding_ap_title=SERVER,
        user_information=wrap(srv, INITIATE_RESPONSE),
    ).to_bytes()
    link = ScriptedLink([aare, *replies])
    assoc = Association(link, AssociationSettings(security=SecurityContext(EK, AK, CLIENT)))
    assoc.associate()
    return assoc, link


def test_genuine_reply_is_accepted():
    srv = meter()
    assoc, _ = associate(srv, lambda _: wrap(srv, GET_RESPONSE))
    assert assoc.request(GET_REQUEST) == GET_RESPONSE


def test_request_direction_envelope_is_refused():
    """A glo-get-request (0xC8) is never an answer, whatever it holds."""
    srv = meter()

    def reflected(_):
        apdu = wrap(srv, GET_REQUEST)
        assert apdu[0] == 0xC8
        return apdu

    assoc, _ = associate(srv, reflected)
    with pytest.raises(AuthenticationError, match="request"):
        assoc.request(GET_REQUEST)


def test_plaintext_must_match_the_envelope():
    """glo-get-response must hold a get-response, not e.g. a set-response."""
    srv = meter()

    def swapped(_):
        apdu = bytearray(wrap(srv, SET_RESPONSE))
        assert apdu[0] == 0xCD
        apdu[0] = 0xCC  # the tag is outside the authenticated data
        return bytes(apdu)

    assoc, _ = associate(srv, swapped)
    with pytest.raises(AuthenticationError, match="SET_RESPONSE"):
        assoc.request(GET_REQUEST)


def test_general_glo_must_carry_a_reply():
    srv = meter()
    assoc, _ = associate(srv, lambda _: wrap_general_glo(srv, GET_REQUEST))
    with pytest.raises(AuthenticationError, match="GET_REQUEST"):
        assoc.request(GET_REQUEST)


def test_general_glo_from_another_system_title_is_refused():
    """Our own APDU reflected in a general-glo envelope carries our title."""
    own = SecurityContext(EK, AK, client_system_title=CLIENT)
    srv = meter()
    assoc, _ = associate(srv, lambda _: wrap_general_glo(own, GET_RESPONSE))
    with pytest.raises(AuthenticationError, match="system title"):
        assoc.request(GET_REQUEST)


def test_initiate_response_envelope_must_match():
    srv = meter()
    aare = AARE(
        ApplicationContext.LN_CIPHERED,
        0,
        responding_ap_title=SERVER,
        user_information=bytes([0x28]) + wrap(srv, GET_RESPONSE)[1:],
    ).to_bytes()
    assoc = Association(
        ScriptedLink([aare]), AssociationSettings(security=SecurityContext(EK, AK, CLIENT))
    )
    with pytest.raises(AuthenticationError, match="GET_RESPONSE"):
        assoc.associate()


# --- HLS reflection -----------------------------------------------------------------------


class Reflector(ScriptedLink):
    """A fake meter that knows no secret: it answers the client's CtoS as its
    StoC and returns the client's own f(StoC) as f(CtoS). For mechanisms
    2/3/4 f depends only on the challenge and the secret, so without the
    StoC == CtoS check this passes pass 4; for mechanism 6 it also claims
    the client's system title."""

    def __init__(self, same_title: bool = False) -> None:
        super().__init__([])
        self.same_title = same_title

    def send_apdu(self, apdu):
        from pydlms.apdu.acse import AARQ
        from pydlms.cosem.enums import ActionResult

        self.sent.append(apdu)
        if apdu[0] == 0x60:
            aarq = AARQ.from_bytes(apdu)
            title = aarq.calling_ap_title if self.same_title else b"EVIL0001"
            self.responses.append(
                AARE(
                    aarq.application_context,
                    0,
                    1,
                    14,  # authentication-required
                    responding_ap_title=title,
                    mechanism=aarq.mechanism,
                    responding_authentication_value=aarq.calling_authentication_value,
                    user_information=INITIATE_RESPONSE,
                ).to_bytes()
            )
        else:
            request = xdlms.decode_apdu(apdu)
            echoed = DlmsData.octet_string(bytes(request.parameters.value))
            self.responses.append(
                xdlms.ActionResponseNormal(
                    apdu[2], ActionResult.SUCCESS, xdlms.GetDataResult(echoed)
                ).to_bytes()
            )


@pytest.mark.parametrize("mechanism", ["HLS", "HLS_MD5", "HLS_SHA1"])
def test_hls_reflected_challenge_is_refused(mechanism):
    from pydlms.association import AssociationState
    from pydlms.exceptions import AssociationError
    from pydlms.security.hls import Mechanism

    link = Reflector()
    assoc = Association(
        link, AssociationSettings(mechanism=Mechanism[mechanism], secret=b"real-secret-1234")
    )
    with pytest.raises(AssociationError, match="StoC equals") as info:
        assoc.associate()
    assert isinstance(info.value.__cause__, AuthenticationError)
    assert assoc.state == AssociationState.IDLE
    assert len(link.sent) == 1  # f(StoC) was never sent


def test_hls_sha256_reflected_title_is_refused():
    from pydlms.exceptions import AssociationError
    from pydlms.security.hls import Mechanism

    link = Reflector(same_title=True)
    settings = AssociationSettings(
        mechanism=Mechanism.HLS_SHA256, secret=b"real-secret-1234", client_system_title=CLIENT
    )
    with pytest.raises(AssociationError, match="our own system title"):
        Association(link, settings).associate()
    assert len(link.sent) == 1


def test_ciphered_aare_with_our_own_title_is_refused():
    """Same title on both sides means the meter's IVs are ours: refused."""
    from pydlms.exceptions import AssociationError

    own = SecurityContext(EK, AK, client_system_title=CLIENT)
    aare = AARE(
        ApplicationContext.LN_CIPHERED,
        0,
        responding_ap_title=CLIENT,
        user_information=wrap(own, INITIATE_RESPONSE),
    ).to_bytes()
    settings = AssociationSettings(security=SecurityContext(EK, AK, CLIENT))
    with pytest.raises(AssociationError, match="our own system title"):
        Association(ScriptedLink([aare]), settings).associate()


# --- the InitiateRequest carrying a dedicated key ---------------------------------------


def _dedicated_association(initiate_reply):
    """Client under an encryption-only policy proposing a dedicated key."""
    from pydlms.security.suites import SecurityPolicy

    srv = SecurityContext(
        EK,
        AK,
        client_system_title=SERVER,
        server_system_title=CLIENT,
        policy=SecurityPolicy.ENCRYPTED,
    )
    aare = AARE(
        ApplicationContext.LN_CIPHERED,
        0,
        responding_ap_title=SERVER,
        user_information=initiate_reply(srv),
    ).to_bytes()
    link = ScriptedLink([aare])
    client_ctx = SecurityContext(EK, AK, CLIENT, policy=SecurityPolicy.ENCRYPTED)
    settings = AssociationSettings(security=client_ctx, use_dedicated_key=True)
    return Association(link, settings), link


def _ae(srv):
    from pydlms.security.suites import SecurityControl

    return wrap(srv, INITIATE_RESPONSE, sc=SecurityControl.from_byte(0x30))


def test_dedicated_key_travels_authenticated_and_encrypted():
    from pydlms.apdu.acse import AARQ

    assoc, link = _dedicated_association(_ae)
    assoc.associate()
    user_info = AARQ.from_bytes(link.sent[0]).user_information
    assert user_info[0] == 0x21  # glo-initiate-request
    assert user_info[2] == 0x30  # SC: authenticated and encrypted, despite the policy


@pytest.mark.parametrize(
    "reply",
    [lambda srv: INITIATE_RESPONSE, lambda srv: wrap(srv, INITIATE_RESPONSE)],
    ids=["plain", "enc-only"],
)
def test_answer_to_a_dedicated_key_must_be_authenticated_and_encrypted(reply):
    from pydlms.exceptions import SecurityError

    assoc, _ = _dedicated_association(reply)
    with pytest.raises(SecurityError, match="dedicated key"):
        assoc.associate()


# --- a non-ciphered application context ---------------------------------------------


def _plain_context(protection: str = "glo", **kw):
    from tests.test_association import AARE_OK

    link = ScriptedLink([AARE_OK, GET_RESPONSE])
    settings = AssociationSettings(
        security=SecurityContext(EK, AK, CLIENT),
        ciphered_context=False,
        protection=protection,
        **kw,
    )
    return Association(link, settings), link


@pytest.mark.parametrize("protection", ["glo", "general-glo"])
def test_plain_context_exchanges_plain_apdus(protection):
    """LN/SN without ciphering: xDLMS APDUs travel in clear even when a
    security context is configured (e.g. for HLS-GMAC keys, Gurux
    LN-v2-GMac); the meter answers in clear."""
    assoc, link = _plain_context(protection)
    assoc.associate()
    assert assoc.request(GET_REQUEST) == GET_RESPONSE
    assert link.sent[-1] == GET_REQUEST


def test_ciphered_context_still_requires_protection():
    from pydlms.exceptions import ProtocolError

    srv = meter()
    assoc, _ = associate(srv, GET_RESPONSE)
    with pytest.raises(ProtocolError, match="unprotected"):
        assoc.request(GET_REQUEST)


# --- C2: the meter's system title can be pinned ------------------------------------------

OTHER = b"OTHERMTR"


def _pinned(responding_ap_title, *, expected=None, server_title=None, user_information=None):
    """A client pinned by ``expected`` (AssociationSettings) and/or
    ``server_title`` (SecurityContext), against an AARE from ``responding_ap_title``."""
    srv = meter()
    if user_information is None:
        user_information = wrap(srv, INITIATE_RESPONSE)
    aare = AARE(
        ApplicationContext.LN_CIPHERED,
        0,
        responding_ap_title=responding_ap_title,
        user_information=user_information,
    ).to_bytes()
    link = ScriptedLink([aare])
    ctx = SecurityContext(EK, AK, CLIENT, server_system_title=server_title)
    settings = AssociationSettings(security=ctx, expected_server_system_title=expected)
    return Association(link, settings), link, ctx


def test_expected_server_title_is_validated():
    with pytest.raises(ValueError, match="8 octets"):
        AssociationSettings(expected_server_system_title=b"SHORT")


def test_context_records_whether_the_peer_title_was_configured():
    assert not SecurityContext(EK, AK, CLIENT).peer_title_pinned
    assert SecurityContext(EK, AK, CLIENT, server_system_title=SERVER).peer_title_pinned


@pytest.mark.parametrize("where", ["settings", "context", "both"])
def test_matching_pin_associates(where):
    expected = SERVER if where in ("settings", "both") else None
    server_title = SERVER if where in ("context", "both") else None
    assoc, _, ctx = _pinned(SERVER, expected=expected, server_title=server_title)
    assoc.associate()
    assert assoc.server_system_title == SERVER and ctx.server_system_title == SERVER


@pytest.mark.parametrize("where", ["settings", "context"])
def test_pin_mismatch_raises_before_the_user_information_is_opened(where):
    from pydlms.association import AssociationState
    from pydlms.exceptions import AssociationError

    # A user-information that would fail authentication if it were opened:
    # the mismatch must be reported first, as an AssociationError.
    forged = bytes([0x28, 0x1F, 0x30]) + bytes(30)
    assoc, link, ctx = _pinned(
        OTHER,
        expected=SERVER if where == "settings" else None,
        server_title=SERVER if where == "context" else None,
        user_information=forged,
    )
    with pytest.raises(AssociationError, match=OTHER.hex()):
        assoc.associate()
    assert assoc.state == AssociationState.IDLE
    assert len(link.sent) == 1
    # A configured title is never overwritten by the AARE.
    assert ctx.server_system_title == (SERVER if where == "context" else None)
    assert assoc.server_system_title is None


def test_pin_requires_a_responding_ap_title():
    from pydlms.exceptions import AssociationError

    assoc, _, _ = _pinned(None, expected=SERVER)
    with pytest.raises(AssociationError, match="no responding-AP-title"):
        assoc.associate()


def test_rejected_aare_without_title_reports_the_rejection():
    from pydlms.exceptions import AssociationError

    aare = AARE(ApplicationContext.LN_CIPHERED, 1, 1, 13).to_bytes()
    settings = AssociationSettings(
        security=SecurityContext(EK, AK, CLIENT), expected_server_system_title=SERVER
    )
    with pytest.raises(AssociationError, match="rejected") as info:
        Association(ScriptedLink([aare]), settings).associate()
    assert info.value.result == 1 and info.value.diagnostic == 13


def test_unpinned_context_takes_the_title_from_the_aare():
    assoc, _, ctx = _pinned(SERVER)
    assoc.associate()
    assert ctx.server_system_title == SERVER
    assert not ctx.peer_title_pinned  # learnt, not configured: a reconnect may differ


@pytest.mark.parametrize("mechanism", ["HLS_SHA256", "HLS_GMAC"])
def test_pin_mismatch_raises_before_hls_pass_3(mechanism):
    """Plain context: f(StoC) must never reach a meter that is not the pinned one."""
    from pydlms.exceptions import AssociationError
    from pydlms.security.hls import Mechanism

    link = Reflector()  # answers with title EVIL0001
    settings = AssociationSettings(
        mechanism=Mechanism[mechanism],
        secret=b"real-secret-1234",
        client_system_title=CLIENT,
        expected_server_system_title=SERVER,
    )
    if mechanism == "HLS_GMAC":
        settings.security = SecurityContext(EK, AK, CLIENT)
        settings.ciphered_context = False
    with pytest.raises(AssociationError, match="pinned"):
        Association(link, settings).associate()
    assert len(link.sent) == 1


def test_contradicting_pins_are_refused_at_construction():
    from pydlms.exceptions import SecurityError

    settings = AssociationSettings(
        security=SecurityContext(EK, AK, CLIENT, server_system_title=SERVER),
        expected_server_system_title=OTHER,
    )
    with pytest.raises(SecurityError, match="contradicts"):
        Association(ScriptedLink([]), settings)


def test_pin_contradicting_the_peer_certificate_is_refused_at_construction():
    from pydlms.exceptions import SecurityError
    from pydlms.security import ec
    from tests.crypto.test_certificates import make_cert

    server_key = ec.generate_private_key(1)
    ctx = SecurityContext(
        bytes(16),
        AK,
        CLIENT,
        suite=1,
        signing_key=ec.generate_private_key(1),
        peer_certificate=make_cert(server_key, common_names=(SERVER.hex().upper(),)),
    )
    assert ctx.peer_title_pinned
    with pytest.raises(SecurityError, match="peer certificate"):
        Association(
            ScriptedLink([]),
            AssociationSettings(security=ctx, expected_server_system_title=OTHER),
        )
    # The same title is fine.
    Association(
        ScriptedLink([]), AssociationSettings(security=ctx, expected_server_system_title=SERVER)
    )
