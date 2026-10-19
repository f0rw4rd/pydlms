"""Broadcast-key send.

``Association.send_broadcast`` ciphers an unconfirmed service request with
the global broadcast key (security control bit 6, IEC 62056-5-3 Table 39)
and sends it to the all-station address of the link: wPort 0x007F on the
wrapper, an HDLC UI frame to the all-station server address.

Known-answer test: none exists. No published vector covers the broadcast
key (Green Book 9.2.7.2 / IEC 62056-5-3 annex vectors use the unicast key
only), so it is replaced by (a) the Green Book GCM vector self-consistency
already pinned in ``test_gcm_greenbook.py`` (the same ``gcm.encrypt`` with
the key and security control the broadcast path selects), (b) a
reconstruction here that recomputes the expected ciphertext with
``gcm.encrypt`` and the broadcast key directly, and (c) the go-dlms and
Gurux.DLMS.Net ``decrypt`` oracles (``tests/interop``, ``-m integration``).
"""

from __future__ import annotations

import logging

import pytest

from pydlms.apdu import xdlms
from pydlms.apdu.acse import AARE, ApplicationContext
from pydlms.apdu.tags import PLAIN_FOR_CIPHERED, Tag
from pydlms.association import Association, AssociationSettings, AssociationState
from pydlms.client import DlmsClient
from pydlms.cosem.data import DlmsData
from pydlms.debug import TRACE
from pydlms.exceptions import (
    AuthenticationError,
    DecodeError,
    KeyMissingError,
    ProtocolError,
    SecurityError,
)
from pydlms.hdlc.address import HdlcAddress
from pydlms.hdlc.connection import HdlcLink
from pydlms.hdlc.framing import decode_frame
from pydlms.obis import ObisCode
from pydlms.security import gcm
from pydlms.security.ciphering import unwrap, wrap
from pydlms.security.context import SecurityContext
from pydlms.security.suites import SecurityControl, SecurityPolicy
from pydlms.transports.base import LoopbackTransport
from pydlms.wrapper import WPORT_BROADCAST, WrapperLink, decode_wrapper
from tests.test_association import AARE_OK, INITIATE_RESPONSE, ScriptedLink

EK = bytes.fromhex("A1A2A3A4A5A6A7A8A9AAABACADAEAFB0")
AK = bytes.fromhex("B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0")
BK = bytes.fromhex("E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0")
CLIENT = b"CLIENT01"
SERVER = b"SERVER01"

# set-request-normal, Invoke-Id-And-Priority 0x81 (high priority, service
# class unconfirmed, invoke id 1), Data 0.0.96.1.0.255 attribute 2,
# visible-string "A".
UNCONFIRMED_SET = bytes.fromhex("c1 01 81 0001 0000600100ff 02 00 0a 01 41".replace(" ", ""))
UNCONFIRMED_GET = bytes.fromhex("c0 01 01 0003 0100010800ff 02 00".replace(" ", ""))
UNCONFIRMED_ACTION = bytes.fromhex("c3 01 01 0046 0000600300ff 01 00".replace(" ", ""))
SN_UNCONFIRMED_WRITE = bytes.fromhex("16 01 02 00 0200 0f 01".replace(" ", ""))
GET_RESPONSE = xdlms.GetResponseNormal(0xC1, xdlms.GetDataResult(data=DlmsData.uint8(1))).to_bytes()
GET_REQUEST = bytes.fromhex("c0 01 c1 0001 0000010000ff 02 00".replace(" ", ""))


class BroadcastLink(ScriptedLink):
    """ScriptedLink that records unconfirmed sends with their broadcast flag."""

    def __init__(self, responses):
        super().__init__(responses)
        self.unconfirmed: list[tuple[bytes, bool]] = []

    def send_unconfirmed(self, apdu: bytes, broadcast: bool = False) -> None:
        self.unconfirmed.append((apdu, broadcast))
        self.sent.append(apdu)


def meter(broadcast_key: bytes | None = BK, **kw) -> SecurityContext:
    """The meter's side: its own title outbound, ours as the peer."""
    return SecurityContext(
        EK, AK, client_system_title=SERVER, server_system_title=CLIENT,
        broadcast_key=broadcast_key, **kw,
    )  # fmt: skip


def client_ctx(broadcast_key: bytes | None = BK, **kw) -> SecurityContext:
    return SecurityContext(EK, AK, CLIENT, broadcast_key=broadcast_key, **kw)


def associate(*replies, protection="glo", **ctx_kw) -> tuple[Association, BroadcastLink]:
    srv = meter()
    aare = AARE(
        ApplicationContext.LN_CIPHERED,
        0,
        responding_ap_title=SERVER,
        user_information=wrap(srv, INITIATE_RESPONSE),
    ).to_bytes()
    link = BroadcastLink([aare, *replies])
    settings = AssociationSettings(security=client_ctx(**ctx_kw), protection=protection)
    assoc = Association(link, settings)
    assoc.associate()
    return assoc, link


def _ic(apdu: bytes) -> int:
    """The invocation counter of a glo- or general-glo APDU."""
    if apdu[0] == Tag.GENERAL_GLO_CIPHERING:
        start = 2 + apdu[1]
        start += 1 if apdu[start] < 0x80 else 1 + (apdu[start] & 0x7F)
    else:
        start = 2 if apdu[1] < 0x80 else 2 + (apdu[1] & 0x7F)
    return int.from_bytes(apdu[start + 1 : start + 5], "big")


# --- what goes out --------------------------------------------------------------


@pytest.mark.parametrize(
    "plain,envelope",
    [
        (UNCONFIRMED_SET, Tag.GLO_SET_REQUEST),
        (UNCONFIRMED_GET, Tag.GLO_GET_REQUEST),
        (UNCONFIRMED_ACTION, Tag.GLO_ACTION_REQUEST),
        (SN_UNCONFIRMED_WRITE, Tag.GLO_UNCONFIRMED_WRITE_REQUEST),
    ],
)
def test_broadcast_is_ciphered_with_the_broadcast_key(plain, envelope):
    assoc, link = associate()
    assoc.send_broadcast(plain)
    ((apdu, broadcast),) = link.unconfirmed
    assert broadcast is True
    assert apdu[0] == envelope
    sc = SecurityControl.from_byte(apdu[2])
    assert sc.broadcast_key and sc.authenticated and sc.encrypted
    assert unwrap(meter(), apdu).plaintext == plain


def test_broadcast_matches_an_independent_gcm_reconstruction():
    """Self-consistency in place of a KAT (none is published for the
    broadcast key): the body is gcm.encrypt (pinned to the Green Book
    vector) under the broadcast key, the client title and the IC drawn."""
    assoc, link = associate()
    ic = assoc.security.invocation_counter
    assoc.send_broadcast(UNCONFIRMED_SET)
    ((apdu, _),) = link.unconfirmed
    sc = SecurityControl.from_byte(0x70)
    body = gcm.encrypt(sc, BK, AK, CLIENT, ic, UNCONFIRMED_SET)
    content = bytes([0x70]) + ic.to_bytes(4, "big") + body
    assert apdu == bytes([Tag.GLO_SET_REQUEST, len(content)]) + content


def test_broadcast_general_glo_carries_the_broadcast_key_bit():
    assoc, link = associate(protection="general-glo")
    assoc.send_broadcast(UNCONFIRMED_SET)
    ((apdu, _),) = link.unconfirmed
    assert apdu[0] == Tag.GENERAL_GLO_CIPHERING
    assert apdu[2:10] == CLIENT
    result = unwrap(meter(), apdu)
    assert result.security_control.broadcast_key
    assert result.plaintext == UNCONFIRMED_SET


@pytest.mark.parametrize(
    "policy,sc",
    [
        (SecurityPolicy.AUTHENTICATED, 0x50),
        (SecurityPolicy.ENCRYPTED, 0x60),
        (SecurityPolicy.AUTHENTICATED_ENCRYPTED, 0x70),
    ],
)
def test_broadcast_follows_the_policy(policy, sc):
    assoc, link = associate(policy=policy)
    assoc.send_broadcast(UNCONFIRMED_SET)
    ((apdu, _),) = link.unconfirmed
    assert apdu[2] == sc
    assert unwrap(meter(policy=policy), apdu).plaintext == UNCONFIRMED_SET


def test_broadcast_never_uses_the_dedicated_key():
    assoc, link = associate()
    assoc.settings.use_dedicated_key = True
    assoc.security.set_dedicated_key(bytes(range(16)))
    assoc.send_broadcast(UNCONFIRMED_SET)
    ((apdu, _),) = link.unconfirmed
    assert apdu[0] == Tag.GLO_SET_REQUEST  # not ded-
    assert unwrap(meter(), apdu).plaintext == UNCONFIRMED_SET


def test_unicast_key_does_not_open_a_broadcast():
    assoc, link = associate()
    assoc.send_broadcast(UNCONFIRMED_SET)
    ((apdu, _),) = link.unconfirmed
    with pytest.raises(AuthenticationError):
        unwrap(meter(broadcast_key=EK), apdu)  # the unicast key in the broadcast slot
    with pytest.raises(KeyMissingError):
        unwrap(meter(broadcast_key=None), apdu)


# --- invocation counter -------------------------------------------------------------


def test_ic_is_shared_with_unicast_and_never_reused():
    srv = meter(invocation_counter=100)  # past the AARE's IC
    assoc, link = associate(lambda _: wrap(srv, GET_RESPONSE))
    first = assoc.security.invocation_counter
    assoc.send_broadcast(UNCONFIRMED_SET)
    assoc.send_unconfirmed(UNCONFIRMED_SET)
    assoc.request(GET_REQUEST)
    assoc.send_broadcast(UNCONFIRMED_ACTION)
    sent = link.sent[1:]  # after the AARQ
    ics = [_ic(apdu) for apdu in sent]
    assert ics == [first, first + 1, first + 2, first + 3]
    assert [b for _, b in link.unconfirmed] == [True, False, True]
    assert assoc.security.invocation_counter == first + 4
    # IC 0 went into the AARQ's glo-InitiateRequest, from the same counter.
    assert first == 1


def test_send_broadcast_takes_no_counter_argument():
    import inspect

    assert list(inspect.signature(Association.send_broadcast).parameters) == ["self", "apdu"]


def test_exhausted_counter_refuses_a_broadcast():
    assoc, link = associate()
    assoc.security.set_invocation_counter(0xFFFFFFFF)
    assoc.send_broadcast(UNCONFIRMED_SET)
    from pydlms.exceptions import ReplayError

    with pytest.raises(ReplayError):
        assoc.send_broadcast(UNCONFIRMED_SET)
    assert len(link.unconfirmed) == 1


# --- refusals ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "apdu",
    [
        UNCONFIRMED_SET[:2] + b"\xc1" + UNCONFIRMED_SET[3:],  # confirmed SET
        bytes.fromhex("c0 01 c1 0003 0100010800ff 02 00".replace(" ", "")),  # confirmed GET
        bytes.fromhex("c3 01 41 0046 0000600300ff 01 00".replace(" ", "")),  # confirmed ACTION
        bytes.fromhex("d9 00000001 00 00 00".replace(" ", "")),  # ACCESS, even unconfirmed
        bytes.fromhex("05 01 02 0200".replace(" ", "")),  # SN ReadRequest
        bytes.fromhex("62 00".replace(" ", "")),  # RLRQ
        b"",
    ],
)
def test_refuses_confirmed_and_other_services(apdu):
    assoc, link = associate()
    counter = assoc.security.invocation_counter
    with pytest.raises(ProtocolError):
        assoc.send_broadcast(apdu)
    assert link.unconfirmed == []
    assert assoc.security.invocation_counter == counter


def test_refuses_without_a_broadcast_key():
    assoc, link = associate(broadcast_key=None)
    counter = assoc.security.invocation_counter
    with pytest.raises(KeyMissingError, match="broadcast"):
        assoc.send_broadcast(UNCONFIRMED_SET)
    assert link.unconfirmed == []
    assert assoc.security.invocation_counter == counter  # no IC spent


def test_refuses_without_an_authentication_key_when_the_policy_needs_one():
    assoc, link = associate()
    assoc.security.authentication_key = None
    counter = assoc.security.invocation_counter
    with pytest.raises(KeyMissingError, match="authentication"):
        assoc.send_broadcast(UNCONFIRMED_SET)
    assert assoc.security.invocation_counter == counter


def test_refuses_a_plain_association():
    link = BroadcastLink([AARE_OK])
    assoc = Association(link)
    assoc.associate()
    with pytest.raises(ProtocolError, match="ciphered"):
        assoc.send_broadcast(UNCONFIRMED_SET)
    assert link.unconfirmed == []


def test_refuses_a_plain_context_with_keys_for_hls_only():
    """A security context in a non-ciphered LN context protects nothing with
    glo- ciphering (protects_services is False): no clear broadcast."""
    link = BroadcastLink([AARE_OK])
    settings = AssociationSettings(security=client_ctx(), ciphered_context=False)
    assoc = Association(link, settings)
    assoc.state = AssociationState.ASSOCIATED
    with pytest.raises(ProtocolError, match="ciphered"):
        assoc.send_broadcast(UNCONFIRMED_SET)
    assert link.unconfirmed == []


def test_refuses_a_policy_that_protects_nothing():
    assoc, link = associate()
    assoc.security.policy = SecurityPolicy.NONE
    with pytest.raises(ProtocolError, match="policy"):
        assoc.send_broadcast(UNCONFIRMED_SET)
    assert link.unconfirmed == []


@pytest.mark.parametrize("protection", ["general-ciphering", "general-signing", "glo+signing"])
def test_refuses_protections_without_a_broadcast_form(protection):
    assoc, link = associate()
    assoc.settings.protection = protection
    counter = assoc.security.invocation_counter
    with pytest.raises(ProtocolError, match="glo"):
        assoc.send_broadcast(UNCONFIRMED_SET)
    assert assoc.security.invocation_counter == counter


def test_refuses_when_not_associated():
    link = BroadcastLink([])
    assoc = Association(link, AssociationSettings(security=client_ctx()))
    with pytest.raises(ProtocolError, match="not associated"):
        assoc.send_broadcast(UNCONFIRMED_SET)
    assert link.sent == []


def test_refuses_an_apdu_over_the_server_pdu_size_before_ciphering():
    assoc, link = associate()  # server max-receive-pdu-size 512
    big = UNCONFIRMED_SET[:-3] + b"\x09\x82\x01\xf0" + bytes(0x1F0)
    counter = assoc.security.invocation_counter
    with pytest.raises(ProtocolError, match="max-receive-pdu-size"):
        assoc.send_broadcast(big)
    assert assoc.security.invocation_counter == counter


def test_link_without_broadcast_address_refuses():
    """The base ApduLink has no all-station address."""
    srv = meter()
    aare = AARE(
        ApplicationContext.LN_CIPHERED,
        0,
        responding_ap_title=SERVER,
        user_information=wrap(srv, INITIATE_RESPONSE),
    ).to_bytes()
    link = ScriptedLink([aare])
    assoc = Association(link, AssociationSettings(security=client_ctx()))
    assoc.associate()
    with pytest.raises(ProtocolError, match="broadcast"):
        assoc.send_broadcast(UNCONFIRMED_SET)


# --- links ------------------------------------------------------------------------


def _assoc_on(link) -> Association:
    assoc = Association(link, AssociationSettings(security=client_ctx()))
    assoc.state = AssociationState.ASSOCIATED
    return assoc


def test_wrapper_broadcast_goes_to_wport_0x7f():
    transport = LoopbackTransport()
    assoc = _assoc_on(WrapperLink(transport, client_wport=0x10, server_wport=0x01))
    assoc.send_broadcast(UNCONFIRMED_SET)
    (raw,) = transport.sent
    pdu = decode_wrapper(raw)
    assert (pdu.source, pdu.destination) == (0x10, WPORT_BROADCAST)
    assert unwrap(meter(), pdu.apdu).plaintext == UNCONFIRMED_SET


@pytest.mark.parametrize(
    "server,dest",
    [
        (HdlcAddress.server(1), b"\xff"),
        (HdlcAddress.server(1, 17), b"\xfe\xff"),
    ],
)
def test_hdlc_broadcast_is_a_ui_frame_to_all_stations(server, dest):
    transport = LoopbackTransport()
    transport.open()
    assoc = _assoc_on(HdlcLink(transport, timeout=0.05, server_address=server))
    assoc.send_broadcast(UNCONFIRMED_SET)
    (raw,) = transport.sent
    assert raw[3 : 3 + len(dest)] == dest
    frame = decode_frame(raw)
    assert frame.kind.name == "UI" and not frame.poll_final
    assert frame.info[:3] == b"\xe6\xe6\x00"
    assert unwrap(meter(), frame.info[3:]).plaintext == UNCONFIRMED_SET


# --- inbound tamper -----------------------------------------------------------------


def _broadcast_apdu(protection: str) -> bytes:
    assoc, link = associate(protection=protection)
    assoc.send_broadcast(UNCONFIRMED_SET)
    return link.unconfirmed[0][0]


TAMPER = {p: _broadcast_apdu(p) for p in ("glo", "general-glo")}


def _open_as_meter(apdu: bytes) -> bytes:
    """What a meter does with a broadcast: unwrap with the broadcast key and
    check that the envelope names the service it holds (the envelope tag is
    not covered by GCM)."""
    plain = unwrap(meter(), apdu).plaintext
    if apdu[0] in PLAIN_FOR_CIPHERED and plain[:1] != bytes([PLAIN_FOR_CIPHERED[apdu[0]][0]]):
        raise AuthenticationError("envelope names another service")
    return plain


def test_untampered_broadcast_opens():
    for apdu in TAMPER.values():
        assert _open_as_meter(apdu) == UNCONFIRMED_SET


@pytest.mark.parametrize(
    "protection,position,bit",
    [(p, pos, bit) for p, a in TAMPER.items() for pos in range(len(a)) for bit in (0x01, 0x80)],
)
def test_any_tampered_byte_is_refused(protection, position, bit):
    tampered = bytearray(TAMPER[protection])
    tampered[position] ^= bit
    with pytest.raises((SecurityError, DecodeError)):
        _open_as_meter(bytes(tampered))


# --- logs -------------------------------------------------------------------------


def test_no_key_bytes_in_logs(caplog):
    caplog.set_level(TRACE, logger="pydlms")
    assoc, link = associate()
    assoc.send_broadcast(UNCONFIRMED_SET)
    unwrap(meter(), link.unconfirmed[0][0])
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "broadcast" in text
    for secret in (EK, AK, BK):
        for rendering in (secret.hex(), secret.hex().upper(), repr(secret)):
            assert rendering not in text


# --- client wrappers ----------------------------------------------------------------


def _client() -> tuple[DlmsClient, BroadcastLink]:
    assoc, link = associate()
    client = DlmsClient(link, auto_associate=False)
    client.association = assoc
    return client, link


def test_client_broadcast_set_builds_an_unconfirmed_set():
    client, link = _client()
    client.broadcast_set("0.0.96.1.0.255", 1, 2, DlmsData.visible_string("A"))
    ((apdu, broadcast),) = link.unconfirmed
    assert broadcast
    plain = unwrap(meter(), apdu).plaintext
    assert plain[:2] == b"\xc1\x01"
    assert not plain[2] & 0x40  # service class unconfirmed
    assert plain[3:] == UNCONFIRMED_SET[3:]


def test_client_broadcast_action_builds_an_unconfirmed_action():
    client, link = _client()
    client.broadcast_action("0.0.96.3.0.255", 70, 1, DlmsData.int8(0))
    ((apdu, _),) = link.unconfirmed
    plain = unwrap(meter(), apdu).plaintext
    assert plain[:2] == b"\xc3\x01"
    assert not plain[2] & 0x40
    assert plain[3:] == bytes.fromhex("0046 0000600300ff 01 01 0f00".replace(" ", ""))


def test_client_broadcast_action_without_parameters():
    client, link = _client()
    client.broadcast_action("0.0.96.3.0.255", 70, "remote_disconnect")
    ((apdu, _),) = link.unconfirmed
    plain = unwrap(meter(), apdu).plaintext
    assert plain[3:] == UNCONFIRMED_ACTION[3:]


def test_client_broadcast_set_short_names_uses_unconfirmed_write():
    client, link = _client()
    client.association.settings.logical_names = False
    client._sn_map = {(1, ObisCode.parse("0.0.96.1.0.255")): 0x0200}
    client.broadcast_set("0.0.96.1.0.255", 1, 2, DlmsData.uint8(1))
    ((apdu, _),) = link.unconfirmed
    assert apdu[0] == Tag.GLO_UNCONFIRMED_WRITE_REQUEST
    # attribute 2 of base name 0x0200 is 0x0208 (base + 8 * (attr - 1))
    assert unwrap(meter(), apdu).plaintext == bytes.fromhex(
        "16 01 02 0208 01 11 01".replace(" ", "")
    )


def test_client_broadcast_action_refuses_short_names():
    client, link = _client()
    client.association.settings.logical_names = False
    with pytest.raises(ProtocolError, match="short-name"):
        client.broadcast_action("0.0.96.3.0.255", 70, 1)
    assert link.unconfirmed == []


def test_debug_log_names_the_drawn_ic(caplog):
    """The debug record names the drawn IC, which is the shared counter."""
    caplog.set_level(logging.DEBUG, logger="pydlms")
    assoc, _ = associate()
    ic = assoc.security.invocation_counter
    assoc.send_broadcast(UNCONFIRMED_SET)
    assert any(f"IC={ic}" in r.getMessage() for r in caplog.records)
