"""The ACCESS service in the association, the client and the simulator.

Association: the 24-bit invoke-id of the Long-Invoke-Id-And-Priority is
matched between ``D9`` and ``DA``; ACCESS has no glo-/ded- ciphered form, so
``protection="glo"`` sends it as general-glo / general-ded (INFO log) and
``"glo+signing"`` refuses it; :meth:`protection_overhead` sizes it so.
Client: :meth:`DlmsClient.access` needs ACCESS negotiated (opt-in
``propose_access``) and checks the results against the operations.
Simulator: ACCESS through its GET/SET/ACTION paths, break-on-error, offered
in its conformance.
"""

from __future__ import annotations

import logging

import pytest

from pydlms import AccessAction, AccessGet, AccessOutcome, AccessSet
from pydlms.apdu import xdlms
from pydlms.apdu.acse import AARE, ApplicationContext
from pydlms.apdu.gbt import decode_gbt
from pydlms.apdu.tags import Tag
from pydlms.association import Association, AssociationSettings
from pydlms.client import DlmsClient
from pydlms.cosem.data import DlmsData
from pydlms.cosem.enums import ActionResult, DataAccessResult
from pydlms.cosem.interface_classes import ClassId
from pydlms.exceptions import ProtocolError, ServiceError
from pydlms.obis import ObisCode
from pydlms.simulator import example_meter, serve
from tests.test_association import ScriptedLink

ACCESS = xdlms.Conformance.ACCESS
GBT = xdlms.Conformance.GENERAL_BLOCK_TRANSFER
SERIAL = ObisCode.parse("0.0.96.1.0.255")
ENERGY = ObisCode.parse("1.0.1.8.0.255")
DISCONNECT = ObisCode.parse("0.0.96.3.10.255")
EK = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
AK = bytes.fromhex("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF")


# --- Association with a scripted peer --------------------------------------------------


def _aare(conformance, pdu=1024):
    return AARE(
        ApplicationContext.LN,
        0,
        user_information=xdlms.InitiateResponse(conformance, pdu).to_bytes(),
    ).to_bytes()


def access_association(responses, conformance=None, pdu=1024, **settings):
    conformance = (
        conformance if conformance is not None else xdlms.Conformance.default_ln() | ACCESS
    )
    link = ScriptedLink([_aare(conformance, pdu), *responses])
    assoc = Association(link, AssociationSettings(propose_access=True, **settings))
    assoc.associate()
    return assoc, link


def _get(invoke: int) -> bytes:
    spec = xdlms.AccessRequestGet(xdlms.AttributeDescriptor(1, SERIAL, 2))
    return xdlms.AccessRequest(invoke, None, [spec], [DlmsData.null()]).to_bytes()


def _answer(invoke: int) -> bytes:
    return xdlms.AccessResponse(
        invoke, None, None, [DlmsData.uint8(1)], [xdlms.AccessResponseGet(DataAccessResult.SUCCESS)]
    ).to_bytes()


def test_propose_access_sets_conformance_bit_17():
    _, link = access_association([], propose_gbt=False)
    # default LN 00 7E 1F plus bit 17 (0x40 in the last-but-one octet)
    assert b"\x5f\x1f\x04\x00\x00\x7e\x5f" in link.sent[0]
    link = ScriptedLink([_aare(xdlms.Conformance.default_ln())])
    Association(link).associate()
    assert b"\x5f\x1f\x04\x00\x00\x7e\x1f" in link.sent[0]  # off by default


def test_long_invoke_id_counter_is_24_bits_and_carries_the_flags():
    assoc, _ = access_association([])
    assert assoc.access_negotiated
    first = assoc.next_long_invoke_id()
    assert first == 0xC0000001
    assert assoc.next_long_invoke_id(break_on_error=True) == 0xE0000002
    assert assoc.next_long_invoke_id(confirmed=False, high_priority=False) == 0x00000003
    assoc._long_invoke_id = 0xFFFFFF
    assert assoc.next_long_invoke_id() == 0xC0000000  # wraps within 24 bits


def test_access_reply_is_matched_on_the_24_bit_invoke_id(caplog):
    late = _answer(0xC0000004)  # an answer to an earlier, timed-out request
    ours = _answer(0x40000005)  # same id, other flags: only the low 24 bits count
    assoc, link = access_association([late, ours])
    with caplog.at_level(logging.WARNING):
        assert assoc.request(_get(0xC0000005)) == ours
    assert "discarding ACCESS_RESPONSE with invoke-id 4 (expected 5)" in caplog.text
    # an id that differs only above bit 23 is the same request
    assoc, _ = access_association([_answer(0x00000105)])
    assert assoc.request(_get(0xFF000105))[0] == Tag.ACCESS_RESPONSE


def test_access_reply_with_an_id_beyond_15_matches():
    # the 4-bit Invoke-Id-And-Priority rule must not apply: 0x11 and 0x01
    # share their low nibble but are different long invoke ids
    assoc, _ = access_association([_answer(0xC0000001), _answer(0xC0000011)])
    assert assoc.request(_get(0xC0000011)) == _answer(0xC0000011)


def test_exception_and_truncated_replies_are_not_dropped_as_stale():
    assoc, _ = access_association([xdlms.ExceptionResponse(1, 2).to_bytes()])
    with pytest.raises(ServiceError, match="SERVICE_NOT_ALLOWED"):
        assoc.request(_get(0xC0000001))
    assoc, _ = access_association([b"\xda\x40"])
    assert assoc.request(_get(0xC0000001)) == b"\xda\x40"  # decoding then fails


def test_oversized_access_without_gbt_is_refused_and_with_gbt_is_split():
    big = xdlms.AccessRequest(
        0xC0000001,
        None,
        [xdlms.AccessRequestSet(xdlms.AttributeDescriptor(1, SERIAL, 2))],
        [DlmsData.octet_string(bytes(200))],
    ).to_bytes()
    assoc, _ = access_association([], pdu=64)
    with pytest.raises(ProtocolError, match="general-block-transfer not negotiated"):
        assoc.request(big)
    from tests.test_gbt_transfer import ack

    reply = _answer(0xC0000001)
    assoc, link = access_association(
        [ack(1, 1), ack(2, 2), ack(3, 3), reply],
        conformance=xdlms.Conformance.default_ln() | ACCESS | GBT,
        pdu=64,
        propose_gbt=True,
    )
    assert assoc.request(big) == reply
    blocks = [decode_gbt(a) for a in link.sent[1:]]
    assert b"".join(b.data for b in blocks) == big
    assert all(len(a) <= 64 for a in link.sent[1:])


# --- protection ----------------------------------------------------------------------


def _ciphered_association(protection, responses=(), dedicated=False):
    pytest.importorskip("cryptography")
    from pydlms.security.context import SecurityContext

    security = SecurityContext(EK, AK, client_system_title=b"PYDCLNT1")
    security.server_system_title = b"PYD\x00\x00\x00\x00\x01"
    conf = xdlms.Conformance.default_ln() | ACCESS | xdlms.Conformance.GENERAL_PROTECTION
    link = ScriptedLink(list(responses))
    assoc = Association(
        link,
        AssociationSettings(
            security=security,
            protection=protection,
            propose_access=True,
            use_dedicated_key=dedicated,
        ),
    )
    # associated by hand: the ciphered AARE exchange is covered elsewhere
    from pydlms.association import AssociationState

    assoc.state = AssociationState.ASSOCIATED
    assoc.negotiated_conformance = conf
    assoc.server_max_pdu = 1024
    if dedicated:
        security.set_dedicated_key(bytes(range(16)))
    return assoc, link, security


@pytest.mark.parametrize(
    "protection,dedicated,tag",
    [
        ("glo", False, Tag.GENERAL_GLO_CIPHERING),
        ("glo", True, Tag.GENERAL_DED_CIPHERING),
        ("general-glo", False, Tag.GENERAL_GLO_CIPHERING),
        ("general-glo", True, Tag.GENERAL_DED_CIPHERING),
    ],
)
def test_access_goes_out_as_general_glo_or_ded(caplog, protection, dedicated, tag):
    assoc, _, _ = _ciphered_association(protection, dedicated=dedicated)
    with caplog.at_level(logging.INFO, logger="pydlms.association"):
        protected = assoc._protect(_get(0xC0000001))
        assoc._protect(_get(0xC0000002))
    assert protected[0] == tag
    coerced = [r for r in caplog.records if "no glo-/ded- ciphered form" in r.getMessage()]
    assert len(coerced) == (1 if protection == "glo" else 0)  # logged once, at INFO
    if coerced:
        assert coerced[0].levelno == logging.INFO
        assert ("general-ded" if dedicated else "general-glo") in coerced[0].getMessage()
    # other services keep the configured envelope
    get = xdlms.GetRequestNormal(0xC1, xdlms.AttributeDescriptor(1, SERIAL, 2)).to_bytes()
    assert assoc._protect(get)[0] in (
        (Tag.GLO_GET_REQUEST, Tag.DED_GET_REQUEST) if protection == "glo" else (tag,)
    )


def test_glo_plus_signing_refuses_access():
    assoc, _, _ = _ciphered_association("glo+signing")
    with pytest.raises(ProtocolError, match="'glo\\+signing' cannot carry it"):
        assoc._protect(_get(0xC0000001))


def test_general_ciphering_keeps_its_envelope_for_access():
    assoc, _, _ = _ciphered_association("general-ciphering")
    assert assoc._protect(_get(0xC0000001))[0] == Tag.GENERAL_CIPHERING


def test_protection_overhead_accounts_for_the_access_envelope():
    from pydlms import association as a

    assoc, _, _ = _ciphered_association("glo")
    assert assoc.protection_overhead() == a._GLO_OVERHEAD
    assert assoc.protection_overhead(Tag.ACCESS_REQUEST) == a._GENERAL_GLO_OVERHEAD
    assert assoc.max_plain_request(Tag.ACCESS_REQUEST) == 1024 - a._GENERAL_GLO_OVERHEAD
    protected = assoc._protect(_get(0xC0000001))
    assert len(protected) - len(_get(0xC0000001)) <= a._GENERAL_GLO_OVERHEAD
    assoc, _, _ = _ciphered_association("general-glo")
    assert assoc.protection_overhead(Tag.ACCESS_REQUEST) == assoc.protection_overhead()


def test_unprotected_association_sends_access_in_clear():
    assoc, link = access_association([_answer(0xC0000001)])
    assoc.request(_get(0xC0000001))
    assert link.sent[-1] == _get(0xC0000001)


# --- client against the simulator -------------------------------------------------------


@pytest.fixture
def meter():
    sim = example_meter(encryption_key=EK, authentication_key=AK)
    servers = []

    def start(hdlc=False):
        server = serve(sim, hdlc=hdlc)
        servers.append(server)
        return server.server_address

    sim.start = start
    yield sim
    for server in servers:
        server.shutdown()
        server.server_close()


def client(meter, hdlc=False, **kw) -> DlmsClient:
    host, port = meter.start(hdlc)
    kw.setdefault("propose_access", True)
    return DlmsClient.tcp(host, port, hdlc=hdlc, timeout=3, **kw)


def ciphered(meter, protection="glo"):
    pytest.importorskip("cryptography")
    from pydlms.security.context import SecurityContext
    from pydlms.security.hls import Mechanism
    from pydlms.simulator import ClientProfile

    meter.clients[16] = ClientProfile(Mechanism.HLS_GMAC, ciphered=True)
    return {
        "mechanism": Mechanism.HLS_GMAC,
        "security": SecurityContext(EK, AK, client_system_title=b"PYDCLNT1"),
        "protection": protection,
    }


OPS = [
    AccessGet(SERIAL),
    AccessGet(ENERGY, ClassId.REGISTER, "value"),
    AccessSet("0.0.42.0.0.255", ClassId.DATA, 2, DlmsData.octet_string(b"NEW")),
    AccessAction(DISCONNECT, ClassId.DISCONNECT_CONTROL, 1, DlmsData.int8(0)),
]


@pytest.mark.parametrize("protection", ["plain", "glo", "general-glo"])
@pytest.mark.parametrize("hdlc", [False, True], ids=["wrapper", "hdlc"])
def test_access_end_to_end(meter, protection, hdlc):
    kw = {} if protection == "plain" else ciphered(meter, protection)
    with client(meter, hdlc, **kw) as m:
        assert m.association.access_negotiated
        out = m.access(OPS)
        assert all(isinstance(o, AccessOutcome) for o in out)
        assert [o.ok for o in out] == [True] * 4
        assert out[0].data == DlmsData.visible_string("PYD0000000001")
        assert out[1].data.value == 12345678
        assert out[2].result == DataAccessResult.SUCCESS and out[2].data == DlmsData.null()
        assert out[3].result == ActionResult.SUCCESS
        assert [o.operation for o in out] == OPS
        assert m.get("0.0.42.0.0.255").value == b"NEW"
    accesses = [r for r in meter.requests if r[:1] in (b"\xd9", b"\xdb")]
    assert accesses
    if protection != "plain":
        assert not [r for r in meter.requests if r[:1] == b"\xd9"]  # never in clear


def test_access_reports_failures_per_operation(meter):
    with client(meter) as m:
        out = m.access(
            [
                AccessGet("9.9.9.9.9.9"),
                AccessSet(SERIAL, ClassId.DATA, 1, DlmsData.octet_string(bytes(6))),
                AccessAction(SERIAL, ClassId.DATA, 9),
                AccessGet(SERIAL),
            ]
        )
    assert [o.result for o in out] == [
        DataAccessResult.OBJECT_UNDEFINED,
        DataAccessResult.READ_WRITE_DENIED,
        ActionResult.OBJECT_UNAVAILABLE,
        DataAccessResult.SUCCESS,
    ]
    assert out[0].data == DlmsData.null() and not out[0].ok


def test_break_on_error_skips_the_rest(meter):
    meter.add_object(ClassId.DATA, "0.0.42.1.0.255", {2: DlmsData.uint8(0)})
    with client(meter) as m:
        out = m.access(
            [
                AccessGet("9.9.9.9.9.9"),
                AccessSet("0.0.42.1.0.255", ClassId.DATA, 2, DlmsData.uint8(7)),
                AccessAction(DISCONNECT, ClassId.DISCONNECT_CONTROL, 1),
            ],
            break_on_error=True,
        )
        assert m.get("0.0.42.1.0.255").value == 0  # the set was not run
    # Skipped operations: OTHER_REASON (unverified, as the cB-Sigma server).
    assert [o.result for o in out] == [
        DataAccessResult.OBJECT_UNDEFINED,
        DataAccessResult.OTHER_REASON,
        ActionResult.OTHER_REASON,
    ]
    request = next(xdlms.decode_apdu(r) for r in meter.requests if r[:1] == b"\xd9")
    assert request.processing_option == xdlms.ProcessingOption.BREAK_ON_ERROR


def test_continue_on_error_runs_everything(meter):
    meter.add_object(ClassId.DATA, "0.0.42.1.0.255", {2: DlmsData.uint8(0)})
    with client(meter) as m:
        out = m.access(
            [
                AccessGet("9.9.9.9.9.9"),
                AccessSet("0.0.42.1.0.255", ClassId.DATA, 2, DlmsData.uint8(7)),
            ]
        )
        assert out[1].ok and m.get("0.0.42.1.0.255").value == 7


def test_access_with_selection_and_date_time(meter):
    import datetime as dt

    with client(meter) as m:
        out = m.access(
            [AccessGet("1.0.99.1.0.255", ClassId.PROFILE_GENERIC, 2, xdlms.entry_descriptor(1, 2))],
            date_time=dt.datetime(2024, 5, 1, 12, 0, tzinfo=dt.timezone.utc),
        )
    assert out[0].ok and len(out[0].data.value) == 2
    request = next(xdlms.decode_apdu(r) for r in meter.requests if r[:1] == b"\xd9")
    assert isinstance(request.specifications[0], xdlms.AccessRequestGetWithSelection)
    assert request.timestamp is not None and request.timestamp.date.year == 2024


def test_access_needs_negotiation(meter):
    with client(meter, propose_access=False) as m:
        assert not m.association.access_negotiated
        with pytest.raises(ProtocolError, match="propose_access=True"):
            m.access([AccessGet(SERIAL)])
    assert not [r for r in meter.requests if r[:1] == b"\xd9"]
    meter.conformance &= ~ACCESS  # a meter that does not grant it
    with client(meter) as m, pytest.raises(ProtocolError, match="not negotiated"):
        m.access([AccessGet(SERIAL)])
    assert m.access([]) == []


def test_simulator_refuses_access_when_not_negotiated(meter):
    from pydlms.simulator import _Session

    session = _Session(associated=True)
    raw = _get(0xC0000001)
    assert meter.handle(raw, session) == xdlms.ExceptionResponse(1, 2).to_bytes()
    session.access_negotiated = True
    reply = xdlms.decode_apdu(meter.handle(raw, session))
    assert reply.results == [xdlms.AccessResponseGet(DataAccessResult.SUCCESS)]
    unconfirmed = xdlms.AccessRequest(
        0x00000001,
        None,
        [xdlms.AccessRequestSet(xdlms.AttributeDescriptor(1, ObisCode.parse("0.0.42.0.0.255"), 2))],
        [DlmsData.octet_string(b"U")],
    ).to_bytes()
    assert meter.handle(unconfirmed, session) is None  # unconfirmed: run, no answer
    assert meter.objects[(1, ObisCode.parse("0.0.42.0.0.255"))][2].value == b"U"


def test_simulator_offers_access_by_default():
    assert example_meter().conformance & ACCESS


def _sn_aare(conformance):
    return AARE(
        ApplicationContext.SN,
        0,
        user_information=xdlms.InitiateResponse(conformance, 1024, vaa_name=0xFA00).to_bytes(),
    ).to_bytes()


def test_sn_association_refuses_access():
    link = ScriptedLink([_sn_aare(xdlms.Conformance.default_sn() | ACCESS)])
    m = DlmsClient(link, AssociationSettings(logical_names=False, propose_access=True))
    m.association.associate()
    with pytest.raises(ProtocolError, match="Logical-Name service"):
        m.access([AccessGet(SERIAL)])


# --- client result checks with a scripted meter ---------------------------------------------


def scripted_client(responses):
    link = ScriptedLink([_aare(xdlms.Conformance.default_ln() | ACCESS), *responses])
    m = DlmsClient(link, AssociationSettings(propose_access=True))
    m.association.associate()
    return m, link


def _reply(results, data=None, echo=None, invoke=0xC0000001):
    data = data if data is not None else [DlmsData.null()] * len(results)
    return xdlms.AccessResponse(invoke, None, echo, data, results).to_bytes()


OK_GET = xdlms.AccessResponseGet(DataAccessResult.SUCCESS)
OK_SET = xdlms.AccessResponseSet(DataAccessResult.SUCCESS)


@pytest.mark.parametrize(
    "reply,match",
    [
        (_reply([OK_GET]), "2 operations, got 1 results"),
        (_reply([OK_GET, OK_GET]), "operation 1 .* answered with a get result"),
        (_reply([OK_SET, OK_SET]), "operation 0 .* answered with a set result"),
        (
            _reply(
                [OK_GET, OK_SET],
                echo=[
                    xdlms.AccessRequestGet(xdlms.AttributeDescriptor(1, ENERGY, 2)),
                    xdlms.AccessRequestSet(xdlms.AttributeDescriptor(1, SERIAL, 2)),
                ],
            ),
            "echoes other specifications",
        ),
        (
            xdlms.GetResponseNormal(0xC1, xdlms.GetDataResult(data=DlmsData.null())).to_bytes(),
            "expected an ACCESS response",
        ),
    ],
)
def test_client_checks_results_against_the_operations(reply, match):
    m, _ = scripted_client([reply])
    with pytest.raises(ProtocolError, match=match):
        m.access([AccessGet(SERIAL), AccessSet(SERIAL, 1, 2, DlmsData.uint8(1))])


def test_client_accepts_a_matching_echo_and_builds_the_request():
    echo = [
        xdlms.AccessRequestGet(xdlms.AttributeDescriptor(1, SERIAL, 2)),
        xdlms.AccessRequestAction(xdlms.MethodDescriptor(70, DISCONNECT, 2)),
    ]
    m, link = scripted_client(
        [
            _reply(
                [OK_GET, xdlms.AccessResponseAction(ActionResult.SUCCESS)],
                data=[DlmsData.uint8(3), DlmsData.null()],
                echo=echo,
            )
        ]
    )
    out = m.access([AccessGet(SERIAL), AccessAction(DISCONNECT, 70, "remote_reconnect")])
    assert out[0].data == DlmsData.uint8(3) and out[1].ok
    sent = xdlms.decode_apdu(link.sent[-1])
    assert sent.specifications == echo
    assert sent.data == [DlmsData.null(), DlmsData.null()]
    assert sent.long_invoke_id == 0xC0000001


def test_client_refuses_an_unknown_operation_type():
    m, _ = scripted_client([])
    with pytest.raises(TypeError, match="not an AccessGet"):
        m.access([("0.0.96.1.0.255", 1, 2)])  # type: ignore[list-item]
