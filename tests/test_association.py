"""Association error paths and GBT handling, with a scripted APDU link."""

from __future__ import annotations

import pytest

from pydlms.apdu import xdlms
from pydlms.apdu.acse import AARE, ApplicationContext
from pydlms.apdu.gbt import GbtBlock, GbtReassembler, decode_gbt, encode_gbt, split_gbt
from pydlms.association import Association, AssociationSettings, AssociationState
from pydlms.cosem.data import DlmsData
from pydlms.exceptions import AssociationError, ProtocolError, ServiceError
from pydlms.link import ApduLink

INITIATE_RESPONSE = xdlms.InitiateResponse(xdlms.Conformance.default_ln(), 512).to_bytes()
AARE_OK = AARE(ApplicationContext.LN, 0, user_information=INITIATE_RESPONSE).to_bytes()


class ScriptedLink(ApduLink):
    def __init__(self, responses):
        self.responses = list(responses)
        self.sent: list[bytes] = []

    def connect(self):
        pass

    def disconnect(self):
        pass

    def send_apdu(self, apdu):
        self.sent.append(apdu)

    def receive_apdu(self, timeout=None):
        if not self.responses:
            raise AssertionError("script exhausted")
        item = self.responses.pop(0)
        return item(self.sent[-1]) if callable(item) else item


def associated(responses) -> tuple[Association, ScriptedLink]:
    link = ScriptedLink([AARE_OK, *responses])
    assoc = Association(link)
    assoc.associate()
    return assoc, link


def test_negotiated_values():
    assoc, link = associated([])
    assert assoc.state == AssociationState.ASSOCIATED
    assert assoc.server_max_pdu == 512
    assert link.sent[0][0] == 0x60


def test_exception_response_to_aarq():
    link = ScriptedLink([xdlms.ExceptionResponse(1, 2).to_bytes()])
    with pytest.raises(AssociationError, match="ExceptionResponse"):
        Association(link).associate()


def test_unexpected_answer_to_aarq():
    link = ScriptedLink([b"\xc4\x01\xc1\x00\x11\x01"])
    with pytest.raises(ProtocolError, match="expected AARE"):
        Association(link).associate()


def test_rejected_with_service_error_detail():
    aare = AARE(
        ApplicationContext.LN,
        1,
        1,
        1,
        user_information=xdlms.ConfirmedServiceError(1, 6, 1).to_bytes(),
    ).to_bytes()
    with pytest.raises(AssociationError, match="dlms-version-too-low") as info:
        Association(ScriptedLink([aare])).associate()
    assert info.value.result == 1


def test_rejected_with_gurux_numbered_service_error_still_reports():
    # Gurux sends "task" as ServiceError [8], a choice the Green Book leaves
    # unused; the refusal must still surface as an AssociationError.
    aare = AARE(
        ApplicationContext.LN,
        1,
        1,
        1,
        user_information=xdlms.ConfirmedServiceError(1, 8, 0).to_bytes(),
    ).to_bytes()
    with pytest.raises(AssociationError, match="association rejected"):
        Association(ScriptedLink([aare])).associate()


def test_aare_without_initiate_response():
    aare = AARE(ApplicationContext.LN, 0).to_bytes()
    with pytest.raises(AssociationError, match="no InitiateResponse"):
        Association(ScriptedLink([aare])).associate()


def test_hls_without_stoc():
    from pydlms.security.hls import Mechanism

    aare = AARE(
        ApplicationContext.LN, 0, 1, 14, mechanism=3, user_information=INITIATE_RESPONSE
    ).to_bytes()
    settings = AssociationSettings(mechanism=Mechanism.HLS_MD5, secret=b"x")
    with pytest.raises(AssociationError, match="StoC"):
        Association(ScriptedLink([aare]), settings).associate()


def test_request_maps_exception_and_service_errors():
    assoc, _ = associated(
        [
            xdlms.ExceptionResponse(1, 6, 77).to_bytes(),
            xdlms.ConfirmedServiceError(5, 5, 3).to_bytes(),
        ]
    )
    with pytest.raises(ServiceError, match="INVOCATION_COUNTER_ERROR"):
        assoc.request(b"\xc0\x01\xc1")
    with pytest.raises(ServiceError, match="confirmed service error"):
        assoc.request(b"\xc0\x01\xc1")


def test_gbt_response_is_reassembled_and_acknowledged():
    response = xdlms.GetResponseNormal(
        0xC1, xdlms.GetDataResult(data=DlmsData.octet_string(bytes(200)))
    ).to_bytes()
    blocks = split_gbt(response, 64)
    assoc, link = associated(blocks)
    plain = assoc.request(
        xdlms.GetRequestNormal(0xC1, xdlms.AttributeDescriptor(1, "0.0.42.0.0.255", 2)).to_bytes()
    )
    assert plain == response
    acks = [decode_gbt(a) for a in link.sent if a[0] == 0xE0]
    assert [a.block_number_ack for a in acks] == [1, 2, 3]
    assert [a.block_number for a in acks] == [2, 3, 4]
    assert all(a.last and not a.streaming and not a.data for a in acks)


def test_streaming_gbt_needs_no_acks():
    response = b"\xc4\x01\xc1\x00" + b"\x09\x81\x96" + bytes(150)
    blocks = split_gbt(response, 50, window=4, streaming=True)
    assoc, link = associated(blocks)
    assert assoc.request(b"\xc0\x01\xc1") == response
    assert not [a for a in link.sent if a[0] == 0xE0]


def test_ciphered_association_rejects_plaintext_responses():
    pytest.importorskip("cryptography")
    from pydlms.security.ciphering import wrap
    from pydlms.security.context import SecurityContext

    ek, ak = bytes(range(16)), bytes(range(16, 32))
    server = SecurityContext(ek, ak, client_system_title=b"SERVER01")
    ciphered_init = wrap(server, INITIATE_RESPONSE)
    aare = AARE(
        ApplicationContext.LN_CIPHERED,
        0,
        responding_ap_title=b"SERVER01",
        user_information=ciphered_init,
    ).to_bytes()
    plain_answer = xdlms.GetResponseNormal(0xC1, xdlms.GetDataResult(data=DlmsData.uint8(1)))
    link = ScriptedLink([aare, plain_answer.to_bytes()])
    client_ctx = SecurityContext(ek, ak, client_system_title=b"CLIENT01")
    assoc = Association(link, AssociationSettings(security=client_ctx))
    assoc.associate()
    assert client_ctx.server_system_title == b"SERVER01"
    assert link.sent[0][0] == 0x60 and b"\x21" in link.sent[0]  # glo-initiateRequest inside
    with pytest.raises(ProtocolError, match="unprotected GET_RESPONSE APDU: C4 01"):
        assoc.request(b"\xc0\x01\xc1")


def test_settings_repr_hides_secret():
    text = repr(AssociationSettings(secret=b"supersecret"))
    assert "supersecret" not in text and "***" in text


def test_release_never_raises():
    assoc, _ = associated([])  # no RLRE scripted: the link raises
    assoc.release()
    assert assoc.state == AssociationState.IDLE


# --- REVIEW F10: the response invoke-id must match the request's -----------------

GET_INVOKE_1 = bytes.fromhex("c001c1000100002a0000ff0200")
STALE_INVOKE_7 = bytes.fromhex("c401c700090142")
ANSWER_INVOKE_1 = bytes.fromhex("c401c100090143")


def test_stale_response_with_other_invoke_id_is_discarded():
    """REVIEW F10 repro: request invoke 1, a late answer with invoke 7 first."""
    assoc, link = associated([STALE_INVOKE_7, ANSWER_INVOKE_1])
    assert assoc.request(GET_INVOKE_1) == ANSWER_INVOKE_1
    assert len(link.sent) == 2  # AARQ and the GET, no resend


def test_only_stale_responses_raise_protocol_error():
    from pydlms.association import MAX_STALE_RESPONSES

    assoc, _ = associated([STALE_INVOKE_7] * (MAX_STALE_RESPONSES + 1))
    with pytest.raises(ProtocolError, match="invoke-id"):
        assoc.request(GET_INVOKE_1)


def test_invoke_id_check_ignores_priority_bits_and_unnumbered_answers():
    # Priority / service-class bits differ, invoke-id the same: accepted.
    assoc, _ = associated([bytes.fromhex("c4014100090143")])
    assert assoc.request(GET_INVOKE_1)[2] == 0x41
    # ExceptionResponse carries no invoke-id: still mapped to ServiceError.
    assoc, _ = associated([xdlms.ExceptionResponse(1, 2).to_bytes()])
    with pytest.raises(ServiceError):
        assoc.request(GET_INVOKE_1)


def test_client_get_ignores_stale_answer():
    from pydlms.client import DlmsClient

    link = ScriptedLink([AARE_OK, STALE_INVOKE_7, ANSWER_INVOKE_1])
    client = DlmsClient(link)
    client.connect()
    assert client.get("0.0.42.0.0.255").value == b"C"


# --- REVIEW F11: GBT window and acknowledgements ---------------------------------

GBT_RESPONSE = b"\xc4\x01\xc1\x00" + b"\x09\x81\x96" + bytes(150)


def _blocks(flags, chunk=50):
    """GBT APDUs of GBT_RESPONSE; ``flags`` is (streaming, window) per block."""
    data = [GBT_RESPONSE[i : i + chunk] for i in range(0, len(GBT_RESPONSE), chunk)]
    return [
        encode_gbt(GbtBlock(n == len(data), streaming, window, n, 0, part))
        for n, (part, (streaming, window)) in enumerate(zip(data, flags, strict=True), start=1)
    ]


def test_gbt_ack_advertises_the_client_window():
    """REVIEW F11 repro: the server's window 5 was echoed in the ack."""
    assoc, link = associated(_blocks([(False, 5)] * 4))
    assert assoc.request(b"\xc0\x01\xc1") == GBT_RESPONSE
    acks = [decode_gbt(a) for a in link.sent if a[0] == 0xE0]
    assert len(acks) == 3 and all(a.window == 1 for a in acks)


def test_gbt_ack_window_is_configurable():
    link = ScriptedLink([AARE_OK, *_blocks([(False, 1)] * 4)])
    assoc = Association(link, AssociationSettings(gbt_window=3))
    assoc.associate()
    assoc.request(b"\xc0\x01\xc1")
    assert {decode_gbt(a).window for a in link.sent if a[0] == 0xE0} == {3}


def test_gbt_no_ack_mid_stream_even_with_window_field_1():
    """REVIEW F11 repro: streaming=1 with window field 1 drew acks mid-stream."""
    assoc, link = associated(_blocks([(True, 1)] * 4))
    assert assoc.request(b"\xc0\x01\xc1") == GBT_RESPONSE
    assert not [a for a in link.sent if a[0] == 0xE0]


def test_gbt_ack_only_at_the_window_boundary():
    # Window of 2: blocks 1-2 then 3-4; streaming=0 on the last of each window.
    assoc, link = associated(_blocks([(True, 1), (False, 1), (True, 1), (False, 1)]))
    assert assoc.request(b"\xc0\x01\xc1") == GBT_RESPONSE
    acks = [decode_gbt(a) for a in link.sent if a[0] == 0xE0]
    assert [a.block_number_ack for a in acks] == [2]


def test_gbt_duplicate_block_is_dropped():
    blocks = _blocks([(False, 1)] * 4)
    assoc, _ = associated([blocks[0], blocks[1], blocks[1], blocks[2], blocks[3]])
    assert assoc.request(b"\xc0\x01\xc1") == GBT_RESPONSE


def test_gbt_reassembly_is_capped():
    reassembler = GbtReassembler(max_size=100)
    reassembler.add(GbtBlock(False, False, 1, 1, 0, bytes(60)))
    with pytest.raises(ProtocolError, match="exceeds 100"):
        reassembler.add(GbtBlock(False, False, 1, 2, 0, bytes(60)))


def test_gbt_reassembly_cap_comes_from_the_settings():
    link = ScriptedLink([AARE_OK, *_blocks([(False, 1)] * 4)])
    assoc = Association(link, AssociationSettings(max_block_transfer_size=100))
    assoc.associate()
    with pytest.raises(ProtocolError, match="exceeds 100"):
        assoc.request(b"\xc0\x01\xc1")


def _initiate(pdu=512, version=6, vaa=0x0007):
    return xdlms.InitiateResponse(xdlms.Conformance.default_ln(), pdu, version, vaa).to_bytes()


@pytest.mark.parametrize(
    ("aare", "message"),
    [
        (AARE(ApplicationContext.SN, 0, user_information=_initiate(vaa=0xFA00)), "context"),
        (AARE(ApplicationContext.LN_CIPHERED, 0, user_information=_initiate()), "context"),
        (AARE(ApplicationContext.LN, 0, user_information=_initiate(vaa=0xFA00)), "VAA"),
        (AARE(ApplicationContext.LN, 0, user_information=_initiate(version=5)), "version"),
        (AARE(ApplicationContext.LN, 0, user_information=_initiate(pdu=5)), "PDU"),
    ],
    ids=["sn-context", "ciphered-context", "vaa", "version", "pdu-size"],
)
def test_aare_inconsistent_with_the_proposal_is_refused(aare, message):
    assoc = Association(ScriptedLink([aare.to_bytes()]))
    with pytest.raises(AssociationError, match=message):
        assoc.associate()
    assert assoc.state == AssociationState.IDLE


def test_sn_aare_needs_the_association_sn_vaa():
    sn_ok = AARE(ApplicationContext.SN, 0, user_information=_initiate(vaa=0xFA00)).to_bytes()
    assoc = Association(ScriptedLink([sn_ok]), AssociationSettings(logical_names=False))
    assoc.associate()
    assert assoc.state == AssociationState.ASSOCIATED
    sn_bad = AARE(ApplicationContext.SN, 0, user_information=_initiate()).to_bytes()
    with pytest.raises(AssociationError, match="VAA"):
        Association(ScriptedLink([sn_bad]), AssociationSettings(logical_names=False)).associate()


def test_hls_accept_without_authentication_required_is_logged(caplog):
    from pydlms.security.hls import Mechanism

    aare = AARE(
        ApplicationContext.LN,
        0,
        diagnostic=0,
        mechanism=3,
        responding_authentication_value=b"S" * 16,
        user_information=_initiate(),
    ).to_bytes()

    def reply(request):
        return xdlms.ActionResponseNormal(
            request[2], 0, xdlms.GetDataResult(DlmsData.octet_string(b"x" * 16))
        ).to_bytes()

    assoc = Association(
        ScriptedLink([aare, reply]),
        AssociationSettings(mechanism=Mechanism.HLS_MD5, secret=b"secret"),
    )
    with caplog.at_level("WARNING", logger="pydlms.association"):
        with pytest.raises(AssociationError, match="pass 4"):
            assoc.associate()
    assert "authentication-required" in caplog.text


def test_undefined_result_code_reaches_the_error():
    from pydlms.client import DlmsClient
    from pydlms.obis import ObisCode

    link = ScriptedLink([AARE_OK, bytes.fromhex("C401C101AA")])
    client = DlmsClient(link)
    client.connect()
    with pytest.raises(ServiceError, match="170") as info:
        client.get(ObisCode(1, 0, 1, 8, 0, 255), 3)
    assert info.value.result == 0xAA
