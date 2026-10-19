"""SN read-/write-data-block-access: client block sender and simulator reassembly.

The scripted tests pin the client's checks on each server reply; the
end-to-end tests run the client against the in-process simulator, whose
reassembly follows the GuruxDLMS servers (``svr_handleReadDataBlockAccess``).
No live interop server is used: none of the oracles here accepts a long SN
request (jDLMS ignores data-block-access, see its ``ReadRequestProcessor``).
"""

from __future__ import annotations

import pytest

from pydlms.apdu import sn, xdlms
from pydlms.apdu.acse import AARE, ApplicationContext
from pydlms.association import Association, AssociationSettings
from pydlms.client import DlmsClient
from pydlms.cosem.data import DlmsData
from pydlms.cosem.enums import DataAccessResult
from pydlms.cosem.interface_classes import ClassId
from pydlms.exceptions import ProtocolError, ServiceError
from pydlms.simulator import example_meter, serve
from tests.test_association import ScriptedLink

PDU = 64


def _sn_association(responses, pdu=PDU, conformance=None):
    conformance = xdlms.Conformance.default_sn() if conformance is None else conformance
    initiate = xdlms.InitiateResponse(conformance, pdu, 6, 0xFA00).to_bytes()
    aare = AARE(ApplicationContext.SN, 0, user_information=initiate).to_bytes()
    link = ScriptedLink([aare, *responses])
    assoc = Association(link, AssociationSettings(logical_names=False))
    assoc.associate()
    return assoc, link


def _write_ack(n):
    return sn.WriteResponse([sn.WriteBlockNumber(n)]).to_bytes()


def _read_ack(n):
    return sn.ReadResponse([sn.ReadResult(block_number=n)]).to_bytes()


LONG = DlmsData.octet_string(bytes(range(150)))
WRITE = sn.WriteRequest([sn.VariableName(0x1008)], [LONG])
READ = sn.ReadRequest([sn.ParameterizedAccess(0x1058, 0, LONG)])


def _parts(link):
    return [sn.decode_sn_apdu(raw) for raw in link.sent[1:]]


def test_long_write_goes_in_numbered_blocks_that_rebuild_the_request():
    assoc, link = _sn_association([_write_ack(1), _write_ack(2), sn.WriteResponse([0]).to_bytes()])
    response = assoc.sn_request(WRITE)
    assert response.results == [DataAccessResult.SUCCESS]
    parts = _parts(link)
    assert len(parts) == 3
    assert all(len(raw) <= PDU for raw in link.sent[1:])
    assert [p.items[0] for p in parts] == [
        sn.WriteDataBlockAccess(False, 1),
        sn.WriteDataBlockAccess(False, 2),
        sn.WriteDataBlockAccess(True, 3),
    ]
    joined = b"".join(p.values[0].value for p in parts)
    assert joined == WRITE.to_bytes()[1:]


def test_long_read_goes_in_read_data_block_access():
    final = sn.ReadResponse([sn.ReadResult(data=DlmsData.uint8(7))]).to_bytes()
    assoc, link = _sn_association([_read_ack(1), _read_ack(2), final])
    assert assoc.sn_read_value(assoc.sn_request(READ), "method") == DlmsData.uint8(7)
    parts = [p.items[0] for p in _parts(link)]
    assert [(p.last_block, p.block_number) for p in parts] == [(False, 1), (False, 2), (True, 3)]
    assert b"".join(p.raw_data for p in parts) == READ.to_bytes()[1:]


def test_last_write_block_acknowledged_by_number_is_success():
    assoc, _ = _sn_association([_write_ack(1), _write_ack(2), _write_ack(3)])
    assert assoc.sn_request(WRITE).results == [DataAccessResult.SUCCESS]


@pytest.mark.parametrize(
    ("replies", "error", "match"),
    [
        ([_write_ack(2)], ProtocolError, "acknowledged as block 2"),
        ([_write_ack(1), _write_ack(1)], ProtocolError, "acknowledged as block 1"),
        ([_write_ack(1), _write_ack(2), _write_ack(4)], ProtocolError, "as block 4"),
        (
            [sn.WriteResponse([DataAccessResult.DATA_BLOCK_NUMBER_INVALID]).to_bytes()],
            ServiceError,
            "refused",
        ),
        ([sn.WriteResponse([0]).to_bytes()], ProtocolError, "before the last block"),
        ([sn.WriteResponse([0, 0]).to_bytes()], ProtocolError, "unexpected reply"),
        ([_read_ack(1)], ProtocolError, "unexpected reply"),
    ],
    ids=["wrong-first", "repeated", "wrong-last", "error", "early-success", "two", "read"],
)
def test_write_block_replies_are_checked(replies, error, match):
    assoc, _ = _sn_association(replies)
    with pytest.raises(error, match=match):
        assoc.sn_request(WRITE)


@pytest.mark.parametrize(
    ("replies", "error", "match"),
    [
        ([_read_ack(3)], ProtocolError, "acknowledged as block 3"),
        (
            [sn.ReadResponse([sn.ReadResult(error=DataAccessResult.OTHER_REASON)]).to_bytes()],
            ServiceError,
            "refused",
        ),
        ([_read_ack(1), _read_ack(2), _read_ack(3)], ProtocolError, "without data"),
        ([_write_ack(1)], ProtocolError, "unexpected reply"),
    ],
    ids=["wrong-number", "error", "last-acked", "write"],
)
def test_read_block_replies_are_checked(replies, error, match):
    assoc, _ = _sn_association(replies)
    with pytest.raises(error, match=match):
        assoc.sn_request(READ)


@pytest.mark.parametrize(
    ("request_", "bit"),
    [
        (WRITE, xdlms.Conformance.BLOCK_TRANSFER_WITH_SET_OR_WRITE),
        (READ, xdlms.Conformance.BLOCK_TRANSFER_WITH_GET_OR_READ),
    ],
    ids=["write", "read"],
)
def test_long_request_without_block_transfer_is_refused_before_sending(request_, bit):
    assoc, link = _sn_association([], conformance=xdlms.Conformance.default_sn() & ~bit)
    with pytest.raises(ProtocolError, match=bit.name):
        assoc.sn_request(request_)
    assert len(link.sent) == 1  # the AARQ only


def test_block_count_is_bounded_by_unsigned16():
    assoc, link = _sn_association([], pdu=16)
    huge = sn.WriteRequest([sn.VariableName(0x1008)], [DlmsData.octet_string(bytes(0x80000))])
    with pytest.raises(ProtocolError, match="Unsigned16"):
        assoc.sn_request(huge)
    assert len(link.sent) == 1


def test_short_request_is_sent_whole():
    assoc, link = _sn_association([sn.WriteResponse([0]).to_bytes()])
    short = sn.WriteRequest([sn.VariableName(0x1008)], [DlmsData.uint8(1)])
    assert assoc.sn_request(short).results == [DataAccessResult.SUCCESS]
    assert link.sent[1] == short.to_bytes()


def test_read_continuation_out_of_sequence_is_refused():
    first = sn.ReadResponse([sn.ReadResult(block_last=False, block_number=1, raw_data=b"\x09")])
    skipped = sn.ReadResponse([sn.ReadResult(block_last=True, block_number=3, raw_data=b"\x00")])
    assoc, _ = _sn_association([skipped.to_bytes()])
    with pytest.raises(ProtocolError, match="out of sequence"):
        assoc.sn_read_value(first, "READ")


# --- end to end against the simulator ---------------------------------------------------


@pytest.fixture
def meter():
    sim = example_meter()
    sim.max_pdu = 256
    server = serve(sim)
    sim.address = server.server_address
    yield sim
    server.shutdown()
    server.server_close()


def _client(meter) -> DlmsClient:
    return DlmsClient.tcp(*meter.address, timeout=3, logical_names=False)


def _data_block_parts(requests, choice):
    return [r for r in requests if r[0] in (0x05, 0x06) and len(r) > 2 and r[2] == choice]


@pytest.mark.parametrize("size", [250, 600, 3000])
def test_sn_write_of_a_long_value_in_blocks(meter, size):
    value = DlmsData.octet_string(bytes(i & 0xFF for i in range(size)))
    with _client(meter) as m:
        start = len(meter.requests)
        m.set("0.0.42.0.0.255", ClassId.DATA, 2, value)
        sent = meter.requests[start:]
        assert m.get("0.0.42.0.0.255", ClassId.DATA, 2) == value
    assert max(len(r) for r in sent) <= 256, [len(r) for r in sent]
    assert len(_data_block_parts(sent, 0x07)) > 1


def test_sn_method_with_long_parameters_in_read_data_block_access(meter):
    received = []
    meter.add_method(
        ClassId.DISCONNECT_CONTROL,
        "0.0.96.3.10.255",
        1,
        lambda sim, params: received.append(params) or DlmsData.uint8(len(received)),
    )
    params = DlmsData.octet_string(bytes(700))
    with _client(meter) as m:
        start = len(meter.requests)
        back = m.action("0.0.96.3.10.255", ClassId.DISCONNECT_CONTROL, 1, params)
        sent = meter.requests[start:]
    assert received == [params]
    assert back == DlmsData.uint8(1)
    assert max(len(r) for r in sent) <= 256
    assert len(_data_block_parts(sent, 0x06)) > 1


def test_simulator_refuses_a_block_out_of_sequence(meter):
    with _client(meter) as m:
        first = sn.ReadRequest([sn.ReadDataBlockAccess(False, 1, b"\x01\x02")])
        assert sn.decode_sn_apdu(m.association.request(first.to_bytes())).results == [
            sn.ReadResult(block_number=1)
        ]
        skipped = sn.ReadRequest([sn.ReadDataBlockAccess(True, 3, b"\x10\x08")])
        reply = sn.decode_sn_apdu(m.association.request(skipped.to_bytes()))
        assert reply.results == [sn.ReadResult(error=DataAccessResult.DATA_BLOCK_NUMBER_INVALID)]
        # The transfer was dropped: the old block 2 is now out of sequence too.
        again = sn.WriteRequest([sn.WriteDataBlockAccess(True, 2)], [DlmsData.octet_string(b"")])
        reply = sn.decode_sn_apdu(m.association.request(again.to_bytes()))
        assert reply.results == [DataAccessResult.DATA_BLOCK_NUMBER_INVALID]


def test_simulator_refuses_a_part_without_its_octet_string(meter):
    with _client(meter) as m:
        bad = sn.WriteRequest([sn.WriteDataBlockAccess(True, 1)], [DlmsData.uint8(1)])
        reply = sn.decode_sn_apdu(m.association.request(bad.to_bytes()))
    assert reply.results == [DataAccessResult.DATA_BLOCK_UNAVAILABLE]
