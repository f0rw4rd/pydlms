"""xDLMS service forms beyond the basics, end to end against the simulator:
SET-/ACTION-with-list, block-transferred GET-with-list and ACTION return
data, and every session protection mode (general-glo, general-ciphering,
general-signing and their combinations).

Byte layouts are pinned at codec level in ``test_xdlms.py``; these tests
prove the client orchestration (invoke ids, block numbering, list
bookkeeping, envelope selection) over real sockets.
"""

from __future__ import annotations

import pytest

from pydlms.apdu import xdlms
from pydlms.apdu.tags import Tag
from pydlms.client import DlmsClient
from pydlms.cosem.data import DlmsData
from pydlms.cosem.enums import ActionResult, DataAccessResult
from pydlms.cosem.interface_classes import ClassId
from pydlms.exceptions import DecodeError
from pydlms.security.suites import SecuritySuite
from pydlms.simulator import ClientProfile, example_meter, serve

EK = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
AK = bytes.fromhex("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF")
CLIENT_TITLE = b"PYDCLNT1"


@pytest.fixture
def meter():
    sim = example_meter(encryption_key=EK, authentication_key=AK)
    servers = []

    def start():
        server = serve(sim)
        servers.append(server)
        return server.server_address

    sim.start = start
    yield sim
    for server in servers:
        server.shutdown()
        server.server_close()


def client(meter, **kw) -> DlmsClient:
    host, port = meter.start()
    return DlmsClient.tcp(host, port, timeout=3, **kw)


def sent(meter, prefix: bytes) -> int:
    """How many plaintext requests the meter saw starting with ``prefix``."""
    return sum(1 for r in meter.requests if r.startswith(prefix))


# --- GET-with-list -------------------------------------------------------------------


def test_get_many_reassembles_block_transferred_list(meter):
    meter.max_pdu = 128
    big = DlmsData.octet_string(bytes(range(256)))
    meter.add_object(ClassId.DATA, "0.0.96.99.0.255", {2: big})
    with client(meter) as m:
        values = m.get_many(
            [
                ("1.0.1.8.0.255", ClassId.REGISTER, 2),
                ("0.0.96.99.0.255", ClassId.DATA, 2),
                ("9.9.9.9.9.9", ClassId.DATA, 2),
                ("1.0.2.8.0.255", ClassId.REGISTER, 2),
            ]
        )
    assert values[0].value == 12345678
    assert values[1].value == big.value
    assert values[2] == DataAccessResult.OBJECT_UNDEFINED
    assert values[3].value == 4321
    assert sent(meter, bytes([Tag.GET_REQUEST, 3])) == 1
    assert sent(meter, bytes([Tag.GET_REQUEST, 2])) >= 2  # Get-Request-Next


def test_get_data_results_codec():
    results = [
        xdlms.GetDataResult(data=DlmsData.uint16(7)),
        xdlms.GetDataResult(error=DataAccessResult.READ_WRITE_DENIED),
    ]
    raw = xdlms.encode_get_data_results(results)
    assert raw.hex() == "02" + "00" + "120007" + "01" + "03"
    assert xdlms.decode_get_data_results(raw) == results
    with pytest.raises(DecodeError):
        xdlms.decode_get_data_results(raw + b"\x00")
    with pytest.raises(DecodeError):
        xdlms.decode_get_data_results(raw[:-1])
    with pytest.raises(DecodeError):
        xdlms.decode_get_data_results(b"\x01\x02")  # bad Get-Data-Result choice


# --- SET-with-list -------------------------------------------------------------------


def test_set_many_reports_per_item_results(meter):
    with client(meter) as m:
        results = m.set_many(
            [
                ("0.0.42.0.0.255", ClassId.DATA, 2, DlmsData.octet_string(b"NEW-NAME")),
                ("9.9.9.9.9.9", ClassId.DATA, 2, DlmsData.uint8(1)),
                ("0.0.96.1.0.255", ClassId.DATA, 1, DlmsData.octet_string(bytes(6))),
                ("0.0.96.1.0.255", ClassId.DATA, 2, DlmsData.visible_string("X1")),
            ]
        )
        assert results == [
            DataAccessResult.SUCCESS,
            DataAccessResult.OBJECT_UNDEFINED,
            DataAccessResult.READ_WRITE_DENIED,  # logical_name is read-only
            DataAccessResult.SUCCESS,
        ]
        assert m.get("0.0.42.0.0.255").value == b"NEW-NAME"
        assert m.get("0.0.96.1.0.255").value == "X1"
    assert sent(meter, bytes([Tag.SET_REQUEST, 4])) == 1


def test_set_many_falls_back_without_multiple_references(meter):
    conformance = xdlms.Conformance.GET | xdlms.Conformance.SET
    with client(meter, conformance=conformance) as m:
        assert not m.conformance & xdlms.Conformance.MULTIPLE_REFERENCES
        results = m.set_many(
            [
                ("0.0.42.0.0.255", ClassId.DATA, 2, DlmsData.octet_string(b"A")),
                ("9.9.9.9.9.9", ClassId.DATA, 2, DlmsData.uint8(1)),
            ]
        )
    assert results == [DataAccessResult.SUCCESS, DataAccessResult.OBJECT_UNDEFINED]
    assert sent(meter, bytes([Tag.SET_REQUEST, 4])) == 0
    assert sent(meter, bytes([Tag.SET_REQUEST, 1])) == 2


def test_set_many_empty_is_a_no_op(meter):
    with client(meter) as m:
        assert m.set_many([]) == []


# --- ACTION-with-list and pblock return data -----------------------------------------


def test_action_many(meter):
    meter.add_method(ClassId.DATA, "0.0.42.0.0.255", 1, lambda sim, p: DlmsData.uint8(41))
    meter.add_method(ClassId.DATA, "0.0.42.0.0.255", 2, lambda sim, p: None)
    with client(meter) as m:
        results = m.action_many(
            [
                ("0.0.42.0.0.255", ClassId.DATA, 1, DlmsData.int8(0)),
                ("0.0.42.0.0.255", ClassId.DATA, 2, None),
                ("9.9.9.9.9.9", ClassId.DATA, 1, None),
                ("0.0.96.3.10.255", ClassId.DISCONNECT_CONTROL, "remote_disconnect", None),
            ]
        )
        assert results[0].value == 41
        assert results[1] is None
        assert results[2] == ActionResult.OBJECT_UNAVAILABLE
        assert results[3] is None
        assert m.get("0.0.96.3.10.255", ClassId.DISCONNECT_CONTROL, 2).value is False
    assert sent(meter, bytes([Tag.ACTION_REQUEST, 3])) == 1


def test_action_return_data_in_pblocks(meter):
    payload = bytes(range(256)) * 3
    meter.add_method(
        ClassId.DATA, "0.0.42.0.0.255", 1, lambda sim, p: DlmsData.octet_string(payload)
    )
    meter.max_pdu = 128
    with client(meter) as m:
        result = m.action("0.0.42.0.0.255", ClassId.DATA, 1, DlmsData.int8(0))
        assert result.value == payload
        # Large parameters *and* large return data: pblocks both ways.
        result = m.action("0.0.42.0.0.255", ClassId.DATA, 1, DlmsData.octet_string(bytes(400)))
        assert result.value == payload
    assert sent(meter, bytes([Tag.ACTION_REQUEST, 2])) >= 2 * (len(payload) // 96)


def test_action_pblock_out_of_sequence_rejected():
    from pydlms.association import Association, AssociationSettings
    from pydlms.exceptions import ProtocolError

    class _Stub:
        def request(self, apdu):
            return xdlms.ActionResponseWithPblock(0xC1, True, 3, b"\x11\x01").to_bytes()

    assoc = Association.__new__(Association)
    assoc.settings = AssociationSettings()
    assoc.request = _Stub().request  # type: ignore[method-assign]
    first = xdlms.ActionResponseWithPblock(0xC1, False, 1, b"")
    with pytest.raises(ProtocolError, match="out of sequence"):
        assoc.action_result(0xC1, first, "m")


# --- session protection modes ---------------------------------------------------------


@pytest.mark.parametrize(
    "protection",
    [
        "glo",
        "general-glo",
        "general-ciphering",
        "general-signing",
        "glo+signing",
        "general-ciphering+signing",
    ],
)
def test_every_protection_mode_round_trips(meter, protection):
    pytest.importorskip("cryptography")
    from pydlms.security import ec
    from pydlms.security.context import SecurityContext
    from pydlms.security.hls import Mechanism

    client_key = ec.generate_private_key(1)
    server_key = ec.generate_private_key(1)
    meter.clients[16] = ClientProfile(Mechanism.NONE, ciphered=True)
    meter.security.suite = SecuritySuite(1)  # the suite id in SC must match
    meter.security.signing_key = server_key
    meter.security.peer_signing_key = client_key.public_key()
    security = SecurityContext(
        EK,
        AK,
        client_system_title=CLIENT_TITLE,
        suite=1,
        signing_key=client_key,
        peer_signing_key=server_key.public_key(),
    )
    with client(meter, security=security, protection=protection) as m:
        assert m.get_register("1.0.32.7.0.255").value == pytest.approx(230.1)
        m.set("0.0.42.0.0.255", ClassId.DATA, 2, DlmsData.octet_string(b"P"))
        assert m.get("0.0.42.0.0.255").value == b"P"
    outer = {
        "glo": Tag.GLO_GET_REQUEST,
        "general-glo": Tag.GENERAL_GLO_CIPHERING,
        "general-ciphering": Tag.GENERAL_CIPHERING,
        "general-signing": Tag.GENERAL_SIGNING,
        "glo+signing": Tag.GENERAL_SIGNING,
        "general-ciphering+signing": Tag.GENERAL_SIGNING,
    }[protection]
    assert any(r[0] == outer for r in meter.requests)


# --- Security Setup key_transfer ------------------------------------------------------


def test_transfer_keys_wraps_under_the_master_key(meter, caplog):
    pytest.importorskip("cryptography")
    from pydlms.debug import TRACE
    from pydlms.exceptions import KeyMissingError
    from pydlms.security.context import SecurityContext
    from pydlms.security.hls import Mechanism
    from pydlms.security.keywrap import KeyId, unwrap_key

    kek = bytes.fromhex("000102030405060708090A0B0C0D0E0F")[::-1]
    new_ek = bytes(range(0x40, 0x50))
    new_ak = bytes(range(0x60, 0x70))
    installed = {}

    def key_transfer(sim, params):
        for entry in params.value:
            key_id, wrapped = (e.value for e in entry.value)
            installed[key_id] = unwrap_key(kek, wrapped)

    meter.add_object(ClassId.SECURITY_SETUP, "0.0.43.0.0.255", {2: DlmsData.enum(1)})
    meter.add_method(ClassId.SECURITY_SETUP, "0.0.43.0.0.255", 2, key_transfer)
    meter.clients[16] = ClientProfile(Mechanism.NONE, ciphered=True)
    security = SecurityContext(EK, AK, client_system_title=CLIENT_TITLE, master_key=kek)
    caplog.set_level(TRACE, logger="pydlms")
    with client(meter, security=security) as m:
        m.transfer_keys({KeyId.GLOBAL_UNICAST_ENCRYPTION: new_ek, KeyId.AUTHENTICATION: new_ak})
        with pytest.raises(ValueError, match="octets"):
            m.transfer_keys({KeyId.AUTHENTICATION: bytes(32)})
        with pytest.raises(ValueError):
            m.transfer_keys({9: new_ek})
        with pytest.raises(ValueError, match="no keys"):
            m.transfer_keys({})
    assert installed == {0: new_ek, 2: new_ak}
    for secret in (new_ek, new_ak, kek):
        assert secret.hex() not in caplog.text.replace(" ", "").lower()

    # Without a KEK nothing is sent (checked before any I/O).
    plain = SecurityContext(EK, AK, client_system_title=CLIENT_TITLE)
    requests = len(meter.requests)
    with pytest.raises(KeyMissingError, match="master_key"):
        client(meter, security=plain).transfer_keys({KeyId.GLOBAL_UNICAST_ENCRYPTION: new_ek})
    assert len(meter.requests) == requests


@pytest.mark.parametrize(
    "kind,scheme", [("agreed", 2), ("agreed", 1), ("identified", 1), ("wrapped", 1), ("none", 1)]
)
def test_general_ciphering_key_info_forms(meter, kind, scheme):
    """Every key-info form round-trips against the simulator; the static
    unified model carries a fresh transaction-id (its only per-APDU input
    to the KDF; Gurux also needs one, see test_gurux_suite1.py)."""
    pytest.importorskip("cryptography")
    from pydlms.security import ec
    from pydlms.security.context import SecurityContext
    from pydlms.security.general import KeyInfo
    from pydlms.security.hls import Mechanism

    kek = bytes(range(16))
    client_sign, server_sign = ec.generate_private_key(1), ec.generate_private_key(1)
    client_ka, server_ka = ec.generate_private_key(1), ec.generate_private_key(1)
    meter.clients[16] = ClientProfile(Mechanism.NONE, ciphered=True)

    meter.security.suite = SecuritySuite(1)  # same 16-octet keys as suite 0
    meter.security.master_key = kek
    meter.security.signing_key = server_sign
    meter.security.peer_signing_key = client_sign.public_key()
    meter.security.key_agreement_key = server_ka
    meter.security.peer_key_agreement_key = client_ka.public_key()
    security = SecurityContext(
        EK,
        AK,
        client_system_title=CLIENT_TITLE,
        suite=1,
        master_key=kek,
        signing_key=client_sign,
        peer_signing_key=server_sign.public_key(),
        key_agreement_key=client_ka,
        peer_key_agreement_key=server_ka.public_key(),
    )
    with client(
        meter, security=security, protection="general-ciphering", key_info=KeyInfo(kind, 0, scheme)
    ) as m:
        assert m.get("0.0.42.0.0.255").value == b"PYD1000000000001"
        assert m.get("0.0.42.0.0.255").value == b"PYD1000000000001"
    general = [r for r in meter.requests if r[0] == Tag.GENERAL_CIPHERING]
    assert len(general) >= 2
    transaction_ids = [r[2 : 2 + r[1]] for r in general]
    if kind == "agreed" and scheme == 2:
        assert all(len(t) == 8 for t in transaction_ids)
        assert len(set(transaction_ids)) == len(transaction_ids)
    else:
        assert all(t == b"" for t in transaction_ids)


# --- peer certificate pins the meter ----------------------------------------------------


@pytest.mark.parametrize("matching", [True, False], ids=["same-title", "other-title"])
def test_peer_certificate_title_must_match_aare(meter, matching):
    pytest.importorskip("cryptography")
    from pydlms.exceptions import AssociationError
    from pydlms.security import ec
    from pydlms.security.context import SecurityContext
    from pydlms.security.hls import Mechanism
    from tests.crypto.test_certificates import make_cert

    server_key = ec.generate_private_key(1)
    client_key = ec.generate_private_key(1)
    meter_title = meter.security.client_system_title  # the simulator's own title
    cn = (meter_title if matching else b"OTHERMTR").hex().upper()
    meter.clients[16] = ClientProfile(Mechanism.NONE, ciphered=True)
    meter.security.suite = SecuritySuite(1)  # the suite id in SC must match
    meter.security.signing_key = server_key
    meter.security.peer_signing_key = client_key.public_key()
    security = SecurityContext(
        EK,
        AK,
        client_system_title=CLIENT_TITLE,
        suite=1,
        signing_key=client_key,
        peer_certificate=make_cert(server_key, common_names=(cn,)),
    )
    m = client(meter, security=security, protection="glo+signing")
    if matching:
        with m:
            assert m.get("0.0.42.0.0.255").value == b"PYD1000000000001"
    else:
        with pytest.raises(AssociationError, match="peer certificate"):
            m.connect()
        m.link.disconnect()


def test_get_datablock_transfer_is_capped():
    """REVIEW F7: GET datablocks from an untrusted meter are bounded by
    AssociationSettings.max_block_transfer_size."""
    from pydlms.association import AssociationSettings
    from pydlms.client import DlmsClient
    from pydlms.exceptions import ProtocolError
    from tests.test_association import AARE_OK, ScriptedLink

    def block(number, last):
        return xdlms.GetResponseWithDatablock(0xC1, last, number, bytes(60)).to_bytes()

    link = ScriptedLink([AARE_OK, block(1, False), block(2, False), block(3, True)])
    client = DlmsClient(link, AssociationSettings(max_block_transfer_size=100))
    client.connect()
    with pytest.raises(ProtocolError, match="exceeds 100"):
        client.get("0.0.42.0.0.255")


@pytest.mark.parametrize(
    "item",
    [
        DlmsData.structure([DlmsData.uint16(3), DlmsData.uint8(0)]),  # too short
        DlmsData.uint16(3),  # not a structure
        DlmsData.structure(
            [
                DlmsData.uint16(3),
                DlmsData.uint8(0),
                DlmsData.octet_string(b"\x01\x00"),
                DlmsData.null(),
            ]
        ),  # 2-octet logical name
        DlmsData.structure(
            [DlmsData.octet_string(b"x"), DlmsData.uint8(0), DlmsData.octet_string(bytes(6))]
        ),  # class id not an integer
    ],
)
def test_malformed_ln_object_list_entry_is_a_decode_error(item):
    from pydlms.client import _ln_entry

    with pytest.raises(DecodeError):
        _ln_entry(item)


@pytest.mark.parametrize(
    "item",
    [
        DlmsData.structure([DlmsData.int16(0x100), DlmsData.uint16(3), DlmsData.uint8(0)]),
        DlmsData.structure(
            [DlmsData.int16(0x100), DlmsData.uint16(3), DlmsData.uint8(0), DlmsData.uint8(1)]
        ),
    ],
)
def test_malformed_sn_object_list_entry_is_a_decode_error(item):
    from pydlms.client import _sn_entry

    with pytest.raises(DecodeError):
        _sn_entry(item)


def test_malformed_capture_object_is_a_decode_error():
    from pydlms.client import _capture_object

    with pytest.raises(DecodeError):
        _capture_object(DlmsData.structure([DlmsData.uint16(3), DlmsData.octet_string(bytes(6))]))
