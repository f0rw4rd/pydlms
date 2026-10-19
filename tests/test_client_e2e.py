"""End-to-end client tests against the in-process meter simulator.

Real sockets on 127.0.0.1, the full stack on both sides: transport,
wrapper or HDLC framing, ACSE, ciphering, xDLMS services. The simulator
shares codecs with the client, so these tests prove the *orchestration*
(association sequences, block transfer, invoke ids, counters); byte-level
correctness is pinned separately by known-answer vectors and real captures.
"""

from __future__ import annotations

import datetime as dt
import socket
import threading

import pytest

from pydlms.apdu.xdlms import Conformance, date_time_value, entry_descriptor, range_descriptor
from pydlms.client import DlmsClient
from pydlms.cosem.data import DlmsData
from pydlms.cosem.enums import DataAccessResult, Unit
from pydlms.cosem.interface_classes import ClassId
from pydlms.exceptions import AssociationError, KeyMissingError, ProtocolError, ServiceError
from pydlms.security.hls import Mechanism
from pydlms.simulator import ClientProfile, _Session, example_meter, serve
from pydlms.wrapper import decode_wrapper, encode_wrapper

EK = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
AK = bytes.fromhex("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF")
CLIENT_TITLE = b"PYDCLNT1"


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


def security(**kw):
    pytest.importorskip("cryptography")
    from pydlms.security.context import SecurityContext

    return SecurityContext(EK, AK, client_system_title=CLIENT_TITLE, **kw)


def client(meter, hdlc=False, **kw) -> DlmsClient:
    host, port = meter.start(hdlc)
    return DlmsClient.tcp(host, port, hdlc=hdlc, timeout=3, **kw)


# --- reading -----------------------------------------------------------------------


@pytest.mark.parametrize("hdlc", [False, True], ids=["wrapper", "hdlc"])
def test_read_register_clock_and_identity(meter, hdlc):
    with client(meter, hdlc) as m:
        energy = m.get_register("1.0.1.8.0.255")
        assert energy.value == 12345678 and energy.unit == Unit.WATT_HOUR
        voltage = m.get_register("1.0.32.7.0.255")
        assert voltage.value == pytest.approx(230.1) and str(voltage) == "230.1 V"
        assert m.get("0.0.96.1.0.255").value == "PYD0000000001"
        clock = m.get_clock()
        assert clock.to_datetime().utcoffset() == dt.timedelta(hours=2)
        assert Conformance.GET in m.conformance


def test_attribute_by_name_and_errors(meter):
    with client(meter) as m:
        scaler_unit = m.get("1.0.32.7.0.255", ClassId.REGISTER, "scaler_unit")
        assert scaler_unit.to_python() == [-1, 35]
        with pytest.raises(ServiceError) as info:
            m.get("9.9.9.9.9.9", ClassId.REGISTER, 2)
        assert info.value.result == DataAccessResult.OBJECT_UNDEFINED
        with pytest.raises(ServiceError):
            m.get("1.0.32.7.0.255", ClassId.REGISTER, 9)


def test_get_many_with_list(meter):
    with client(meter) as m:
        values = m.get_many(
            [("1.0.1.8.0.255", 3, 2), ("9.9.9.9.9.9", 3, 2), ("1.0.2.8.0.255", 3, 2)]
        )
        assert values[0].value == 12345678
        assert values[1] == DataAccessResult.OBJECT_UNDEFINED
        assert values[2].value == 4321


def test_association_view(meter):
    with client(meter) as m:
        view = m.get_association_view()
        names = {str(e.logical_name) for e in view}
        assert {"1.0.1.8.0.255", "0.0.1.0.0.255", "1.0.99.1.0.255"} <= names
        profile = next(e for e in view if str(e.logical_name) == "1.0.99.1.0.255")
        assert profile.class_id == 7 and profile.version == 1


@pytest.mark.parametrize("hdlc", [False, True], ids=["wrapper", "hdlc"])
def test_profile_block_transfer(meter, hdlc):
    meter.max_pdu = 256  # forces GET-with-datablock on the 96-row buffer
    with client(meter, hdlc) as m:
        profile = m.read_profile("1.0.99.1.0.255")
        assert len(profile.rows) == 96
        assert (
            profile.columns[1][1] == "1.0.1.8.0.255"
            or str(profile.columns[1][1]) == "1.0.1.8.0.255"
        )
        assert profile.rows[-1][1] == 1000 + 95 * 7
    responses = [r for r in meter.requests if r[:2] == b"\xc0\x02"]
    assert len(responses) >= 2  # GET-Request-Next was used


def test_selective_access(meter):
    with client(meter) as m:
        by_entry = m.read_profile("1.0.99.1.0.255", entry_descriptor(10, 12))
        assert [row[1] for row in by_entry.rows] == [1063, 1070, 1077]
        start = dt.datetime(2024, 5, 1, 1, 0, tzinfo=dt.timezone.utc)
        end = dt.datetime(2024, 5, 1, 1, 30, tzinfo=dt.timezone.utc)
        by_range = m.read_profile(
            "1.0.99.1.0.255", range_descriptor(date_time_value(start), date_time_value(end))
        )
        assert len(by_range.rows) == 3


# --- writing and methods -------------------------------------------------------------


def test_set_and_set_clock(meter):
    with client(meter) as m:
        m.set("0.0.96.1.0.255", ClassId.DATA, 2, DlmsData.visible_string("NEWSERIAL"))
        assert m.get("0.0.96.1.0.255").value == "NEWSERIAL"
        when = dt.datetime(2025, 1, 2, 3, 4, 5, tzinfo=dt.timezone.utc)
        m.set_clock(when)
        assert m.get_clock().to_datetime() == when
        with pytest.raises(ServiceError):
            m.set("0.0.96.1.0.255", ClassId.DATA, 1, DlmsData.null())


def test_set_with_datablocks(meter):
    meter.max_pdu = 128
    big = DlmsData.octet_string(bytes(range(256)) * 2)
    with client(meter) as m:
        m.set("0.0.42.0.0.255", ClassId.DATA, 2, big)
        assert m.get("0.0.42.0.0.255").value == big.value
    assert any(r[:2] == b"\xc1\x03" for r in meter.requests)


def test_action_and_pblock(meter):
    received = []
    meter.add_method(
        ClassId.DATA,
        "0.0.42.0.0.255",
        1,
        lambda sim, params: received.append(params) or DlmsData.uint8(7),
    )
    meter.max_pdu = 128
    with client(meter) as m:
        assert m.get("0.0.96.3.10.255", ClassId.DISCONNECT_CONTROL, 2).value is True
        assert (
            m.action(
                "0.0.96.3.10.255", ClassId.DISCONNECT_CONTROL, "remote_disconnect", DlmsData.int8(0)
            )
            is None
        )
        assert m.get("0.0.96.3.10.255", ClassId.DISCONNECT_CONTROL, 2).value is False
        result = m.action("0.0.42.0.0.255", ClassId.DATA, 1, DlmsData.octet_string(bytes(400)))
        assert result.value == 7 and len(received[0].value) == 400
        with pytest.raises(ServiceError):
            m.action("0.0.42.0.0.255", ClassId.DATA, 9)


# --- association mechanisms --------------------------------------------------------


def test_lls(meter):
    meter.clients[16] = ClientProfile(Mechanism.LLS, b"12345678")
    with client(meter, mechanism=Mechanism.LLS, password="12345678") as m:
        assert m.get_register("1.0.1.8.0.255").value == 12345678


def test_lls_wrong_password(meter):
    meter.clients[16] = ClientProfile(Mechanism.LLS, b"12345678")
    m = client(meter, mechanism=Mechanism.LLS, password="wrong")
    with pytest.raises(AssociationError) as info:
        m.connect()
    assert info.value.diagnostic == 13  # authentication-failure
    m.link.disconnect()


def test_unknown_client_sap_rejected(meter):
    host, port = meter.start()
    m = DlmsClient.tcp(host, port, client_sap=99, timeout=3)
    with pytest.raises(AssociationError):
        m.connect()
    m.link.disconnect()


@pytest.mark.parametrize("mechanism", [Mechanism.HLS_MD5, Mechanism.HLS_SHA1])
def test_hls_hash_mechanisms(meter, mechanism):
    meter.clients[16] = ClientProfile(mechanism, b"HLSsecret")
    with client(meter, mechanism=mechanism, password=b"HLSsecret") as m:
        assert m.get_register("1.0.1.7.0.255").value == 1520


@pytest.mark.parametrize("mechanism", [Mechanism.HLS_MD5, Mechanism.HLS_SHA1])
def test_hls_wrong_secret_rejected(meter, mechanism):
    meter.clients[16] = ClientProfile(mechanism, b"HLSsecret")
    m = client(meter, mechanism=mechanism, password=b"nope")
    with pytest.raises(AssociationError):
        m.connect()
    m.link.disconnect()


def test_hls_gmac_ciphered(meter):
    meter.clients[16] = ClientProfile(Mechanism.HLS_GMAC, ciphered=True)
    ctx = security()
    with client(meter, mechanism=Mechanism.HLS_GMAC, security=ctx) as m:
        assert m.get_register("1.0.1.8.0.255").value == 12345678
        assert ctx.server_system_title == meter.system_title
    # Every service APDU after the AARQ went out ciphered (glo-).
    assert all(r[0] in (0x60, 0x62, 0xCB, 0xC8) for r in meter.requests)


def test_hls_sha256_ciphered(meter):
    meter.clients[16] = ClientProfile(Mechanism.HLS_SHA256, b"sha256-secret", ciphered=True)
    with client(
        meter, mechanism=Mechanism.HLS_SHA256, password=b"sha256-secret", security=security()
    ) as m:
        assert m.get("0.0.96.1.0.255").value == "PYD0000000001"


def test_hls_gmac_wrong_key_rejected(meter):
    pytest.importorskip("cryptography")
    from pydlms.security.context import SecurityContext

    meter.clients[16] = ClientProfile(Mechanism.HLS_GMAC, ciphered=True)
    bad = SecurityContext(EK, bytes(16), client_system_title=CLIENT_TITLE)
    m = client(meter, mechanism=Mechanism.HLS_GMAC, security=bad)
    with pytest.raises((AssociationError, ServiceError)):
        m.connect()
    m.link.disconnect()


def test_ciphered_lls_with_dedicated_key(meter):
    meter.clients[16] = ClientProfile(Mechanism.LLS, b"12345678", ciphered=True)
    ctx = security()
    with client(
        meter, mechanism=Mechanism.LLS, password="12345678", security=ctx, use_dedicated_key=True
    ) as m:
        assert m.get_register("1.0.1.8.0.255").value == 12345678
        assert ctx.dedicated_key is not None
    assert any(r[0] == 0xD0 for r in meter.requests)  # ded-get-request


def test_ciphered_counters_increase(meter):
    meter.clients[16] = ClientProfile(Mechanism.NONE, ciphered=True)
    ctx = security(invocation_counter=1000)
    with client(meter, security=ctx) as m:
        for _ in range(3):
            m.get_register("1.0.1.8.0.255")
    assert ctx.invocation_counter > 1000 + 6


def test_ciphered_required_but_plain_requested(meter):
    meter.clients[16] = ClientProfile(Mechanism.NONE, ciphered=True)
    m = client(meter)
    with pytest.raises(AssociationError) as info:
        m.connect()
    assert info.value.diagnostic == 2  # application-context-name-not-supported
    m.link.disconnect()


def test_gmac_without_context_is_a_key_error(meter):
    meter.clients[16] = ClientProfile(Mechanism.HLS_GMAC, ciphered=False)
    m = client(meter, mechanism=Mechanism.HLS_GMAC)
    with pytest.raises(KeyMissingError):
        m.connect()
    m.link.disconnect()


# --- short names -------------------------------------------------------------------------


def test_short_name_referencing(meter):
    with client(meter, logical_names=False) as m:
        assert m.get_register("1.0.1.8.0.255").value == 12345678
        assert m.get("0.0.96.1.0.255").value == "PYD0000000001"
        m.set("0.0.96.1.0.255", ClassId.DATA, 2, DlmsData.visible_string("SN-WRITE"))
        assert m.get("0.0.96.1.0.255").value == "SN-WRITE"
        view = m.get_association_view()
        assert all(e.base_name is not None for e in view)
    assert any(r[0] == 0x05 for r in meter.requests)  # SN ReadRequest on the wire


def test_short_name_hls(meter):
    meter.clients[16] = ClientProfile(Mechanism.HLS_MD5, b"secret!!")
    with client(meter, logical_names=False, mechanism=Mechanism.HLS_MD5, password=b"secret!!") as m:
        assert m.get_register("1.0.31.7.0.255").value == pytest.approx(5.23)


# --- HDLC specifics ----------------------------------------------------------------------


def test_hdlc_segmentation_both_directions(meter):
    from pydlms.hdlc.connection import HdlcParameters

    host, port = meter.start(hdlc=True)
    m = DlmsClient.tcp(host, port, hdlc=True, timeout=3)
    m.link.proposed = HdlcParameters(max_info_tx=32, max_info_rx=32)
    with m:
        assert m.link.negotiated.max_info_tx == 32
        big = DlmsData.visible_string("X" * 150)
        m.set("0.0.96.1.0.255", ClassId.DATA, 2, big)
        assert m.get("0.0.96.1.0.255").value == "X" * 150


def test_release_and_reconnect(meter):
    m = client(meter)
    m.connect()
    m.close()
    assert any(r[0] == 0x62 for r in meter.requests)  # RLRQ sent
    m.connect()
    assert m.get_register("1.0.1.8.0.255").value == 12345678
    m.close()


def test_service_before_association_raises(meter):
    from pydlms.exceptions import ProtocolError

    m = DlmsClient.tcp(*meter.start(), timeout=3)
    m.auto_associate = False
    m.connect()
    with pytest.raises(ProtocolError):
        m.get("1.0.1.8.0.255", 3, 2)
    m.link.disconnect()


def test_read_push_from_wrapper_link():
    """A meter pushing a DataNotification to a listening client (wrapper link)."""
    from pydlms.apdu.xdlms import DataNotification
    from pydlms.transports.base import LoopbackTransport
    from pydlms.wrapper import WrapperLink, encode_wrapper

    note = DataNotification(
        7,
        DlmsData.structure(
            [
                DlmsData.structure(
                    [DlmsData.octet_string(bytes([1, 0, 1, 8, 0, 255])), DlmsData.uint32(42)]
                )
            ]
        ),
    )
    transport = LoopbackTransport(timeout=0.5)
    transport.inject(encode_wrapper(1, 0x10, note.to_bytes()))
    client = DlmsClient(WrapperLink(transport), auto_associate=False)
    client.connect()
    message = client.read_push()
    assert message.get("1.0.1.8.0.255") == 42
    assert message.notification.long_invoke_id == 7


def test_short_name_block_transfer_and_method(meter):
    meter.max_pdu = 200  # the 96-row profile no longer fits one ReadResponse
    with client(meter, logical_names=False) as m:
        profile = m.read_profile("1.0.99.1.0.255")
        assert len(profile.rows) == 96
        assert m.get("0.0.96.3.10.255", ClassId.DISCONNECT_CONTROL, 2).value is True
        m.action(
            "0.0.96.3.10.255", ClassId.DISCONNECT_CONTROL, "remote_disconnect", DlmsData.int8(0)
        )
        assert m.get("0.0.96.3.10.255", ClassId.DISCONNECT_CONTROL, 2).value is False
    # The SN block continuation (block-number-access, choice 5) was on the wire.
    assert any(r[0] == 0x05 and r[2] == 0x05 for r in meter.requests)


# --- UDP wrapper -------------------------------------------------------------------


def _serve_udp(sim):
    """Test-side UDP front end for the simulator: one wrapper PDU per datagram.

    ``serve()`` only speaks TCP; this loop is the smallest UDP equivalent
    (IEC 62056-47 over UDP carries exactly one wrapper PDU per datagram).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(0.05)
    session = _Session()
    seen: list[tuple[int, int]] = []
    stop = threading.Event()

    def run():
        while not stop.is_set():
            try:
                data, addr = sock.recvfrom(65535)
            except TimeoutError:
                continue
            except OSError:
                return
            pdu = decode_wrapper(data)
            seen.append((pdu.source, pdu.destination))
            session.client_sap = pdu.source
            response = sim.handle(pdu.apdu, session)
            if response is not None:
                sock.sendto(encode_wrapper(pdu.destination, pdu.source, response), addr)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()

    def close():
        stop.set()
        thread.join(1)
        sock.close()

    return sock.getsockname(), seen, close


def test_udp_associate_read_and_block_transfer():
    sim = example_meter()
    sim.max_pdu = 256  # the profile needs several GET-Response-with-datablock datagrams
    (host, port), seen, close = _serve_udp(sim)
    try:
        with DlmsClient.udp(host, port, timeout=3) as m:
            energy = m.get_register("1.0.1.8.0.255")
            assert energy.value == 12345678 and energy.unit == Unit.WATT_HOUR
            assert m.get("0.0.96.1.0.255").value == "PYD0000000001"
            profile = m.read_profile("1.0.99.1.0.255")
            assert len(profile.rows) == 96
            assert profile.rows[-1][1] == 1000 + 95 * 7
    finally:
        close()
    assert sim.requests[0][0] == 0x60  # AARQ came in over UDP
    assert any(r[:2] == b"\xc0\x02" for r in sim.requests)  # GET-Request-Next
    # Every datagram went public client wPort 0x10 -> logical device wPort 0x01.
    assert seen and set(seen) == {(0x10, 0x01)}


# --- REVIEW F9: no request APDU exceeds the server's max-receive-pdu-size ------------

PROTECTIONS = [
    pytest.param({}, id="plain"),
    pytest.param({"protection": "glo"}, id="glo"),
    pytest.param({"protection": "glo", "use_dedicated_key": True}, id="ded"),
    pytest.param({"protection": "general-glo"}, id="general-glo"),
]


@pytest.mark.parametrize("settings", PROTECTIONS)
@pytest.mark.parametrize("size", [150, 200, 222, 224, 240, 600])
def test_set_never_exceeds_server_max_pdu(meter, settings, size):
    """REVIEW F9 repro: with server_max_pdu 256 the glo SET-normal at the old
    limit was 257 octets, general-glo with datablocks 274."""
    meter.max_pdu = 256
    ciphered = bool(settings)
    if ciphered:
        meter.clients[16] = ClientProfile(Mechanism.NONE, ciphered=True)
        settings = {**settings, "security": security()}
    value = DlmsData.octet_string(bytes(range(256))[:size] if size <= 256 else bytes(size))
    with client(meter, **settings) as m:
        assert m.association.server_max_pdu == 256
        start = len(meter.requests)
        m.set("0.0.42.0.0.255", ClassId.DATA, 2, value)
        sent = meter.requests[start:]
    assert max(len(r) for r in sent) <= 256, [len(r) for r in sent]
    with client(meter, **settings) as m:
        assert m.get("0.0.42.0.0.255").value == value.value


@pytest.mark.parametrize("settings", PROTECTIONS)
@pytest.mark.parametrize("size", [150, 222, 240, 600])
def test_action_never_exceeds_server_max_pdu(meter, settings, size):
    received = []
    meter.add_method(
        ClassId.DATA, "0.0.42.0.0.255", 1, lambda sim, params: received.append(params) or None
    )
    meter.max_pdu = 256
    if settings:
        meter.clients[16] = ClientProfile(Mechanism.NONE, ciphered=True)
        settings = {**settings, "security": security()}
    parameters = DlmsData.octet_string(bytes(size))
    with client(meter, **settings) as m:
        start = len(meter.requests)
        m.action("0.0.42.0.0.255", ClassId.DATA, 1, parameters)
        sent = meter.requests[start:]
    assert max(len(r) for r in sent) <= 256, [len(r) for r in sent]
    assert received and received[0].value == parameters.value


def test_request_larger_than_server_max_pdu_is_refused_before_sending(meter):
    from pydlms.apdu.xdlms import AttributeDescriptor, SetRequestWithList
    from pydlms.obis import ObisCode

    meter.max_pdu = 256
    descriptor = AttributeDescriptor(ClassId.DATA, ObisCode.parse("0.0.42.0.0.255"), 2)
    with client(meter) as m:
        start = len(meter.requests)
        request = SetRequestWithList(
            m.association.next_invoke_id(),
            [(descriptor, None, DlmsData.octet_string(bytes(60)))] * 5,
        )
        with pytest.raises(ProtocolError, match="exceeds"):
            m.association.request(request.to_bytes())
        assert len(meter.requests) == start


def test_set_with_list_counts_the_ciphering_overhead(meter):
    # Two 100-octet values fit 256 octets in clear but not general-glo
    # ciphered: set_many must split the list by the protected size.
    meter.max_pdu = 256
    meter.clients[16] = ClientProfile(Mechanism.NONE, ciphered=True)
    items = [("0.0.42.0.0.255", ClassId.DATA, 2, DlmsData.octet_string(bytes(100)))] * 2
    with client(meter, security=security(), protection="general-glo") as m:
        m.association.negotiated_conformance |= Conformance.MULTIPLE_REFERENCES
        start = len(meter.requests)
        assert m.set_many(items) == [DataAccessResult.SUCCESS] * 2
        sent = meter.requests[start:]
    assert len(sent) == 2
    assert max(len(r) for r in sent) <= 256, [len(r) for r in sent]


def test_read_profile_entry_columns_narrow_the_column_list(meter):
    with client(meter) as m:
        # Columns 2..2 only: the energy register, not the clock.
        profile = m.read_profile("1.0.99.1.0.255", entry_descriptor(10, 11, 2, 2))
        assert [(c[0], str(c[1]), c[2]) for c in profile.columns] == [(3, "1.0.1.8.0.255", 2)]
        assert profile.rows == [[1063], [1070]]
        # to_column 0 means "up to the last column".
        tail = m.read_profile("1.0.99.1.0.255", entry_descriptor(10, 10, 2, 0))
        assert [str(c[1]) for c in tail.columns] == ["1.0.1.8.0.255"]


def test_read_profile_range_selected_values_narrow_the_column_list(meter):
    from pydlms.obis import ObisCode

    start = dt.datetime(2024, 5, 1, 1, 0, tzinfo=dt.timezone.utc)
    end = dt.datetime(2024, 5, 1, 1, 30, tzinfo=dt.timezone.utc)
    energy = (3, ObisCode.parse("1.0.1.8.0.255"), 2, 0)
    with client(meter) as m:
        profile = m.read_profile(
            "1.0.99.1.0.255",
            range_descriptor(
                date_time_value(start), date_time_value(end), selected_values=[energy]
            ),
        )
    assert [str(c[1]) for c in profile.columns] == ["1.0.1.8.0.255"]
    assert profile.rows == [[1028], [1035], [1042]]


def test_read_profile_rejects_rows_that_do_not_match_the_columns(meter):
    from pydlms.exceptions import DecodeError
    from pydlms.obis import ObisCode

    key = (ClassId.PROFILE_GENERIC, ObisCode.parse("1.0.99.1.0.255"))
    rows = meter.objects[key][2].value
    meter.objects[key][2] = DlmsData.array([*rows[:2], DlmsData.structure(rows[2].value[:1])])
    with client(meter) as m, pytest.raises(DecodeError, match="row 3"):
        m.read_profile("1.0.99.1.0.255")


def test_range_descriptor_bounds_are_instants_not_octets(meter):
    """Day-of-week 0xFF (not specified) and another deviation still select by
    the instant (Blue Book 4.1.6.1 date-time fields)."""
    from dataclasses import replace

    from pydlms.cosem.time import CosemDateTime

    def bound(when):
        stamp = CosemDateTime.from_datetime(when)
        return DlmsData.octet_string(
            replace(stamp, date=replace(stamp.date, day_of_week=None)).to_bytes()
        )

    start = dt.datetime(2024, 5, 1, 0, 0, tzinfo=dt.timezone.utc)
    end = dt.datetime(2024, 5, 1, 3, 0, tzinfo=dt.timezone(dt.timedelta(hours=2)))  # 01:00 UTC
    with client(meter) as m:
        profile = m.read_profile("1.0.99.1.0.255", range_descriptor(bound(start), bound(end)))
    assert [row[1] for row in profile.rows] == [1000, 1007, 1014, 1021, 1028]


def test_get_many_splits_requests_to_fit_the_server_pdu(meter):
    meter.max_pdu = 128
    names = ["1.0.1.8.0.255", "9.9.9.9.9.9", "1.0.2.8.0.255"] * 10
    with client(meter) as m:
        limit = m.association.max_plain_request()
        values = m.get_many([(name, 3, 2) for name in names])
    with_list = [r for r in meter.requests if r[:2] == b"\xc0\x03"]
    assert len(with_list) > 1
    assert all(len(r) <= limit for r in with_list)
    assert [v.value if isinstance(v, DlmsData) else v for v in values] == [
        12345678,
        DataAccessResult.OBJECT_UNDEFINED,
        4321,
    ] * 10


def test_short_name_method_address_uses_the_object_version(meter):
    from pydlms.obis import ObisCode

    called = []
    meter.add_object(
        ClassId.SECURITY_SETUP,
        "0.0.43.0.0.255",
        {2: DlmsData.enum(0), 3: DlmsData.enum(0)},
        version=0,
        base_name=0x5000,
    )
    meter.add_method(
        ClassId.SECURITY_SETUP, ObisCode.parse("0.0.43.0.0.255"), 1, lambda m, p: called.append(p)
    )
    with client(meter, logical_names=False) as m:
        m.action("0.0.43.0.0.255", ClassId.SECURITY_SETUP, "security_activate", DlmsData.enum(1))
    assert called and called[0].value == 1
    # ReadRequest, one item, parameterized access (4) at base + 0x28 (v0)
    assert any(r[:5] == bytes.fromhex("0501045028") for r in meter.requests)


def test_release_keeps_the_dedicated_key(meter):
    meter.clients[16] = ClientProfile(Mechanism.LLS, b"12345678", ciphered=True)
    ctx = security()
    m = client(
        meter, mechanism=Mechanism.LLS, password="12345678", security=ctx, use_dedicated_key=True
    )
    m.connect()
    key = ctx.dedicated_key
    counter = ctx.invocation_counter
    m.close()
    assert ctx.dedicated_key == key
    assert ctx.invocation_counter == counter + 1  # the RLRQ InitiateRequest is ciphered anew
    rlrq = [r for r in meter.requests if r[0] == 0x62]
    assert len(rlrq) == 1


# --- the ciphered release is verified --------------------------------------------------


@pytest.mark.parametrize("dedicated", [False, True], ids=["global", "dedicated"])
def test_ciphered_release_is_verified(meter, dedicated):
    meter.clients[16] = ClientProfile(Mechanism.LLS, b"12345678", ciphered=True)
    m = client(
        meter,
        mechanism=Mechanism.LLS,
        password="12345678",
        security=security(),
        use_dedicated_key=dedicated,
        require_verified_release=True,
    )
    with m:
        m.get("0.0.42.0.0.255")
    assert m.association.release_status == "verified"


def test_plain_release_status(meter):
    with client(meter) as m:
        m.get("0.0.42.0.0.255")
    assert m.association.release_status == "plain"


def test_close_disconnects_and_keeps_the_counter_when_release_is_refused(
    meter, monkeypatch, tmp_path
):
    from pydlms.apdu.acse import RLRE
    from pydlms.counters import CounterStore
    from pydlms.exceptions import AuthenticationError

    # A meter that answers the ciphered RLRQ without user-information.
    monkeypatch.setattr(meter, "_ciphered_rlre", lambda rlrq, session: RLRE(0))
    meter.clients[16] = ClientProfile(Mechanism.LLS, b"12345678", ciphered=True)
    store = CounterStore(tmp_path / "ic.json")
    ctx = security()
    m = client(
        meter,
        mechanism=Mechanism.LLS,
        password="12345678",
        security=ctx,
        counter_store=store,
        require_verified_release=True,
    )
    m.connect()
    disconnected = []
    real = m.link.disconnect
    monkeypatch.setattr(m.link, "disconnect", lambda: (disconnected.append(1), real())[1])
    with pytest.raises(AuthenticationError, match="unverified"):
        m.close()
    assert disconnected == [1]
    assert m.association.release_status == "unverified"
    assert store.get(m._store_key()) == ctx.invocation_counter
