"""Addressing and association settings exposed by the DlmsClient
constructors: HDLC address size, physical address from the
serial, wrapper client wPort, AssociationSettings pass-through."""

from __future__ import annotations

import contextlib

import pytest

from pydlms import DlmsClient
from pydlms.apdu.xdlms import Conformance
from pydlms.debug import FrameRecorder
from pydlms.hdlc.address import HdlcAddress
from pydlms.simulator import ClientProfile, example_meter, serve

# What the default constructors put on the wire before X5, recorded from
# DlmsClient.tcp(...) against the simulator at 641eca9: the wrapper AARQ
# and the HDLC SNRM plus the AARQ I-frame.
WRAPPER_AARQ = bytes.fromhex(
    "000100100001001f601da109060760857405080101be10040e01000000065f1f0400007e1fffff"
)
HDLC_SNRM = bytes.fromhex("7ea01e032193cd3b818012050180060180070400000001080400000001533b7e")
HDLC_AARQ = bytes.fromhex(
    "7ea02b032110fbafe6e600601da109060760857405080101be10040e01000000065f1f0400007e1fffff99c87e"
)


@contextlib.contextmanager
def simulator(hdlc: bool = False, sim=None):
    server = serve(sim or example_meter(), hdlc=hdlc)
    try:
        yield server.server_address[:2]
    finally:
        server.shutdown()
        server.server_close()


def _tx(client: DlmsClient) -> list[bytes]:
    recorder = FrameRecorder()
    client.link.transport.recorder = recorder
    with client as meter:
        meter.get("0.0.1.0.0.255", 8, 2)
    return [data for kind, data in recorder.frames if kind == "TX"]


# -- defaults ----------------------------------------------------------------


def test_default_wrapper_aarq_unchanged():
    with simulator() as (host, port):
        assert _tx(DlmsClient.tcp(host, port, timeout=3))[0] == WRAPPER_AARQ


def test_default_hdlc_snrm_and_aarq_unchanged():
    with simulator(hdlc=True) as (host, port):
        frames = _tx(DlmsClient.tcp(host, port, hdlc=True, timeout=3))
    assert frames[:2] == [HDLC_SNRM, HDLC_AARQ]


# -- address_size ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("size", "physical", "expected"),
    [
        (None, None, HdlcAddress(1, None, 1)),
        (1, None, HdlcAddress(1, None, 1)),
        (2, 17, HdlcAddress(1, 17, 2)),
        (4, 17, HdlcAddress(1, 17, 4)),
        (None, 17, HdlcAddress(1, 17, 2)),
        (4, 0x3FFF, HdlcAddress(1, 0x3FFF, 4)),
    ],
)
def test_tcp_hdlc_address_size(size, physical, expected):
    client = DlmsClient.tcp("192.0.2.1", hdlc=True, server_physical=physical, address_size=size)
    assert client.link.server == expected


@pytest.mark.parametrize(
    ("size", "physical", "logical", "match"),
    [
        (3, 17, 1, "1, 2 or 4"),
        (0, None, 1, "1, 2 or 4"),
        (True, None, 1, "1, 2 or 4"),
        (1, 17, 1, "no lower part"),
        (2, None, 1, "needs a physical"),
        (4, None, 1, "needs a physical"),
        (2, 200, 1, "out of range"),
        (2, 17, 200, "out of range"),
        (4, 0x4000, 1, "out of range"),
    ],
)
def test_address_size_invalid(size, physical, logical, match, monkeypatch):
    # No transport may be created, let alone opened.
    import pydlms.transports.tcp as tcp

    def no_io(*a, **k):
        raise AssertionError("transport created")

    monkeypatch.setattr(tcp, "TcpTransport", no_io)
    with pytest.raises(ValueError, match=match):
        DlmsClient.tcp(
            "192.0.2.1",
            hdlc=True,
            server_logical=logical,
            server_physical=physical,
            address_size=size,
        )


def test_serial_and_optical_address_size():
    pytest.importorskip("serial")
    serial = DlmsClient.serial("loop://", server_physical=17, address_size=4)
    optical = DlmsClient.optical("loop://", server_physical=17, address_size=4)
    assert serial.link.server == optical.link.server == HdlcAddress(1, 17, 4)
    with pytest.raises(ValueError, match="1, 2 or 4"):
        DlmsClient.serial("loop://", address_size=3)
    with pytest.raises(ValueError, match="1, 2 or 4"):
        DlmsClient.optical("loop://", address_size=3)


def test_hdlc_options_need_hdlc():
    with pytest.raises(ValueError, match="address_size requires hdlc=True"):
        DlmsClient.tcp("192.0.2.1", address_size=4)
    with pytest.raises(ValueError, match="physical_from_serial requires hdlc=True"):
        DlmsClient.tcp("192.0.2.1", physical_from_serial=(12345678, "landis+gyr"))


def test_four_octet_address_end_to_end():
    with simulator(hdlc=True) as (host, port):
        client = DlmsClient.tcp(
            host, port, hdlc=True, server_physical=0x1234, address_size=4, timeout=3
        )
        frames = _tx(client)
    # SNRM: flag, format (2), then the 4-octet destination 1/0x1234:
    # 00 02 | 48 69 (7-bit halves 0x00 0x01 | 0x24 0x34, shifted, EA on the last).
    assert frames[0][3:7] == bytes([0x00, 0x02, 0x48, 0x69])
    assert frames[0][7] == 0x21  # client SAP 16


# -- physical_from_serial ---------------------------------------------------------


def test_physical_from_serial():
    client = DlmsClient.tcp("192.0.2.1", hdlc=True, physical_from_serial=("12345678", "Landis+Gyr"))
    # Landis+Gyr: 1000 + serial % 10000 = 6678, too large for 7 bits.
    assert client.link.server == HdlcAddress(1, 6678, 4)
    small = DlmsClient.tcp(
        "192.0.2.1", hdlc=True, physical_from_serial=(5, "milur"), address_size=2
    )
    assert small.link.server == HdlcAddress(1, 21, 2)


def test_physical_from_serial_serial_and_optical():
    pytest.importorskip("serial")
    for build in (DlmsClient.serial, DlmsClient.optical):
        client = build("loop://", physical_from_serial=(12345678, "elgama"))
        assert client.link.server == HdlcAddress(1, 6678, 4)


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"server_physical": 17, "physical_from_serial": (1, "emh")}, "not both"),
        ({"physical_from_serial": (1, "acme")}, "no serial address rule.*landis"),
        ({"physical_from_serial": ("abc", "emh")}, "no digits"),
        ({"physical_from_serial": "12345678"}, r"\(serial, vendor\) pair"),
        ({"physical_from_serial": (12345678, "emh"), "address_size": 2}, "out of range"),
    ],
)
def test_physical_from_serial_invalid(kwargs, match):
    with pytest.raises(ValueError, match=match):
        DlmsClient.tcp("192.0.2.1", hdlc=True, **kwargs)


# -- client_wport -----------------------------------------------------------------


def test_client_wport_defaults_to_client_sap():
    assert DlmsClient.tcp("192.0.2.1", client_sap=1).link.client_wport == 1
    assert DlmsClient.udp("192.0.2.1", client_sap=1).link.client_wport == 1


def test_client_wport_override():
    tcp = DlmsClient.tcp("192.0.2.1", client_sap=16, client_wport=0x1234)
    udp = DlmsClient.udp("192.0.2.1", client_sap=16, client_wport=0xFFFF)
    assert tcp.link.client_wport == 0x1234
    assert udp.link.client_wport == 0xFFFF


@pytest.mark.parametrize("value", [-1, 0x10000, True, "16"])
def test_client_wport_invalid(value):
    with pytest.raises(ValueError, match="client_wport"):
        DlmsClient.tcp("192.0.2.1", client_wport=value)
    with pytest.raises(ValueError, match="client_wport"):
        DlmsClient.udp("192.0.2.1", client_wport=value)


def test_client_wport_is_not_hdlc():
    with pytest.raises(ValueError, match="wrapper option"):
        DlmsClient.tcp("192.0.2.1", hdlc=True, client_wport=0x20)


def test_client_wport_end_to_end():
    sim = example_meter()
    sim.clients[0x20] = ClientProfile()
    with simulator(sim=sim) as (host, port):
        frames = _tx(DlmsClient.tcp(host, port, client_wport=0x20, timeout=3))
    # Every WPDU leaves from wPort 0x0020 to the management logical device.
    assert {frame[2:6] for frame in frames} == {bytes.fromhex("00200001")}


# -- AssociationSettings pass-through ----------------------------------------------


def test_association_settings_pass_through_every_constructor():
    pytest.importorskip("serial")
    fields = {
        "max_receive_pdu_size": 512,
        "conformance": Conformance.GET | Conformance.SET,
        "gbt_window": 4,
        "require_verified_release": True,
        "invocation_counter_retry": True,
        "expected_server_system_title": b"ABCDEFGH",
        "client_system_title": b"PYDLMS01",
        "protection": "general-glo",
        "use_dedicated_key": True,
    }
    clients = [
        DlmsClient.tcp("192.0.2.1", **fields),
        DlmsClient.tcp("192.0.2.1", hdlc=True, **fields),
        DlmsClient.udp("192.0.2.1", **fields),
        DlmsClient.serial("loop://", **fields),
        DlmsClient.optical("loop://", **fields),
    ]
    for client in clients:
        settings = client.association.settings
        for name, value in fields.items():
            assert getattr(settings, name) == value, name


def test_unknown_setting_rejected():
    with pytest.raises(TypeError, match="no_such_field"):
        DlmsClient.tcp("192.0.2.1", no_such_field=1)
