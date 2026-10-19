"""Invocation-counter discovery, retry and persistence (pydlms.counters)."""

from __future__ import annotations

import json

import pytest

from pydlms.client import DlmsClient
from pydlms.counters import CounterLocation, CounterStore, key_fingerprint, register_location
from pydlms.exceptions import InvocationCounterError
from pydlms.obis import ObisCode
from pydlms.security.hls import Mechanism
from pydlms.simulator import ClientProfile, example_meter, serve

pytest.importorskip("cryptography")

from pydlms.security.context import SecurityContext  # noqa: E402

EK = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
AK = bytes.fromhex("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF")


@pytest.fixture
def meter():
    sim = example_meter(encryption_key=EK, authentication_key=AK)
    sim.clients[1] = ClientProfile(Mechanism.HLS_GMAC, ciphered=True)
    sim.set_ic_location("0.0.43.1.0.255", last=5000)  # the meter has seen IC 5000
    server = serve(sim)
    sim.address = server.server_address
    yield sim
    server.shutdown()
    server.server_close()


def _client(meter, ic=0, **kw) -> tuple[DlmsClient, SecurityContext]:
    ctx = SecurityContext(EK, AK, client_system_title=b"PYDCLNT1", invocation_counter=ic)
    client = DlmsClient.tcp(
        *meter.address, client_sap=1, mechanism=Mechanism.HLS_GMAC, security=ctx, timeout=3, **kw
    )
    return client, ctx


def test_stale_counter_is_refused_with_the_expected_value(meter):
    client, _ = _client(meter, ic=10)
    with pytest.raises(InvocationCounterError) as info:
        client.connect()
    assert info.value.expected == 5000
    client.link.disconnect()


def test_retry_continues_from_the_reported_counter(meter):
    client, ctx = _client(meter, ic=10, invocation_counter_retry=True)
    with client:
        assert client.get_register("1.0.1.8.0.255").value == 12345678
    assert ctx.invocation_counter > 5001


def test_discovery_reads_the_standard_object(meter):
    client, ctx = _client(meter, discover_invocation_counter=True)
    with client:
        assert client.get_register("1.0.1.8.0.255").value == 12345678
    # The public association ran first, on SAP 16, without ciphering.
    assert meter.requests[0][0] == 0x60 and b"\x21" not in meter.requests[0][:20]


def test_discovery_finds_a_vendor_location(meter):
    # Mimic a vendor that keeps the counter outside 0.0.43.1.x.255.
    meter.set_ic_location("0.128.96.1.4.255", last=7000)
    client, ctx = _client(meter, discover_invocation_counter=True)
    with pytest.raises(InvocationCounterError):  # not in the object list scan
        client.connect()
    client.link.disconnect()

    register_location(
        "PYD", CounterLocation(ObisCode.parse("0.128.96.1.4.255"), source="test fixture")
    )
    try:
        client, ctx = _client(meter, discover_invocation_counter=True)
        with client:
            pass
        assert ctx.invocation_counter > 7001
        assert client.manufacturer is None  # derived from the logical device name "PYD..."
    finally:
        from pydlms.counters import VENDOR_LOCATIONS

        VENDOR_LOCATIONS.pop("PYD", None)


def test_explicit_extra_location(meter):
    meter.set_ic_location("0.128.96.1.4.255", last=7000)
    client, ctx = _client(meter)
    found = client.discover_counter(
        extra_locations=[CounterLocation(ObisCode.parse("0.128.96.1.4.255"))]
    )
    assert found == {"1/0.128.96.1.4.255/2": 7000}
    with client:
        pass
    assert ctx.invocation_counter > 7001


def test_counter_store_round_trip(meter, tmp_path):
    store = CounterStore(tmp_path / "ic.json")
    client, ctx = _client(meter, ic=6000, counter_store=store)
    with client:
        client.get_register("1.0.1.8.0.255")
    saved = json.loads((tmp_path / "ic.json").read_text())
    ((key, value),) = saved.items()
    assert value == ctx.invocation_counter > 6000
    assert EK.hex() not in key and key_fingerprint(EK) in key
    # A new client with a stale counter continues from the stored value.
    client2, ctx2 = _client(meter, ic=0, counter_store=store)
    with client2:
        client2.get_register("1.0.1.8.0.255")
    assert ctx2.invocation_counter > value


def test_store_never_lowers(tmp_path):
    store = CounterStore(tmp_path / "ic.json")
    store.put("k", 10)
    store.put("k", 5)
    assert store.get("k") == 10
    assert store.get("missing") is None


def test_store_unreadable_file(tmp_path):
    from pydlms.exceptions import DlmsError

    path = tmp_path / "ic.json"
    path.write_text("{not json")
    with pytest.raises(DlmsError):
        CounterStore(path).get("k")


def test_key_fingerprint_is_not_the_key():
    assert key_fingerprint(None) == "none"
    assert len(key_fingerprint(EK)) == 16 and EK.hex()[:16] != key_fingerprint(EK)


def test_counter_obis_range():
    from pydlms.counters import BLIND_CANDIDATES, is_counter_obis

    assert is_counter_obis(ObisCode.parse("0.0.43.1.0.255"))
    assert is_counter_obis(ObisCode.parse("0.1.43.1.1.255"))  # Italian offline management
    assert is_counter_obis(ObisCode.parse("0.64.43.1.127.255"))
    assert not is_counter_obis(ObisCode.parse("0.65.43.1.0.255"))
    assert not is_counter_obis(ObisCode.parse("0.0.43.0.0.255"))  # security setup
    assert not is_counter_obis(ObisCode.parse("1.0.43.1.0.255"))
    assert all(is_counter_obis(o) for o in BLIND_CANDIDATES)


def test_vendor_table_is_sourced_and_in_range():
    from pydlms.counters import VENDOR_LOCATIONS, is_counter_obis

    assert "KFM" not in VENDOR_LOCATIONS  # no public source yet
    for flag, locations in VENDOR_LOCATIONS.items():
        assert len(flag) == 3 and flag.isupper()
        for location in locations:
            assert location.source and location.confidence
            assert is_counter_obis(location.obis)


def test_metcom_management_counter_is_confirmed_by_two():
    # MetCom MCS301: gurux.fi/node/13858 (management client HLS-GMAC reads
    # 0.0.43.1.0.255, read + 1); Gurux.DLMS.DeviceProfiles@137f6ad (CC0)
    # MetCom/MCS301 and MCS501 HDLC/Management.gxc FrameCounter.
    from pydlms.counters import VENDOR_LOCATIONS

    (location,) = VENDOR_LOCATIONS["MCS"]
    assert str(location.obis) == "0.0.43.1.0.255"
    assert location.confidence == "confirmed by 2"


def test_discovery_finds_non_zero_b_group(meter):
    meter.set_ic_location("0.1.43.1.1.255", last=8000)
    client, ctx = _client(meter, discover_invocation_counter=True)
    with client:
        pass
    assert ctx.invocation_counter > 8001


def test_physical_address_from_serial():
    from pydlms.hdlc.address import physical_address_from_serial

    assert physical_address_from_serial(12345678, "Landis+Gyr") == 6678
    assert physical_address_from_serial("LGZ 0012-3456", "landis+gyr") == 4456
    assert physical_address_from_serial(98765, "emh") == 8765 + 256
    assert physical_address_from_serial(1234, "milur") == 1250
    with pytest.raises(KeyError):
        physical_address_from_serial(1, "hexing")
    with pytest.raises(ValueError):
        physical_address_from_serial("abc", "elgama")


# --- the retry hint is unauthenticated ------------------------------------------------


@pytest.mark.parametrize("hint", [0xFFFFFFF0, 0xFFFFFFFF])
def test_retry_refuses_a_hint_that_would_exhaust_the_counter(meter, tmp_path, hint):
    """The ExceptionResponse carrying the hint is not authenticated: a hint
    of 0xFFFFFFFF used to move (and, through the store, persist) the
    counter to its end, so every later session with that key failed."""
    meter.set_ic_location("0.0.43.1.0.255", last=hint)
    store = CounterStore(tmp_path / "ic.json")
    client, ctx = _client(meter, ic=10, invocation_counter_retry=True, counter_store=store)
    with pytest.raises(InvocationCounterError, match="exhaust"):
        client.connect()
    client.close()
    assert ctx.invocation_counter < 0xFFFFFFF0
    assert all(v < 0xFFFFFFF0 for v in json.loads((tmp_path / "ic.json").read_text()).values())


def test_retry_accepts_a_hint_below_the_limit(meter):
    meter.set_ic_location("0.0.43.1.0.255", last=0xFFFFFFEE)
    client, ctx = _client(meter, ic=10, invocation_counter_retry=True)
    with client:
        assert client.get_register("1.0.1.8.0.255").value == 12345678
    assert ctx.invocation_counter > 0xFFFFFFEF
