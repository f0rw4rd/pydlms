"""Security Setup ``security_activate`` (IC 64 method 1) against the simulator.

Version 0 takes an enum 0..3, version 1 a bit field (bits 0 and 1
reserved); the version comes from the association view or the caller and
is never guessed. ``refuse_weakening`` reads attribute 2 first.
"""

from __future__ import annotations

import pytest

from pydlms.client import DlmsClient
from pydlms.cosem.data import DlmsData
from pydlms.cosem.interface_classes import ClassId
from pydlms.exceptions import SecurityError, ServiceError
from pydlms.security.suites import (
    SecurityPolicyBits,
    SecurityPolicyV0,
    security_policy_value,
    security_policy_weakens,
)
from pydlms.simulator import example_meter, serve

SS = "0.0.43.0.0.255"
B = SecurityPolicyBits


@pytest.fixture
def meter():
    sim = example_meter()
    servers = []

    def start(version: int | None, policy: int = 0):
        if version is not None:
            sim.add_object(ClassId.SECURITY_SETUP, SS, {2: DlmsData.enum(policy)}, version=version)
        sim.activated = []

        def activate(meter, params):
            sim.activated.append(params)
            sim.objects[(ClassId.SECURITY_SETUP, _ss())][2] = params

        if version is not None:
            sim.add_method(ClassId.SECURITY_SETUP, SS, 1, activate)
        server = serve(sim)
        servers.append(server)
        host, port = server.server_address
        return DlmsClient.tcp(host, port, timeout=3)

    sim.start = start
    yield sim
    for server in servers:
        server.shutdown()
        server.server_close()


def _ss():
    from pydlms.obis import ObisCode

    return ObisCode.parse(SS)


@pytest.mark.parametrize(
    "version,policy,value",
    [
        (0, SecurityPolicyV0.NOTHING, 0),
        (0, SecurityPolicyV0.ALL_AUTHENTICATED, 1),
        (0, SecurityPolicyV0.ALL_ENCRYPTED, 2),
        (0, SecurityPolicyV0.ALL_AUTHENTICATED_ENCRYPTED, 3),
        (1, B.AUTHENTICATED_REQUEST | B.AUTHENTICATED_RESPONSE, 0x24),
        (1, B.ENCRYPTED_REQUEST | B.ENCRYPTED_RESPONSE, 0x48),
        (1, B.DIGITALLY_SIGNED_REQUEST | B.DIGITALLY_SIGNED_RESPONSE, 0x90),
        (1, 0xFC, 0xFC),
    ],
)
def test_policy_encoding(version, policy, value):
    assert security_policy_value(policy, version) == value


@pytest.mark.parametrize(
    "version,policy", [(0, 4), (0, -1), (1, 0x01), (1, 0x02), (1, 0x100), (2, 0)]
)
def test_policy_out_of_range_for_the_version(version, policy):
    with pytest.raises(ValueError):
        security_policy_value(policy, version)


@pytest.mark.parametrize(
    "version,current,new,weaker",
    [
        (0, 3, 3, False),
        (0, 1, 3, False),
        (0, 2, 3, False),
        (0, 1, 2, True),  # authenticated -> encrypted drops authentication
        (0, 3, 1, True),
        (0, 1, 0, True),
        (1, 0x24, 0x6C, False),
        (1, 0xFC, 0x7C, True),
        (1, 0x24, 0x48, True),
        (1, 0x00, 0x00, False),
    ],
)
def test_weakening(version, current, new, weaker):
    assert security_policy_weakens(current, new, version) is weaker


@pytest.mark.parametrize("version,policy,sent", [(0, 3, 3), (1, 0x6C, 0x6C)])
def test_version_from_the_association_view(meter, version, policy, sent):
    with meter.start(version) as m:
        m.security_activate(policy)
    assert any(bytes.fromhex("000F0000280000FF02") in r for r in meter.requests)
    assert meter.activated == [DlmsData.enum(sent)]


def test_explicit_version_skips_the_view(meter):
    with meter.start(1) as m:
        m.security_activate(B.AUTHENTICATED_REQUEST, version=1)
    object_list = bytes.fromhex("000F0000280000FF02")  # GET 15/0.0.40.0.0.255/2
    assert not any(object_list in r for r in meter.requests)
    assert meter.activated == [DlmsData.enum(0x04)]


def test_v1_bits_refused_on_a_v0_object(meter):
    with meter.start(0) as m:
        before = len(meter.requests)
        with pytest.raises(ValueError, match="version 0"):
            m.security_activate(0x24)
        # only the view was read; no ACTION went out
        assert not any(r[0] == 0xC3 for r in meter.requests[before:])
    assert meter.activated == []


def test_version_is_never_guessed(meter):
    with meter.start(None) as m:
        with pytest.raises(ServiceError, match="pass version="):
            m.security_activate(1)


def test_refuse_weakening(meter):
    with meter.start(1, policy=0xFC) as m:
        with pytest.raises(SecurityError, match="weaken"):
            m.security_activate(0x6C, refuse_weakening=True)
        assert meter.activated == []
        m.security_activate(0xFC, refuse_weakening=True)
        m.security_activate(0x24)  # without the guard the caller decides
    assert meter.activated == [DlmsData.enum(0xFC), DlmsData.enum(0x24)]
