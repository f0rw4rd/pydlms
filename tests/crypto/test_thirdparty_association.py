"""Third-party layers in an association (``AssociationSettings.third_party``).

End to end against the simulator, whose service handler is wrapped by the
meter side of :mod:`tests.crypto.thirdparty_meter`: the client protects
the TP's layers with its own general-glo / general-ciphering, the meter
answers with its layers for the TP inside its own. Known answers: none
(see ``test_thirdparty.py``); the cB-Sigma meter is the interop check.
"""

from __future__ import annotations

import pytest

from pydlms.apdu.tags import Tag
from pydlms.association import Association, AssociationSettings
from pydlms.client import DlmsClient
from pydlms.exceptions import AuthenticationError, DlmsError
from pydlms.security.context import SecurityContext
from pydlms.security.general import STATIC_UNIFIED_MODEL
from pydlms.security.suites import SecurityPolicy, SecuritySuite
from pydlms.simulator import ClientProfile, example_meter, serve
from tests.crypto.test_thirdparty import AK16, EK16, TP, key, third_party
from tests.crypto.thirdparty_meter import TpMeter
from tests.test_association import ScriptedLink

CLIENT = b"PYDCLNT1"
AE = SecurityPolicy.AUTHENTICATED_ENCRYPTED


class _Meter:
    """The simulator with a meter-side third party handler around its services."""

    def __init__(self, sign_answers: bool = True, answer_tp: bool = True) -> None:
        from pydlms.security.hls import Mechanism

        sim = example_meter(encryption_key=EK16, authentication_key=AK16)
        sim.clients[16] = ClientProfile(Mechanism.NONE, ciphered=True)
        sim.security.suite = SecuritySuite(1)
        self.sim = sim
        self.tp = TpMeter(
            suite=1,
            meter_title=sim.system_title,
            tp_title=TP,
            meter_sign=key("meter-sign", 1),
            meter_ka=key("meter-ka", 1),
            tp_sign_pub=key("tp-sign", 1).public_key(),
            tp_ka_pub=key("tp-ka", 1).public_key(),
            ak=AK16,
            sign_answers=sign_answers,
        )
        self.opened: list = []
        service = sim._service

        def wrapped(plain, session):
            if plain and plain[0] in (Tag.GENERAL_CIPHERING, Tag.GENERAL_SIGNING):
                inner, tx = self.tp.open(plain)
                self.opened.append(tx)
                response = service(inner, session)
                if response is None or not answer_tp:
                    return response
                return self.tp.answer(tx, response)
            return service(plain, session)

        sim._service = wrapped
        self.server = serve(sim)

    def client(self, tp, protection: str, **kw) -> DlmsClient:
        security = SecurityContext(
            EK16,
            AK16,
            client_system_title=CLIENT,
            suite=1,
            peer_signing_key=key("meter-sign", 1).public_key(),
            peer_key_agreement_key=key("meter-ka", 1).public_key(),
            **kw,
        )
        host, port = self.server.server_address
        return DlmsClient.tcp(
            host, port, timeout=3, security=security, protection=protection, third_party=tp
        )

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def meter_factory():
    meters = []

    def make(**kw) -> _Meter:
        m = _Meter(**kw)
        meters.append(m)
        return m

    yield make
    for m in meters:
        m.close()


@pytest.mark.parametrize("protection", ["general-glo", "general-ciphering"])
@pytest.mark.parametrize(
    "tp_kw",
    [
        {},
        {"policy": AE},
        {"sign": False, "policy": AE, "key_agreement": STATIC_UNIFIED_MODEL},
    ],
    ids=["sign", "sign+cipher-one-pass", "cipher-static"],
)
def test_reads_through_third_party_layers(meter_factory, protection, tp_kw):
    m = meter_factory()
    tp = third_party(1, **tp_kw)
    with m.client(tp, protection) as client:
        assert client.get("0.0.42.0.0.255").value == b"PYD1000000000001"
        assert client.get("0.0.96.1.0.255").value == "PYD0000000001"
    assert len(m.opened) >= 2
    assert all(tx.signed == tp.sign and tx.policy == int(tp.policy) for tx in m.opened)


def test_unprotected_answer_needs_the_opt_in(meter_factory):
    m = meter_factory(sign_answers=False)
    strict = third_party(1, signed_responses=False)
    client = m.client(strict, "general-glo")
    with pytest.raises(AuthenticationError, match="J.3"):
        client.connect()
        client.get("0.0.42.0.0.255")
    client.link.disconnect()
    loose = third_party(1, signed_responses=False, accept_unprotected_responses=True)
    with m.client(loose, "general-glo", invocation_counter=100) as client:
        assert client.get("0.0.42.0.0.255").value == b"PYD1000000000001"


def test_reply_without_the_third_party_layer_is_refused(meter_factory):
    m = meter_factory(answer_tp=False)
    client = m.client(third_party(1), "general-glo")
    with pytest.raises(AuthenticationError, match="no layer for the third party"):
        client.connect()
        client.get("0.0.42.0.0.255")
    client.link.disconnect()


def test_unsigned_reply_when_signing_is_required_is_refused(meter_factory):
    m = meter_factory(sign_answers=False)
    client = m.client(third_party(1, policy=AE), "general-ciphering")
    with pytest.raises(AuthenticationError, match="did not sign"):
        client.connect()
        client.get("0.0.42.0.0.255")
    client.link.disconnect()


def _settings(**kw) -> AssociationSettings:
    security = kw.pop("security", None) or SecurityContext(
        EK16, AK16, client_system_title=CLIENT, suite=1, server_system_title=b"METER001"
    )
    return AssociationSettings(security=security, third_party=third_party(1), **kw)


@pytest.mark.parametrize("protection", ["glo", "glo+signing", "general-signing"])
def test_protections_that_cannot_carry_the_layers_are_refused(protection):
    with pytest.raises(ValueError, match="third party layers need protection"):
        Association(ScriptedLink([]), _settings(protection=protection))


def test_suite_0_or_no_security_is_refused():
    suite0 = SecurityContext(EK16, AK16, client_system_title=CLIENT)
    with pytest.raises(ValueError, match="suite 1 or 2"):
        Association(ScriptedLink([]), _settings(security=suite0, protection="general-glo"))
    with pytest.raises(ValueError, match="suite 1 or 2"):
        Association(ScriptedLink([]), AssociationSettings(third_party=third_party(1)))
    with pytest.raises(TypeError):
        Association(
            ScriptedLink([]),
            AssociationSettings(
                security=SecurityContext(EK16, AK16, suite=1),
                protection="general-glo",
                third_party=object(),
            ),
        )


def test_overhead_counts_the_third_party_layers():
    plain = Association(
        ScriptedLink([]),
        AssociationSettings(
            security=SecurityContext(EK16, AK16, client_system_title=CLIENT, suite=1),
            protection="general-glo",
        ),
    )
    signed = Association(ScriptedLink([]), _settings(protection="general-glo"))
    both = Association(
        ScriptedLink([]),
        AssociationSettings(
            security=SecurityContext(EK16, AK16, client_system_title=CLIENT, suite=1),
            protection="general-glo",
            third_party=third_party(1, policy=AE),
        ),
    )
    assert plain.protection_overhead() < signed.protection_overhead() < both.protection_overhead()


def test_no_layers_without_the_setting(meter_factory):
    """Default: nothing changes (the meter sees no third-party layer)."""
    m = meter_factory()
    host, port = m.server.server_address
    security = SecurityContext(EK16, AK16, client_system_title=CLIENT, suite=1)
    with DlmsClient.tcp(host, port, timeout=3, security=security, protection="general-glo") as c:
        assert c.get("0.0.42.0.0.255").value == b"PYD1000000000001"
    assert m.opened == []


def test_tampered_reply_fails(meter_factory):
    """A flipped octet anywhere in the protected reply fails, never yields data."""
    m = meter_factory()
    answers = []
    handle = m.sim.handle_all

    def tamper(apdu, session):
        out = handle(apdu, session)
        if apdu and apdu[0] == Tag.GENERAL_GLO_CIPHERING and len(answers) == 0:
            answers.append(out[0])
            raw = bytearray(out[0])
            raw[len(raw) // 2] ^= 0x01
            return [bytes(raw)]
        return out

    m.sim.handle_all = tamper
    client = m.client(third_party(1), "general-glo")
    with pytest.raises(DlmsError):
        client.connect()
        client.get("0.0.42.0.0.255")
    client.link.disconnect()
