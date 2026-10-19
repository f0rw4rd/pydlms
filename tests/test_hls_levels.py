"""Every authentication level, end to end against the simulator.

Level 0 (none), 1 (LLS), 2 (HLS manufacturer, AES convention), 3 (MD5),
4 (SHA-1), 5 (GMAC), 6 (SHA-256), 7 (ECDSA, suites 1 and 2); each over
Logical and Short Name referencing, with and without ciphering where the
mechanism allows it, and each with a negative case (wrong credential ->
association refused, meter that fails pass 4 -> association refused).
"""

from __future__ import annotations

import pytest

from pydlms.client import DlmsClient
from pydlms.exceptions import AssociationError
from pydlms.security.hls import Mechanism
from pydlms.simulator import ClientProfile, example_meter, serve

pytest.importorskip("cryptography")

from pydlms.security import ec  # noqa: E402
from pydlms.security.context import SecurityContext  # noqa: E402
from pydlms.security.suites import SecuritySuite  # noqa: E402

EK = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
AK = bytes.fromhex("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF")
CLIENT_TITLE = b"PYDCLNT1"
SECRET = b"0123456789ABCDEF"
P256 = SecuritySuite.ECDH_ECDSA_AES_GCM_128_SHA256
P384 = SecuritySuite.ECDH_ECDSA_AES_GCM_256_SHA384


@pytest.fixture
def sim():
    meter = example_meter(encryption_key=EK, authentication_key=AK)
    server = serve(meter)
    meter.address = server.server_address
    yield meter
    server.shutdown()
    server.server_close()


def _client(sim, **settings) -> DlmsClient:
    host, port = sim.address
    return DlmsClient.tcp(host, port, timeout=3, **settings)


# (mechanism, ciphered)
LEVELS = [
    (Mechanism.NONE, False),
    (Mechanism.NONE, True),
    (Mechanism.LLS, False),
    (Mechanism.LLS, True),
    (Mechanism.HLS, False),
    (Mechanism.HLS, True),
    (Mechanism.HLS_MD5, False),
    (Mechanism.HLS_SHA1, False),
    (Mechanism.HLS_SHA1, True),
    (Mechanism.HLS_GMAC, True),
    (Mechanism.HLS_SHA256, False),
    (Mechanism.HLS_SHA256, True),
]


def _settings(mechanism, ciphered):
    settings = {"mechanism": mechanism}
    if mechanism not in (Mechanism.NONE, Mechanism.HLS_GMAC):
        settings["password"] = SECRET
    if ciphered:
        settings["security"] = SecurityContext(EK, AK, client_system_title=CLIENT_TITLE)
    elif mechanism == Mechanism.HLS_SHA256:
        settings["client_system_title"] = CLIENT_TITLE
    return settings


@pytest.mark.parametrize("logical_names", [True, False], ids=["LN", "SN"])
@pytest.mark.parametrize(
    "mechanism,ciphered", LEVELS, ids=[f"{m.name}{'-ciphered' if c else ''}" for m, c in LEVELS]
)
def test_level_associates_and_reads(sim, mechanism, ciphered, logical_names):
    sim.clients[16] = ClientProfile(mechanism, SECRET, ciphered)
    with _client(sim, logical_names=logical_names, **_settings(mechanism, ciphered)) as meter:
        assert meter.get_register("1.0.1.8.0.255").value == 12345678
        assert meter.association.negotiated_conformance


@pytest.mark.parametrize(
    "mechanism,ciphered",
    [lc for lc in LEVELS if lc[0] not in (Mechanism.NONE, Mechanism.HLS_GMAC)],
    ids=lambda v: v.name if isinstance(v, Mechanism) else str(v),
)
def test_level_wrong_secret_refused(sim, mechanism, ciphered):
    sim.clients[16] = ClientProfile(mechanism, SECRET, ciphered)
    settings = _settings(mechanism, ciphered)
    settings["password"] = b"WRONG-SECRET-xyz"
    client = _client(sim, **settings)
    with pytest.raises(AssociationError):
        client.connect()
    client.link.disconnect()


def test_gmac_wrong_authentication_key_refused(sim):
    sim.clients[16] = ClientProfile(Mechanism.HLS_GMAC, ciphered=True)
    bad = SecurityContext(EK, bytes(16), client_system_title=CLIENT_TITLE)
    client = _client(sim, mechanism=Mechanism.HLS_GMAC, security=bad)
    with pytest.raises(AssociationError):
        client.connect()
    client.link.disconnect()


@pytest.mark.parametrize("suite", [P256, P384], ids=["P-256", "P-384"])
@pytest.mark.parametrize("ciphered", [False, True], ids=["plain", "ciphered"])
def test_ecdsa(sim, suite, ciphered):
    client_key = ec.generate_private_key(suite)
    server_key = ec.generate_private_key(suite)
    sim.signing_key = server_key
    sim.clients[16] = ClientProfile(
        Mechanism.HLS_ECDSA, ciphered=ciphered, client_public_key=client_key.public_key()
    )
    settings = {
        "mechanism": Mechanism.HLS_ECDSA,
        "signing_key": client_key,
        "server_public_key": server_key.public_key(),
    }
    if ciphered:
        settings["security"] = SecurityContext(EK, AK, client_system_title=CLIENT_TITLE)
    else:
        settings["client_system_title"] = CLIENT_TITLE
    with _client(sim, **settings) as meter:
        assert meter.get_register("1.0.32.7.0.255").value == pytest.approx(230.1)


def test_ecdsa_client_with_unknown_key_refused(sim):
    sim.signing_key = ec.generate_private_key(P256)
    sim.clients[16] = ClientProfile(
        Mechanism.HLS_ECDSA, client_public_key=ec.generate_private_key(P256).public_key()
    )
    client = _client(
        sim,
        mechanism=Mechanism.HLS_ECDSA,
        signing_key=ec.generate_private_key(P256),
        server_public_key=sim.signing_key.public_key(),
        client_system_title=CLIENT_TITLE,
    )
    with pytest.raises(AssociationError):
        client.connect()
    client.link.disconnect()


def test_ecdsa_impostor_meter_detected(sim):
    """Pass 4: a meter that cannot sign with the expected key is rejected."""
    client_key = ec.generate_private_key(P256)
    sim.signing_key = ec.generate_private_key(P256)  # not the key the client trusts
    sim.clients[16] = ClientProfile(Mechanism.HLS_ECDSA, client_public_key=client_key.public_key())
    client = _client(
        sim,
        mechanism=Mechanism.HLS_ECDSA,
        signing_key=client_key,
        server_public_key=ec.generate_private_key(P256).public_key(),
        client_system_title=CLIENT_TITLE,
    )
    with pytest.raises(AssociationError, match="not authentic"):
        client.connect()
    client.link.disconnect()


@pytest.mark.parametrize("mechanism", [Mechanism.HLS, Mechanism.HLS_MD5, Mechanism.HLS_SHA256])
def test_impostor_meter_detected_in_pass_4(sim, mechanism):
    """A meter that accepts pass 3 but answers with a wrong f(CtoS) is refused."""
    sim.clients[16] = ClientProfile(mechanism, SECRET)
    sim._hls_reply = _impostor(sim._hls_reply, mechanism)
    client = _client(sim, **_settings(mechanism, False))
    with pytest.raises(AssociationError, match="not authentic"):
        client.connect()
    client.link.disconnect()


def _impostor(original, mechanism):
    def reply(invoke_id, params, session):
        response = original(invoke_id, params, session)
        # Replace the server's f(CtoS) with zeros of the same length.
        from pydlms.apdu import xdlms
        from pydlms.cosem.data import DlmsData

        decoded = xdlms.decode_apdu(response)
        if decoded.return_data is not None:
            fake = bytes(len(decoded.return_data.data.value))
            decoded.return_data = xdlms.GetDataResult(data=DlmsData.octet_string(fake))
        return decoded.to_bytes()

    return reply


def test_manufacturer_function_is_pluggable(sim):
    def xor_fn(challenge, secret):
        return bytes(c ^ secret[i % len(secret)] for i, c in enumerate(challenge))

    sim.clients[16] = ClientProfile(Mechanism.HLS, SECRET, hls2_function=xor_fn)
    with _client(sim, mechanism=Mechanism.HLS, password=SECRET, hls2_function=xor_fn) as meter:
        assert meter.get_register("1.0.1.7.0.255").value == 1520


# --- challenge length by mechanism ------------------------------------------------------


def test_ecdsa_challenges_are_at_least_32_octets(sim):
    """IEC 62056-5-3:2023 Table 32 (as cited by cB-Sigma dlms checkStoC):
    8 to 64 octets, 32 to 64 for mechanism 7; go-dlms refuses less."""
    from pydlms.apdu.acse import AARE, AARQ

    suite = P256
    client_key, server_key = ec.generate_private_key(suite), ec.generate_private_key(suite)
    sim.signing_key = server_key
    sim.clients[16] = ClientProfile(
        Mechanism.HLS_ECDSA, ciphered=False, client_public_key=client_key.public_key()
    )
    client = _client(
        sim,
        mechanism=Mechanism.HLS_ECDSA,
        signing_key=client_key,
        server_public_key=server_key.public_key(),
        client_system_title=CLIENT_TITLE,
    )
    recorded: list[tuple[str, bytes]] = []
    original = client.association.link.request

    def request(apdu):
        answer = original(apdu)
        recorded.append(("tx", apdu))
        recorded.append(("rx", answer))
        return answer

    client.association.link.request = request
    with client as meter:
        assert meter.get_register("1.0.32.7.0.255").value == pytest.approx(230.1)
    aarq = AARQ.from_bytes(recorded[0][1])
    aare = AARE.from_bytes(recorded[1][1])
    assert len(aarq.calling_authentication_value) == 32
    assert len(aare.responding_authentication_value) == 32


def test_other_mechanisms_keep_16_octet_challenges(sim):
    from pydlms.security.hls import default_challenge_length

    assert default_challenge_length(Mechanism.HLS_GMAC) == 16
    assert default_challenge_length(Mechanism.HLS_ECDSA) == 32


def test_too_short_ecdsa_challenge_is_refused():
    from pydlms.association import Association, AssociationSettings
    from tests.test_association import ScriptedLink

    settings = AssociationSettings(
        mechanism=Mechanism.HLS_ECDSA, challenge_length=16, client_system_title=CLIENT_TITLE
    )
    with pytest.raises(ValueError, match="32"):
        Association(ScriptedLink([]), settings).associate()
