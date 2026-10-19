"""Broadcast-key APDUs from ``Association.send_broadcast`` against the
go-dlms and Gurux.DLMS.Net ``decrypt`` oracles.

No published vector uses the global broadcast key, so two independent
libraries stand in for one: each is given the broadcast key as ``ek``
(PROTOCOL.md: the encryption key doubles as the broadcast key) and must
recover the plaintext of a glo- and a general-glo broadcast in all three
policies, and must refuse the same APDU given the unicast key or with a
tampered tag. Images: ``docker build -t pydlms-interop-go-dlms
tests/interop/go-dlms`` and ``docker build -t pydlms-interop-gurux-net
tests/interop/gurux-net``.
"""

from __future__ import annotations

import pytest

pytest.importorskip("cryptography")

from pydlms.apdu.acse import AARE, ApplicationContext  # noqa: E402
from pydlms.association import Association, AssociationSettings  # noqa: E402
from pydlms.security.ciphering import wrap  # noqa: E402
from pydlms.security.context import SecurityContext  # noqa: E402
from pydlms.security.suites import SecurityPolicy  # noqa: E402
from tests.interop.model import op_decrypt_bytes  # noqa: E402
from tests.interop.oracle import Oracle, require_image  # noqa: E402
from tests.test_association import INITIATE_RESPONSE, ScriptedLink  # noqa: E402

pytestmark = pytest.mark.integration

EK = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
AK = bytes.fromhex("d0d1d2d3d4d5d6d7d8d9dadbdcdddedf")
BK = bytes.fromhex("e1e2e3e4e5e6e7e8e9eaebecedeeeff0")
CLIENT = bytes.fromhex("4d4d4d0000000001")
SERVER = bytes.fromhex("4d4d4d0000bc614e")
UNCONFIRMED_SET = bytes.fromhex("c1018100010000600100ff0200090141")
UNCONFIRMED_ACTION = bytes.fromhex("c30101004600006003 00ff010100".replace(" ", ""))

IMAGES = ["pydlms-interop-go-dlms", "pydlms-interop-gurux-net"]


class _Link(ScriptedLink):
    def send_unconfirmed(self, apdu: bytes, broadcast: bool = False) -> None:
        assert broadcast
        self.sent.append(apdu)


def _broadcast(plain: bytes, protection: str, policy: SecurityPolicy) -> bytes:
    srv = SecurityContext(EK, AK, client_system_title=SERVER, policy=policy)
    aare = AARE(
        ApplicationContext.LN_CIPHERED,
        0,
        responding_ap_title=SERVER,
        user_information=wrap(srv, INITIATE_RESPONSE),
    ).to_bytes()
    link = _Link([aare])
    ctx = SecurityContext(EK, AK, CLIENT, broadcast_key=BK, policy=policy, invocation_counter=7)
    assoc = Association(link, AssociationSettings(security=ctx, protection=protection))
    assoc.associate()
    assoc.send_broadcast(plain)
    return link.sent[-1]


CASES = [
    (protection, policy, plain)
    for protection in ("glo", "general-glo")
    for policy in (
        SecurityPolicy.AUTHENTICATED_ENCRYPTED,
        SecurityPolicy.AUTHENTICATED,
        SecurityPolicy.ENCRYPTED,
    )
    for plain in (UNCONFIRMED_SET, UNCONFIRMED_ACTION)
]


@pytest.fixture(scope="module", params=IMAGES)
def oracle(request):
    require_image(request.param)
    o = Oracle(request.param)
    yield o
    o.close()


def _decrypt(oracle, key: bytes, apdu: bytes) -> dict:
    return oracle.ask(f"decrypt {key.hex()} {AK.hex()} {CLIENT.hex()} {apdu.hex()}")


def _expected(oracle, policy: SecurityPolicy, plain: bytes) -> bytes:
    """The plaintext the oracle returns. Gurux.DLMS.Net 6f26301 drops the
    last 12 octets of an encryption-only broadcast (SC 0x60): GXGMac.Decrypt
    strips a tag when ``(sc & 0xF0) != 0x20`` but checks one only when
    ``(sc & 0x30) != 0x20`` (GXGMac.cs:287,294). A Gurux bug, not a pydlms
    one: go-dlms and
    pydlms recover the whole APDU."""
    if oracle.image.endswith("gurux-net") and policy == SecurityPolicy.ENCRYPTED:
        return plain[:-12]
    return plain


@pytest.mark.parametrize("protection,policy,plain", CASES)
def test_oracle_recovers_the_plaintext_with_the_broadcast_key(oracle, protection, policy, plain):
    apdu = _broadcast(plain, protection, policy)
    assert apdu[2 if protection == "glo" else 11] & 0x40  # SC names the broadcast key
    reply = _decrypt(oracle, BK, apdu)
    # pydlms's own side of the protocol (model.py) opens it too.
    assert op_decrypt_bytes(BK.hex(), AK.hex(), CLIENT.hex(), apdu) == plain
    want = _expected(oracle, policy, plain)
    assert reply == {"ok": True, "result": {"plaintext": want.hex()}}


@pytest.mark.parametrize("protection", ["glo", "general-glo"])
def test_oracle_refuses_the_unicast_key_and_a_tampered_tag(oracle, protection):
    apdu = _broadcast(UNCONFIRMED_SET, protection, SecurityPolicy.AUTHENTICATED_ENCRYPTED)
    assert not _decrypt(oracle, EK, apdu)["ok"]
    tampered = apdu[:-1] + bytes([apdu[-1] ^ 0x01])
    assert not _decrypt(oracle, BK, tampered)["ok"]
