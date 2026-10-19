"""Inbound general-ciphering / general-signing against APDUs that the Gurux
client library builds with fresh keys on every run, and suite 1/2 ECDH + KDF
against Gurux's own functions.

Image: ``docker build -t pydlms-gurux-client tests/integration/gurux_client``
(the Dockerfile lists the Gurux defects patched for this). The frozen,
offline variant of this check is ``tests/crypto/test_gurux_general_frames.py``.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from pydlms.exceptions import AuthenticationError
from pydlms.security.ciphering import unwrap
from pydlms.security.context import SecurityContext

pytestmark = pytest.mark.integration
IMAGE = "pydlms-gurux-client"
# Per suite, as hardcoded in the harness (Program.cs).
EK = {
    1: bytes.fromhex("000102030405060708090A0B0C0D0E0F"),
    2: bytes.fromhex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
}
AK = {
    1: bytes.fromhex("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF"),
    2: bytes.fromhex("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEF"),
}
PLAINTEXT = bytes.fromhex("c001c1000100002a0000ff0200")  # GET 0.0.42.0.0.255 attr 2


@pytest.fixture(scope="module")
def image():
    pytest.importorskip("cryptography")
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    try:
        subprocess.run(  # noqa: S603,S607 - fixed argv, test-only
            ["docker", "image", "inspect", IMAGE], check=True, capture_output=True
        )
    except subprocess.CalledProcessError:
        pytest.skip(
            f"image {IMAGE} missing: docker build -t {IMAGE} tests/integration/gurux_client"
        )
    return IMAGE


@pytest.mark.parametrize("suite", [1, 2])
@pytest.mark.parametrize("mode", ["general-ciphering", "general-signing", "static-unified"])
def test_pydlms_unwraps_gurux_apdu(image, mode, suite):
    import os

    from pydlms.security import ec

    def hex_priv(key) -> str:
        size = 32 if suite == 1 else 48
        return key.private_numbers().private_value.to_bytes(size, "big").hex()

    gurux_signing = ec.generate_private_key(suite)
    gurux_ka = ec.generate_private_key(suite)
    recipient_ka = ec.generate_private_key(suite)
    recipient_signing = ec.generate_private_key(suite)
    argv = [
        "docker",
        "run",
        "--rm",
        image,
        mode,
        hex_priv(gurux_signing),
        ec.public_key_bytes(recipient_ka).hex(),
        ec.public_key_bytes(recipient_signing).hex(),
    ]
    if mode == "static-unified":
        argv += [hex_priv(gurux_ka), os.urandom(8).hex()]
    out = subprocess.run(  # noqa: S603 - fixed argv, test-only
        argv, check=True, capture_output=True, text=True, timeout=120
    )
    frame = bytes.fromhex(out.stdout.split()[0])
    assert frame[:2] == b"\x00\x01"  # wrapper version
    apdu = frame[8:]
    assert apdu[0] == (0xDF if mode == "general-signing" else 0xDD)

    def ctx(peer_signing_key, peer_key_agreement_key):
        return SecurityContext(
            EK[suite],
            AK[suite],
            client_system_title=bytes.fromhex("4752580000000001"),
            server_system_title=b"GXClient",
            suite=suite,
            key_agreement_key=recipient_ka,
            peer_signing_key=peer_signing_key,
            peer_key_agreement_key=peer_key_agreement_key,
        )

    result = unwrap(ctx(gurux_signing.public_key(), gurux_ka.public_key()), apdu)
    assert result.authenticated
    assert result.security_control.suite == suite
    assert result.plaintext == PLAINTEXT
    # A wrong peer key (signing key, or the static agreement key) must fail.
    wrong = recipient_signing.public_key()
    with pytest.raises(AuthenticationError):
        if mode == "static-unified":
            unwrap(ctx(gurux_signing.public_key(), wrong), apdu)
        else:
            unwrap(ctx(wrong, gurux_ka.public_key()), apdu)


@pytest.mark.parametrize("suite", [1, 2])
def test_ecdh_and_kdf_match_gurux(image, suite):
    import os

    from pydlms.security import ec

    own = ec.generate_private_key(suite)
    peer = ec.generate_private_key(suite)
    party_u, party_v = os.urandom(8), os.urandom(8)
    size = 32 if suite == 1 else 48
    out = subprocess.run(  # noqa: S603,S607 - fixed argv, test-only
        [
            "docker",
            "run",
            "--rm",
            image,
            "kdf",
            own.private_numbers().private_value.to_bytes(size, "big").hex(),
            ec.public_key_bytes(peer).hex(),
            party_u.hex(),
            party_v.hex(),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    gurux_z, gurux_kdf = (bytes.fromhex(x) for x in out.stdout.split())
    z = ec.ecdh_shared_secret(own, peer.public_key())
    assert z == gurux_z
    key = ec.kdf(suite, z, party_u, party_v)
    assert key == gurux_kdf[: len(key)]
