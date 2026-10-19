"""Known-answer tests for the raw primitives we wrap.

These validate our IV/AAD/encoding choices around ``cryptography``:

* GCM: McGrew & Viega GCM spec test case 4 (96-bit IV), tag truncated to 12
  octets as DLMS does.
* ECDSA P-256: RFC 6979 A.2.5, message "sample", SHA-256 (verify of a known
  r||s; signing is randomized so it is round-trip tested).
* ECDSA P-384: RFC 6979 A.2.6, message "sample", SHA-384.
* ECDH P-256 / P-384: RFC 5903 sections 8.1 and 8.2.

Vectors are copied byte-exact from https://www.rfc-editor.org/rfc/rfc6979.txt
and https://www.rfc-editor.org/rfc/rfc5903.txt.

AES key wrap (RFC 3394) lives in ``test_keywrap.py``.
"""

from __future__ import annotations

import hashlib

import pytest

from pydlms.exceptions import AuthenticationError
from pydlms.security import ec, gcm
from pydlms.security.suites import SecuritySuite

GCM_K = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
GCM_IV = bytes.fromhex("cafebabefacedbaddecaf888")
GCM_P = bytes.fromhex(
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
)
GCM_A = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
GCM_C = bytes.fromhex(
    "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
    "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"
)
GCM_T = bytes.fromhex("5bc94fbc3221a5db94fae95ae7121a47")

P256 = SecuritySuite.ECDH_ECDSA_AES_GCM_128_SHA256
P384 = SecuritySuite.ECDH_ECDSA_AES_GCM_256_SHA384


def test_gcm_test_case_4():
    c, t = gcm.gcm_encrypt(GCM_K, GCM_IV, GCM_P, GCM_A)
    assert c == GCM_C
    assert t == GCM_T[:12]
    assert gcm.gcm_decrypt(GCM_K, GCM_IV, c, GCM_A, t) == GCM_P


def test_gcm_full_length_tag_rejected():
    with pytest.raises(AuthenticationError):
        gcm.gcm_decrypt(GCM_K, GCM_IV, GCM_C, GCM_A, GCM_T)


def test_gcm_bad_key_length():
    with pytest.raises(ValueError):
        gcm.gcm_encrypt(b"short", GCM_IV, b"", b"")


def test_iv_inputs_checked():
    with pytest.raises(ValueError):
        gcm.make_iv(bytes(7), 1)
    with pytest.raises(ValueError):
        gcm.make_iv(bytes(8), 1 << 32)


def _p256_private(hex_scalar):
    from cryptography.hazmat.primitives.asymmetric import ec as cec

    return cec.derive_private_key(int(hex_scalar, 16), cec.SECP256R1())


RFC6979_X = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"
RFC6979_PUB = bytes.fromhex(
    "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"
    "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"
)
RFC6979_SIG = bytes.fromhex(
    "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"
    "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"
)


def test_ecdsa_p256_rfc6979_verify():
    key = _p256_private(RFC6979_X)
    assert ec.public_key_bytes(key) == RFC6979_PUB
    public = ec.load_public_key(P256, RFC6979_PUB)
    ec.ecdsa_verify(public, b"sample", RFC6979_SIG)


@pytest.mark.parametrize("position", range(64))
def test_ecdsa_tampered_signature_rejected(position):
    public = ec.load_public_key(P256, RFC6979_PUB)
    sig = bytearray(RFC6979_SIG)
    sig[position] ^= 0x01
    with pytest.raises(AuthenticationError):
        ec.ecdsa_verify(public, b"sample", bytes(sig))


def test_ecdsa_wrong_message_and_length():
    public = ec.load_public_key(P256, RFC6979_PUB)
    with pytest.raises(AuthenticationError):
        ec.ecdsa_verify(public, b"Sample", RFC6979_SIG)
    with pytest.raises(AuthenticationError):
        ec.ecdsa_verify(public, b"sample", RFC6979_SIG[:-1])


@pytest.mark.parametrize("suite,size", [(P256, 64), (P384, 96)])
def test_ecdsa_round_trip_raw_encoding(suite, size):
    key = ec.generate_private_key(suite)
    sig = ec.ecdsa_sign(key, b"message")
    assert len(sig) == size
    public = ec.load_public_key(suite, ec.public_key_bytes(key))
    ec.ecdsa_verify(public, b"message", sig)


def test_ecdh_p256_rfc5903():
    i = _p256_private("C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433")
    r = _p256_private("C6EF9C5D78AE012A011164ACB397CE2088685D8F06BF9BE0B283AB46476BEE53")
    assert ec.public_key_bytes(r) == bytes.fromhex(
        "D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63"
        "56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB"
    )
    z = bytes.fromhex("D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE")
    assert ec.ecdh_shared_secret(i, r.public_key()) == z
    assert ec.ecdh_shared_secret(r, i.public_key()) == z


def test_ecdh_p384_agreement_symmetry():
    a = ec.generate_private_key(P384)
    b = ec.generate_private_key(P384)
    assert ec.ecdh_shared_secret(a, b.public_key()) == ec.ecdh_shared_secret(b, a.public_key())


def test_kdf_matches_sp800_56a_definition():
    z = bytes(range(32))
    u, v = b"CLIENT01", b"SERVER01"
    expected = hashlib.sha256(
        b"\x00\x00\x00\x01" + z + bytes.fromhex("60857405080300") + u + v
    ).digest()[:16]
    assert ec.kdf(P256, z, u, v) == expected
    k256 = ec.kdf(P384, z, u, v)
    assert (
        k256
        == hashlib.sha384(
            b"\x00\x00\x00\x01" + z + bytes.fromhex("60857405080301") + u + v
        ).digest()[:32]
    )
    with pytest.raises(ValueError):
        ec.kdf(SecuritySuite.AES_GCM_128, z, u, v)


def _p384_private(hex_scalar):
    from cryptography.hazmat.primitives.asymmetric import ec as cec

    return cec.derive_private_key(int(hex_scalar, 16), cec.SECP384R1())


# RFC 6979 appendix A.2.6 (ECDSA, 384 bits, NIST P-384): private key x,
# public key Ux || Uy, and the SHA-384 signature r || s of message "sample".
RFC6979_P384_X = (
    "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D8"
    "96D5724E4C70A825F872C9EA60D2EDF5"
)
RFC6979_P384_PUB = bytes.fromhex(
    "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64"
    "DEF8F0EA9055866064A254515480BC13"
    "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1"
    "288B231C3AE0D4FE7344FD2533264720"
)
RFC6979_P384_SIG = bytes.fromhex(
    "94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C"
    "81A648152E44ACF96E36DD1E80FABE46"
    "99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94F"
    "A329C145786E679E7B82C71A38628AC8"
)


def test_ecdsa_p384_rfc6979_verify():
    key = _p384_private(RFC6979_P384_X)
    assert ec.public_key_bytes(key) == RFC6979_P384_PUB
    public = ec.load_public_key(P384, RFC6979_P384_PUB)
    ec.ecdsa_verify(public, b"sample", RFC6979_P384_SIG)


@pytest.mark.parametrize("position", range(96))
def test_ecdsa_p384_tampered_signature_rejected(position):
    public = ec.load_public_key(P384, RFC6979_P384_PUB)
    sig = bytearray(RFC6979_P384_SIG)
    sig[position] ^= 0x01
    with pytest.raises(AuthenticationError):
        ec.ecdsa_verify(public, b"sample", bytes(sig))


def test_ecdsa_p384_wrong_message_rejected():
    public = ec.load_public_key(P384, RFC6979_P384_PUB)
    with pytest.raises(AuthenticationError):
        ec.ecdsa_verify(public, b"Sample", RFC6979_P384_SIG)


def test_ecdh_p384_rfc5903():
    # RFC 5903 section 8.2 (384-bit random ECP group): private keys i and r,
    # responder public key grx || gry, and the shared secret girx. RFC 5903
    # defines the shared secret as the x-coordinate only, which is also what
    # ecdh_shared_secret returns (SP 800-56A Z for ECC CDH).
    i = _p384_private(
        "099F3C7034D4A2C699884D73A375A67F7624EF7C6B3C0F160647B67414DCE655"
        "E35B538041E649EE3FAEF896783AB194"
    )
    r = _p384_private(
        "41CB0779B4BDB85D47846725FBEC3C9430FAB46CC8DC5060855CC9BDA0AA2942"
        "E0308312916B8ED2960E4BD55A7448FC"
    )
    assert ec.public_key_bytes(i) == bytes.fromhex(
        "667842D7D180AC2CDE6F74F37551F55755C7645C20EF73E31634FE72B4C55EE6"
        "DE3AC808ACB4BDB4C88732AEE95F41AA"
        "9482ED1FC0EEB9CAFC4984625CCFC23F65032149E0E144ADA024181535A0F38E"
        "EB9FCFF3C2C947DAE69B4C634573A81C"
    )
    r_pub = bytes.fromhex(
        "E558DBEF53EECDE3D3FCCFC1AEA08A89A987475D12FD950D83CFA41732BC509D"
        "0D1AC43A0336DEF96FDA41D0774A3571"
        "DCFBEC7AACF3196472169E838430367F66EEBE3C6E70C416DD5F0C68759DD1FF"
        "F83FA40142209DFF5EAAD96DB9E6386C"
    )
    assert ec.public_key_bytes(r) == r_pub
    z = bytes.fromhex(
        "11187331C279962D93D604243FD592CB9D0A926F422E47187521287E7156C5C4"
        "D603135569B9E9D09CF5D4A270F59746"
    )
    assert len(z) == 48
    assert ec.ecdh_shared_secret(i, ec.load_public_key(P384, r_pub)) == z
    assert ec.ecdh_shared_secret(r, i.public_key()) == z


def test_load_public_key_length_checked():
    with pytest.raises(ValueError):
        ec.load_public_key(P256, bytes(63))
    with pytest.raises(ValueError):
        ec.curve_for_suite(0)
