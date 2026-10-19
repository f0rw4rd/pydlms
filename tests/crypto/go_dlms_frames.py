"""general-ciphering and general-signing APDUs produced by cB-Sigma dlms.

Provenance: the ``pydlms-interop-go-dlms`` image built from
``tests/interop/go-dlms/Dockerfile`` (github.com/cB-Sigma/dlms, Apache-2.0,
commit ``26360a13e5d8f1da0fba1758118adaaa00be2ccf``, tag v0.3.0; the build
checks the commit), run as ``server``. A pydlms client using the opt-in
(``general_aad=WITH_HEADER`` resp. ``signing_form=LENGTH_PREFIXED_CONTENT``)
associated and read ``1.0.1.8.0.255`` attribute 2 (12345678); the inbound
APDUs were recorded verbatim on 2026-10-16. Keys and titles are the
adapter's fixed test material (``tests/interop/go-dlms/adapter/main.go``,
mirrored in ``tests/interop/test_go_dlms.py``).

* ``GC_*``: client SAP 1, HLS-GMAC, suite 0, ``protection="general-ciphering"``
  with the identified global unicast key. The server answers in
  general-ciphering (key-info identified unicast, SC 0x30) with an empty
  transaction-id and a 12-octet date-time in the header it authenticates.
  ``GC_PASS3`` is the reply to HLS pass 3 (IC 3), ``GC_GET`` the GET
  response (IC 4).
* ``SIGN_*``: client SAP 3, HLS-ECDSA, suite 1, ``protection="glo+signing"``.
  The server signs (ECDSA P-256 with ``server-sign-1``) a glo-ciphered
  response, SC 0x31: ``SIGN_PASS3`` (glo-action-response, IC 7) and
  ``SIGN_GET`` (glo-get-response, IC 8).

These are interop evidence for the alternative forms, not known answers:
no standard example exists for either.
"""

from __future__ import annotations

import hashlib

ORACLE_COMMIT = "26360a13e5d8f1da0fba1758118adaaa00be2ccf"
EK = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
AK = bytes.fromhex("d0d1d2d3d4d5d6d7d8d9dadbdcdddedf")
CLIENT_TITLE = b"PYDLMS01"
SERVER_TITLE = b"GODLMS01"
#: Plain GET response payload: Data double-long-unsigned 12345678.
VALUE = bytes.fromhex("0600BC614E")

GC_PASS3 = bytes.fromhex(
    "DD0008474F444C4D533031085059444C4D5330310C07EA0A1005122114080000"
    "00000100002A30000000039A16968D064330E069ACF5174A54BB1D6F22D4DB61"
    "9D31D3B3E36B5B4DC05107374DECCB58"
)
GC_GET = bytes.fromhex(
    "DD0008474F444C4D533031085059444C4D5330310C07EA0A1005122114080000"
    "00000100001A3000000004DA8398D1F5FA22D82D4598EA7E3E44D38734E154FB"
)
SIGN_PASS3 = bytes.fromhex(
    "DF0008474F444C4D533031085059444C4D5330310C07EA0A1005122114090000"
    "00005BCF5931000000075A8BC19C320E25B4EE314EE2D819E0FB054649AD6D4C"
    "C0B4770D5DCC28AA73EFA9E1D72A3083E776A752F629F58162D29DB28CB68AE9"
    "A8BBD0B760B3CE2D2D95F5370542583A5961D648AE9ED80532C20B1B94254034"
    "8462E7FE35963E6A71115A50CE320630A11676F3844E6D679AFF45341D1D09FC"
    "5361F5E166CE513B5B2D385DD2C7F01B62F23872AEB38E86DB3B9F02CB40B0"
)
SIGN_GET = bytes.fromhex(
    "DF0008474F444C4D533031085059444C4D5330310C07EA0A1005122114090000"
    "00001CCC1A3100000008E5CB8D3DCC6B09574EA9BEA38A52035E01B11DE8C840"
    "11C54476B05326E9DD53C30E644DE1B614CAE8038364A539425C913A9FC016C1"
    "8C02D2122A26C70EA57E9CC44FFC8E58A05B80C491BD3D41B85D31A5B28077F2"
)

_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def server_signing_public_key():
    """The adapter's ``server-sign-1`` key: d = SHA-256(label) mod (n - 1) + 1."""
    from cryptography.hazmat.primitives.asymmetric import ec

    d = int.from_bytes(hashlib.sha256(b"server-sign-1").digest(), "big") % (_P256_ORDER - 1) + 1
    return ec.derive_private_key(d, ec.SECP256R1()).public_key()
