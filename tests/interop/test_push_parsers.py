"""Push parsers and Wireshark's dissector as interop oracles.

* esphome-libs/dlms_parser v2.2.0 (C++, Apache-2.0): a push parser that
  emits OBIS -> value captures, not a data tree. Its ``push`` / ``frame``
  answer (tests/interop/push-parsers/esphome/adapter.cpp) is compared with
  pydlms's :class:`~pydlms.push.PushDecoder` records mapped to the same
  shape (:func:`pydlms_captures`), plus the A-XDR payload both libraries
  find after deciphering and the DataNotification header.
* Wireshark 4.6 ``packet-cosem.c`` via tshark: speaks the plain protocol
  (``data``, ``apdu``), so ``tests.interop.compare`` runs it unchanged.

Build:
  docker build -t pydlms-interop-esphome tests/interop/push-parsers/esphome
  docker build -t pydlms-tshark tests/integration/tshark
  docker build -t pydlms-interop-wireshark tests/interop/push-parsers/wireshark
Run:
  pytest -m integration tests/interop/test_push_parsers.py
  python -m tests.interop.test_push_parsers [--json build/interop-esphome.json]
  python -m tests.interop.compare pydlms-interop-wireshark --json build/interop-wireshark.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter

import pytest

from pydlms.apdu.tags import Tag
from pydlms.cosem.data import DlmsData, encode_data
from pydlms.cosem.enums import DataType
from pydlms.exceptions import DlmsError
from pydlms.push import PushDecoder
from tests.interop import compare, corpus
from tests.interop.model import TYPE_NAMES
from tests.interop.oracle import Oracle, require_image

pytestmark = pytest.mark.integration

ESPHOME = "pydlms-interop-esphome"
WIRESHARK = "pydlms-interop-wireshark"

# --- pydlms's side of the esphome comparison ------------------------------------------------

_FIXED = {
    DataType.BOOLEAN: 1,
    DataType.INTEGER: 1,
    DataType.UNSIGNED: 1,
    DataType.ENUM: 1,
    DataType.BCD: 1,
    DataType.LONG: 2,
    DataType.LONG_UNSIGNED: 2,
    DataType.DOUBLE_LONG: 4,
    DataType.DOUBLE_LONG_UNSIGNED: 4,
    DataType.FLOAT32: 4,
    DataType.LONG64: 8,
    DataType.LONG64_UNSIGNED: 8,
    DataType.FLOAT64: 8,
    DataType.DATE_TIME: 12,
    DataType.DATE: 5,
    DataType.TIME: 4,
    DataType.NULL: 0,
}


def content(item: DlmsData) -> bytes:
    """The value octets after the A-XDR tag (and length), as dlms_parser reports them."""
    raw = encode_data(item)
    if item.tag in _FIXED:
        return raw[1:]
    pos = 1
    first = raw[pos]
    pos += 1 + (first & 0x7F if first & 0x80 else 0)
    return raw[pos:]


#: SC suite id of captures that do not use suite 0, as a user configures the
#: meter (same table as tests/meters/test_meter_dumps.py SUITES).
SUITES = {"mbus_kaifa_ma309m": 1}


def _security(ek: str, ak: str, suite: int = 0, policy: int | None = None):
    """The context a user configures for the meter: inbound APDUs are held to
    its policy and suite, so encryption-only meters (no AK) get ENCRYPTED, as
    ``pydlms push`` does, and probes pass the policy they were built with."""
    if not ek:
        return None
    from pydlms.security.context import SecurityContext
    from pydlms.security.suites import SecurityPolicy

    if policy is None:
        policy = SecurityPolicy.AUTHENTICATED_ENCRYPTED if ak else SecurityPolicy.ENCRYPTED
    return SecurityContext(
        bytes.fromhex(ek),
        bytes.fromhex(ak) if ak else None,
        suite=suite,
        policy=SecurityPolicy(policy),
        allow_unverified_auth=not ak,
        replay_protection=False,
    )


def _body_offset(note) -> int:
    """Offset of the notification body in a plaintext DataNotification."""
    if note.date_time is None:
        return 6
    return 5 + (2 if note.date_time_tagged else 1) + len(note.date_time)


def pydlms_captures(
    hex_: str,
    ek: str = "",
    ak: str = "",
    framing: str = "raw",
    crc=True,
    suite: int = 0,
    policy: int | None = None,
) -> dict:
    """pydlms's PushDecoder result in the esphome adapter's shape."""
    from pydlms.security.ciphering import is_ciphered_apdu, unwrap

    security = _security(ek, ak, suite, policy)
    decoder = PushDecoder(framing=framing, security=security, verify_checksums=crc)
    messages = decoder.feed(bytes.fromhex(hex_))
    if len(messages) != 1:
        raise DlmsError(f"{len(messages)} push messages")
    message = messages[0]
    captures = []
    for record in message.records:
        if record.obis is None or record.data.tag in (DataType.STRUCTURE, DataType.ARRAY):
            continue
        cap = {
            "obis": str(record.obis),
            "type": TYPE_NAMES[record.data.tag],
            "value": content(record.data).hex(),
        }
        if record.unit is not None:
            cap["scaler"] = record.scaler
            cap["unit"] = int(record.unit)
        captures.append(cap)
    out: dict = {"captures": captures, "complete": message.complete}
    note = message.notification
    if framing == "raw" and getattr(note, "date_time_tagged", None) is not None:
        plain = bytes.fromhex(hex_)
        if plain[0] == Tag.GENERAL_BLOCK_TRANSFER:
            plain = None
        elif is_ciphered_apdu(plain):
            plain = unwrap(_security(ek, ak, suite, policy), plain).plaintext
        if plain is not None:
            out["axdr"] = plain[_body_offset(note) :].hex()
    return out


def _same_value(theirs: dict, ours: dict) -> bool:
    if theirs["value"] != ours["value"]:
        return False
    if theirs["type"] == ours["type"]:
        return True
    # dlms_parser relabels a 12-octet octet-string that looks like a date-time.
    return theirs["type"] == "date-time" and ours["type"] == "octet-string"


def capture_diff(theirs: dict, ours: dict) -> str | None:
    """None when dlms_parser's captures and pydlms's records say the same; else why not."""
    if "axdr" in ours and theirs["axdr"] != ours["axdr"]:
        return f"axdr: {theirs['axdr'][:40]}... vs pydlms {ours['axdr'][:40]}..."
    mine: dict[str, list[dict]] = {}
    for cap in ours["captures"]:
        mine.setdefault(cap["obis"], []).append(cap)
    unmatched, wrong = [], []
    for cap in theirs["captures"]:
        if cap["obis"] == "0.0.0.0.0.0":
            continue
        candidates = mine.get(cap["obis"], [])
        if not candidates:
            unmatched.append(cap["obis"])
            continue
        mate = candidates.pop(0)
        if not _same_value(cap, mate):
            wrong.append(
                f"{cap['obis']}: {cap['type']} {cap['value']} vs {mate['type']} {mate['value']}"
            )
        elif (
            "scaler" in cap
            and "scaler" in mate
            and (cap["scaler"], cap["unit"])
            != (
                mate["scaler"],
                mate["unit"],
            )
        ):
            wrong.append(f"{cap['obis']}: scaler/unit {cap['scaler']},{cap['unit']}")
    missing = [obis for obis, caps in mine.items() for _ in caps]
    parts = []
    if wrong:
        parts.append("values " + "; ".join(wrong))
    if unmatched:
        parts.append("only dlms_parser " + ",".join(unmatched))
    if missing:
        parts.append("only pydlms " + ",".join(missing))
    return " | ".join(parts) or None


EK = "000102030405060708090a0b0c0d0e0f"
AK = "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"


def _pair(obis: str, value: DlmsData) -> DlmsData:
    from pydlms.obis import ObisCode

    return DlmsData.structure([DlmsData.octet_string(ObisCode.parse(obis).to_bytes()), value])


def probes() -> list[tuple[str, str, str, str, int | None]]:
    """(name, apdu hex, ek, ak, policy): pushes built by pydlms to probe one
    feature each; policy is the SC protection the receiver is configured for."""
    from pydlms.apdu.xdlms import DataNotification
    from pydlms.security.ciphering import wrap_general_glo
    from pydlms.security.context import SecurityContext
    from pydlms.security.suites import SecurityControl

    def note(body: DlmsData) -> bytes:
        return DataNotification(1, body).to_bytes()

    out = []
    # 130 objects: the array count needs the long form 81 82 (A-XDR length).
    many = DlmsData.array([_pair(f"1.0.1.8.0.{k}", DlmsData.uint16(k)) for k in range(130)])
    out.append(("array-130", note(many).hex(), "", "", None))
    # bcd is a one-octet type (Blue Book 4.1.5, tag 13), no length octet.
    bcd = DlmsData.structure(
        [
            _pair("1.0.1.8.0.255", DlmsData(DataType.BCD, 0x12)),
            _pair("1.0.2.8.0.255", DlmsData.uint32(7)),
        ]
    )
    out.append(("bcd", note(bcd).hex(), "", "", None))
    # A 200-octet octet-string (length 81 C8) as a positive control.
    long_octets = DlmsData.structure([_pair("0.0.96.1.0.255", DlmsData.octet_string(bytes(200)))])
    out.append(("octets-200", note(long_octets).hex(), "", "", None))
    # general-glo-ciphering, security control 0x10: authenticated, not encrypted.
    plain = note(DlmsData.structure([_pair("1.0.1.8.0.255", DlmsData.uint32(42))]))
    for label, sc in (("auth-only", 0x10), ("auth-enc", 0x30), ("enc-only", 0x20)):
        ctx = SecurityContext(
            bytes.fromhex(EK),
            bytes.fromhex(AK),
            client_system_title=bytes.fromhex("4142434445464748"),
        )
        apdu = wrap_general_glo(ctx, plain, SecurityControl.from_byte(sc))
        out.append((label, apdu.hex(), EK, AK if sc & 0x10 else "", sc))
    return out


def esphome_lines() -> list[tuple[str, str, dict]]:
    """(row name, oracle line, pydlms call kwargs) for every push input."""
    from tests.meter_fixtures import all_names, load

    out = []
    for name, hex_, ek, ak in corpus.pushes():
        line = " ".join(x for x in ("push", hex_, ek or ("-" if ak else ""), ak) if x)
        suite = SUITES.get(name.rsplit("-", 1)[0], 0)
        out.append((f"push:{name}", line, {"hex_": hex_, "ek": ek, "ak": ak, "suite": suite}))
    for name, hex_, ek, ak, policy in probes():
        line = " ".join(x for x in ("push", hex_, ek, ak) if x)
        out.append((f"probe:{name}", line, {"hex_": hex_, "ek": ek, "ak": ak, "policy": policy}))
    for name in all_names():
        fx = load(name)
        framing = {"hdlc": "hdlc", "mbus": "mbus"}.get(fx.transport, "raw")
        ek = fx.encryption_key.hex() if fx.encryption_key else ""
        ak = fx.authentication_key.hex() if fx.authentication_key else ""
        crc = name != "hdlc_landis_gyr_zmf100"  # upstream's own capture has a bad FCS
        line = f"frame {fx.raw.hex()} {ek or '-'} {ak or '-'} {'crc' if crc else 'nocrc'}"
        kwargs = {
            "hex_": fx.raw.hex(),
            "ek": ek,
            "ak": ak,
            "framing": framing,
            "crc": crc,
            "suite": SUITES.get(name, 0),
        }
        out.append((f"frame:{name}", line, kwargs))
    return out


def classify_esphome(oracle, name: str, line: str, kwargs: dict) -> dict:
    theirs = oracle.ask(line)
    try:
        ours = {"ok": True, "result": pydlms_captures(**kwargs)}
    except (DlmsError, ValueError) as exc:
        ours = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    row = {"name": name, "op": name.split(":", 1)[0], "pydlms": ours, "oracle": theirs}
    if theirs.get("unsupported"):
        row["outcome"] = "unsupported"
    elif ours["ok"] and theirs["ok"]:
        diff = capture_diff(theirs["result"], ours["result"])
        row["outcome"] = "agree" if diff is None else "disagree"
        if diff:
            row["diff"] = diff
    elif not ours["ok"] and not theirs["ok"]:
        row["outcome"] = "both-reject"
    else:
        row["outcome"] = "only-pydlms-rejects" if not ours["ok"] else "only-oracle-rejects"
    return row


def run_esphome(oracle) -> list[dict]:
    return [classify_esphome(oracle, n, line, kw) for n, line, kw in esphome_lines()]


def run_esphome_corpus(oracle) -> Counter:
    """Every corpus APDU as a push: what dlms_parser accepts that is no DataNotification."""
    counts: Counter = Counter()
    for _, hex_ in corpus.apdus():
        is_push = bytes.fromhex(hex_)[0] == Tag.DATA_NOTIFICATION
        reply = oracle.ask(f"push {hex_}")
        counts[f"{'push' if is_push else 'other'}:{'ok' if reply['ok'] else 'reject'}"] += 1
    return counts


# --- known disagreements -------------------------------------------------------------------

COMPACT_HAN = (
    "Kaifa HAN list carries no OBIS (compact form): dlms_parser's default patterns find no "
    "object and it rejects; pydlms decodes the body and labels it only through a profile"
)
ZMF_SWAP = (
    "capture has 06 09 where the OBIS header 09 06 belongs (not A-XDR): dlms_parser has a "
    "Landis+Gyr workaround (TOW pattern); pydlms stops at the damage and flags it incomplete"
)
MA309M = (
    "second M-Bus segment of the capture is corrupt: dlms_parser still reports the value of "
    "1.0.1.7.0.255 whose scaler_unit is garbage; pydlms keeps only fully decoded elements"
)
SELFDESC6 = (
    "push_object_list entries with 6 members (restriction, columns): dlms_parser's SelfDesc "
    "accepts only 4 and falls back to reading the definitions as values (attribute index "
    "as scaler); pydlms maps value i to definition i"
)
COUNT_LONG = (
    "array of 130: A-XDR count 81 82 (long form); dlms_parser reads one octet (0x81 = 129) "
    "and silently loses the first object"
)
BCD = "bcd is one octet (Blue Book Data CHOICE [13] Integer8); dlms_parser reads a length"
AUTH_ONLY = (
    "security control 0x10 (authentication only, plaintext + tag): dlms_parser always runs "
    "GCM decryption and fails the tag; pydlms verifies the tag over the plaintext"
)

KNOWN_ESPHOME: dict[str, tuple[str, str]] = {
    "push:hdlc_kaifa_ma304h3e-0": ("only-oracle-rejects", COMPACT_HAN),
    "frame:hdlc_kaifa_ma304h3e": ("only-oracle-rejects", COMPACT_HAN),
    "push:hdlc_landis_gyr_zmf100-0": ("disagree", ZMF_SWAP),
    "frame:hdlc_landis_gyr_zmf100": ("disagree", ZMF_SWAP),
    "push:mbus_kaifa_ma309m-0": ("disagree", MA309M),
    "frame:mbus_kaifa_ma309m": ("disagree", MA309M),
    "push:raw_energomera-0": ("disagree", SELFDESC6),
    "frame:raw_energomera": ("disagree", SELFDESC6),
    "probe:array-130": ("disagree", COUNT_LONG),
    "probe:bcd": ("disagree", BCD),
    "probe:auth-only": ("only-oracle-rejects", AUTH_ONLY),
}

WS_COMPACT = (
    "compact-array: the dissector reads the type description from the contents octets "
    "(description offset 0 in the contents tvb), so every compact array is malformed"
)
WS_LONG64 = "long64 printed with PRIu64 and long64-unsigned with PRId64 (format specifiers swapped)"
WS_SELECTOR = (
    "Selective-Access-Descriptor OPTIONAL: the dissector takes the presence octet for the "
    "access selector and the selector for a Data tag"
)
WS_LAST_DATABLOCK = (
    "Set-Response-Last-Datablock: block number read at the result octet (offset not advanced)"
)
WS_EVENT_TIME = (
    "EventNotification-Request: the dissector assumes time is absent and skips one octet; "
    "here time is present (01 0C + 12 octets), so the descriptor is misaligned"
)
WS_EXC_COUNTER = (
    "ExceptionResponse service-error invocation-counter-error [6] is IMPLICIT Unsigned32: "
    "d8xx06 lacks the counter; pydlms's strict decode rejects (7c98299), the dissector "
    "never reads the counter"
)
WS_AP_TITLE = (
    "AP-title encoded A6/A4 0A 04 08 <system title> (OCTET STRING, as in the Green Book "
    "AARQ example of tests/test_acse.py): the dissector's AP-title CHOICE has no OCTET "
    "STRING form and flags a BER error"
)
WS_INITIATE = (
    "xDLMS Initiate OPTIONAL/DEFAULT fields: the dissector reads response-allowed as one "
    "octet and skips an extra octet before quality-of-service; A-XDR has a presence octet "
    "then the value, no tag"
)
WS_ATTR_INT8 = "attribute_id is Integer8 (Green Book Cosem-Object-Attribute-Id); dissector: uint8"
WS_DN_BODY = (
    "DataNotification body is not A-XDR (vendor quirk): pydlms's strict APDU decode "
    "rejects; the dissector never decodes a DataNotification body"
)

WS_ACCESS_DATE_TIME = (
    "Wireshark 4.6 reports an ACCESS request or response with a 12-octet date-time "
    "07E8010101000000FF800000 as malformed (12 zero octets pass, and a DataNotification "
    "with the same date-time is dissected); cause not traced"
)
KNOWN_WIRESHARK: dict[str, tuple[str, str]] = {
    "apdu:access-request-date-time": ("only-oracle-rejects", WS_ACCESS_DATE_TIME),
    "data:hand-03-GetResponseNormal#0": ("only-oracle-rejects", WS_COMPACT),
    "data:hand-03-GetResponseNormal#18": ("only-oracle-rejects", WS_COMPACT),
    "data:hand-03-GetResponseNormal#6": ("disagree", WS_LONG64),
    "data:hand-03-GetResponseNormal#7": ("disagree", WS_LONG64),
    **{
        f"{op}:data-compact-{kind}{suffix}": ("only-oracle-rejects", WS_COMPACT)
        for op, suffix in (("data", "#0"), ("apdu", ""))
        for kind in ("structure", "array", "octets", "boolean", "int8")
    },
    "apdu:hand-03-GetResponseNormal": ("only-oracle-rejects", WS_COMPACT),
    "apdu:session-07-TX": ("disagree", WS_SELECTOR),
    "apdu:set-selective": ("disagree", WS_SELECTOR),
    "apdu:set-first-selective": ("disagree", WS_SELECTOR),
    "apdu:hand-00-GetRequestNormal": ("only-oracle-rejects", WS_SELECTOR),
    "apdu:hand-14-SetResponseLastDatablock": ("disagree", WS_LAST_DATABLOCK),
    "apdu:hand-29-EventNotificationRequest": ("disagree", WS_EVENT_TIME),
    **{f"apdu:exception-{s}-6": ("only-pydlms-rejects", WS_EXC_COUNTER) for s in range(3)},
    **{f"apdu:aarq-mechanism-{m}": ("only-oracle-rejects", WS_AP_TITLE) for m in range(1, 8)},
    "apdu:aare-hls": ("only-oracle-rejects", WS_AP_TITLE),
    "apdu:aarq-qos": ("only-oracle-rejects", WS_INITIATE),
    "apdu:initiate-no-response": ("only-oracle-rejects", WS_INITIATE),
    "apdu:initiate-qos": ("only-oracle-rejects", WS_INITIATE),
    "apdu:initiate-response-qos": ("only-oracle-rejects", WS_INITIATE),
    "apdu:get-class-attribute-edge": ("disagree", WS_ATTR_INT8),
    "apdu:capture-hdlc_landis_gyr_zmf100-0": ("only-pydlms-rejects", WS_DN_BODY),
    "apdu:capture-raw_egd_example-0": ("only-pydlms-rejects", WS_DN_BODY),
    "apdu:capture-raw_sagemcom_xt211-0": ("only-pydlms-rejects", WS_DN_BODY),
    "apdu:set-response-last-list-truncated": (
        "only-pydlms-rejects",
        "Set-Response-Last-Datablock-With-List cut before its Unsigned32 block-number: "
        "pydlms rejects the truncated APDU, the dissector stops after the results",
    ),
}


def _unexplained(rows: list[dict], known: dict) -> dict:
    got = {
        f"{r['op']}:{r['name']}" if ":" not in r["name"] else r["name"]: r["outcome"]
        for r in rows
        if r["outcome"] not in ("agree", "both-reject", "unsupported")
    }
    return {
        "unexplained": {k: v for k, v in got.items() if known.get(k, (None,))[0] != v},
        "stale": sorted(k for k in known if k not in got),
    }


# --- tests ------------------------------------------------------------------------------------


def _need(image: str, build_dir: str) -> None:
    """require_image, with the build hint for our nested Dockerfile directories."""
    import shutil
    import subprocess

    if (
        shutil.which("docker")
        and subprocess.run(  # noqa: S603,S607
            ["docker", "image", "inspect", image], capture_output=True, check=False
        ).returncode
    ):
        pytest.skip(f"image {image} missing: docker build -t {image} {build_dir}")
    require_image(image)


@pytest.fixture(scope="module")
def esphome():
    _need(ESPHOME, "tests/interop/push-parsers/esphome")
    oracle = Oracle(ESPHOME)
    yield oracle
    oracle.close()


@pytest.fixture(scope="module")
def wireshark():
    _need(WIRESHARK, "tests/interop/push-parsers/wireshark (after tests/integration/tshark)")
    oracle = Oracle(WIRESHARK)
    yield oracle
    oracle.close()


def test_esphome_hello(esphome):
    assert esphome.hello["library"] == "esphome-libs/dlms_parser"
    assert esphome.hello["version"].startswith("2.2.0")


def test_esphome_push_and_frames(esphome):
    rows = run_esphome(esphome)
    assert len(rows) == len(corpus.pushes()) + len(probes()) + 16
    assert _unexplained(rows, KNOWN_ESPHOME) == {"unexplained": {}, "stale": []}


def test_wireshark_corpus(wireshark):
    rows = compare.run(wireshark, ("data", "apdu"))
    assert sum(r["op"] == "data" for r in rows) == len(corpus.data_values())
    assert sum(r["op"] == "apdu" for r in rows) == len(corpus.apdus())
    assert _unexplained(rows, KNOWN_WIRESHARK) == {"unexplained": {}, "stale": []}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--json")
    p.add_argument("--corpus", action="store_true", help="also feed all corpus APDUs as pushes")
    args = p.parse_args()
    oracle = Oracle(ESPHOME)
    try:
        rows = run_esphome(oracle)
        extra = run_esphome_corpus(oracle) if args.corpus else None
    finally:
        oracle.close()
    for row in rows:
        if row["outcome"] not in ("agree", "both-reject", "unsupported"):
            why = row.get("diff") or row["oracle"].get("error") or row["pydlms"].get("error")
            print(row["name"], row["outcome"], why)
    print(json.dumps(Counter(f"{r['op']}:{r['outcome']}" for r in rows), indent=1))
    if extra is not None:
        print("corpus APDUs as push:", json.dumps(extra))
    print(json.dumps(_unexplained(rows, KNOWN_ESPHOME), indent=1))
    if args.json:
        with open(args.json, "w") as out:
            json.dump(rows, out, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
