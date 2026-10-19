"""APDUs whose Gurux translator XML is frozen in ``tests/fixtures/gurux_xml``.

``build()`` lists every APDU shape pydlms produces: the simulator session and
hand-built APDUs of ``test_apduxml``, the real captures, every result and
error code, every conformance bit, the ACSE variants, data types and the
ciphered wrappers. ``python -m tests.gurux_xml_corpus`` runs them through
``GXDLMSTranslator`` (image ``pydlms-gurux-client``, see
``tests/integration/gurux_client/Dockerfile``) and rewrites the fixture.
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path

FIXTURE = Path(__file__).parent / "fixtures" / "gurux_xml" / "translator.json"
IMAGE = "pydlms-gurux-client"
EK = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
AK = bytes.fromhex("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF")


def _probes() -> list[tuple[str, bytes]]:
    from pydlms.apdu import sn, xdlms
    from pydlms.apdu.acse import AARE, AARQ, RLRE, RLRQ, ApplicationContext
    from pydlms.cosem.data import CompactArray, DlmsData, TypeDescription
    from pydlms.cosem.enums import ActionResult, DataAccessResult, DataType
    from pydlms.obis import ObisCode

    energy = ObisCode.parse("1.0.1.8.0.255")
    att = xdlms.AttributeDescriptor(3, energy, 2)
    initiate = xdlms.InitiateRequest(xdlms.Conformance.default_ln(), 512)
    rows: list[tuple[str, bytes]] = []

    def add(name, obj):
        rows.append((name, obj if isinstance(obj, bytes) else obj.to_bytes()))

    def get(data):
        return xdlms.GetResponseNormal(0xC1, xdlms.GetDataResult(data=data))

    for v in [*range(20), 250]:
        add(f"set-result-{v}", bytes([0xC5, 1, 0xC1, v]))
        add(f"action-result-{v}", bytes([0xC7, 1, 0xC1, v, 0]))
    for state in range(3):
        for service in range(8):
            add(f"exception-{state}-{service}", bytes([0xD8, state, service]))
    add("exception-ic", bytes.fromhex("d80106000004d2"))
    for error in range(9):
        for value in range(8):
            add(f"cse-{error}-{value}", bytes([0x0E, 1, error, value]))
    add("cse-service-10", bytes([0x0E, 10, 6, 1]))
    for bit in range(24):
        add(f"conformance-{bit}", xdlms.InitiateResponse(xdlms.Conformance(1 << bit), 512))
    for result in range(3):
        for source, diagnostics in ((1, range(16)), (2, range(3))):
            for diagnostic in diagnostics:
                add(
                    f"aare-{result}-{source}-{diagnostic}",
                    AARE(ApplicationContext.LN, result, source, diagnostic),
                )
    for context in ApplicationContext:
        add(f"aarq-context-{int(context)}", AARQ(context, initiate.to_bytes()))
    for mech in range(8):
        add(
            f"aarq-mechanism-{mech}",
            AARQ(
                ApplicationContext.LN_CIPHERED,
                initiate.to_bytes(),
                mechanism=mech,
                calling_authentication_value=b"ABCDEFGH" if mech else None,
                calling_ap_title=b"ABCDEFGH" if mech else None,
            ),
        )
    conf = xdlms.Conformance.default_ln()
    add(
        "aarq-dedicated-key",
        AARQ(
            ApplicationContext.LN,
            xdlms.InitiateRequest(conf, 512, dedicated_key=bytes(range(16))).to_bytes(),
        ),
    )
    add(
        "aarq-qos",
        AARQ(
            ApplicationContext.LN,
            xdlms.InitiateRequest(
                conf, 512, quality_of_service=3, response_allowed=False
            ).to_bytes(),
        ),
    )
    add(
        "aarq-ae-qualifier",
        AARQ(ApplicationContext.LN, initiate.to_bytes(), calling_ae_qualifier=b"\x01\x02"),
    )
    add(
        "aare-hls",
        AARE(
            ApplicationContext.LN_CIPHERED,
            0,
            1,
            14,
            responding_ap_title=b"MMMMMMMM",
            mechanism=5,
            responding_authentication_value=b"P" * 16,
            user_information=xdlms.InitiateResponse(conf, 512).to_bytes(),
        ),
    )
    add(
        "aare-sn",
        AARE(
            ApplicationContext.SN,
            0,
            1,
            0,
            user_information=xdlms.InitiateResponse(
                xdlms.Conformance(0x1C), 512, vaa_name=0xFA00
            ).to_bytes(),
        ),
    )
    add(
        "aare-error",
        AARE(ApplicationContext.LN, 1, 1, 1, user_information=bytes.fromhex("0e010601")),
    )
    for reason in (None, 0, 1, 30):
        add(f"rlrq-{reason}", RLRQ(reason, b""))
        add(f"rlre-{reason}", RLRE(reason, b""))
    add("rlrq-user-information", RLRQ(0, initiate.to_bytes()))
    data = {
        "null": DlmsData.null(),
        "boolean": DlmsData.boolean(True),
        "int8": DlmsData.int8(-1),
        "int16": DlmsData.int16(-2),
        "int32": DlmsData(DataType.DOUBLE_LONG, -3),
        "uint32": DlmsData.uint32(3),
        "int64": DlmsData(DataType.LONG64, 5),
        "enum": DlmsData(DataType.ENUM, 7),
        "float32": DlmsData(DataType.FLOAT32, 0.0),
        "visible": DlmsData.visible_string("ab"),
        "visible-spaces": DlmsData.visible_string("  x  "),
        "visible-nul": DlmsData.visible_string("a\x00b"),
        "visible-markup": DlmsData.visible_string("<&>\"'"),
        "visible-control": DlmsData.visible_string("a\tb\rc"),
        "visible-latin1": DlmsData.visible_string("\xe9\xff"),
        "utf8": DlmsData(DataType.UTF8_STRING, "x"),
        "octets-empty": DlmsData.octet_string(b""),
        "octets-obis": DlmsData.octet_string(energy.to_bytes()),
        "octets-ascii": DlmsData.octet_string(b"HELLO"),
        "date-time": DlmsData(DataType.DATE_TIME, bytes.fromhex("07E8010101000000FF800000")),
        "bits-empty": DlmsData(DataType.BIT_STRING, []),
        "bits-9": DlmsData(DataType.BIT_STRING, [True] * 9),
        "array-empty": DlmsData.array([]),
        "array-300": DlmsData.array([DlmsData.uint8(i % 256) for i in range(300)]),
        "structure-empty": DlmsData.structure([]),
        "nested": DlmsData.array([DlmsData.structure([DlmsData.null(), DlmsData.array([])])]),
    }
    u8 = TypeDescription(DataType.UNSIGNED)
    compact = {
        "compact-uint16-empty": CompactArray(TypeDescription(DataType.LONG_UNSIGNED), []),
        "compact-structure": CompactArray(
            TypeDescription(DataType.STRUCTURE, members=(u8, TypeDescription(DataType.LONG))),
            [
                DlmsData.structure([DlmsData.uint8(1), DlmsData(DataType.LONG, -2)]),
                DlmsData.structure([DlmsData.uint8(3), DlmsData(DataType.LONG, 4)]),
            ],
        ),
        "compact-array": CompactArray(
            TypeDescription(DataType.ARRAY, array_of=(2, u8)),
            [DlmsData.array([DlmsData.uint8(1), DlmsData.uint8(2)])],
        ),
        "compact-octets": CompactArray(
            TypeDescription(DataType.OCTET_STRING),
            [DlmsData.octet_string(b"\x01\x02"), DlmsData.octet_string(b"")],
        ),
        "compact-boolean": CompactArray(
            TypeDescription(DataType.BOOLEAN), [DlmsData.boolean(True), DlmsData.boolean(False)]
        ),
        "compact-int8": CompactArray(TypeDescription(DataType.INTEGER), [DlmsData.int8(-1)]),
    }
    for name, value in compact.items():
        data[name] = DlmsData(DataType.COMPACT_ARRAY, value)
    for name, value in data.items():
        add(f"data-{name}", get(value))
    add(
        "get-list-error",
        xdlms.GetResponseWithList(
            0xC1,
            [
                xdlms.GetDataResult(error=DataAccessResult(4)),
                xdlms.GetDataResult(data=DlmsData.uint8(1)),
            ],
        ),
    )
    method = xdlms.MethodDescriptor(8, energy, 1)
    add(
        "action-list",
        xdlms.ActionRequestWithList(
            0xC1,
            [(method, DlmsData.int8(0)), (xdlms.MethodDescriptor(8, energy, 2), DlmsData.null())],
        ),
    )
    add(
        "action-list-response",
        xdlms.ActionResponseWithList(
            0xC1,
            [
                (ActionResult.SUCCESS, xdlms.GetDataResult(data=DlmsData.uint8(1))),
                (ActionResult.TYPE_UNMATCHED, None),
            ],
        ),
    )
    add(
        "action-return-error",
        xdlms.ActionResponseNormal(
            0xC1, ActionResult.SUCCESS, xdlms.GetDataResult(error=DataAccessResult(3))
        ),
    )
    sel = xdlms.SelectiveAccess(2, DlmsData.uint8(5))
    add(
        "set-selective",
        xdlms.SetRequestNormal(
            0xC1, att, DlmsData.uint8(1), xdlms.SelectiveAccess(1, DlmsData.null())
        ),
    )
    add(
        "set-first-selective",
        xdlms.SetRequestWithFirstDatablock(
            0xC1, att, True, 1, b"\x11\x01", xdlms.SelectiveAccess(1, DlmsData.null())
        ),
    )
    add("set-list-selective", xdlms.SetRequestWithList(0xC1, [(att, sel, DlmsData.uint8(1))]))
    add("get-list-selective", xdlms.GetRequestWithList(0xC1, [(att, sel)]))
    add(
        "get-class-attribute-edge",
        xdlms.GetRequestNormal(
            0xC1, xdlms.AttributeDescriptor(0x1234, ObisCode.parse("1.2.3.4.5.6"), -2)
        ),
    )
    stamp = bytes.fromhex("07E8010101000000FF800000")
    add("notification-date-time", xdlms.DataNotification(0x80000001, DlmsData.uint8(1), stamp))
    add(
        "notification-tagged-date-time",
        xdlms.DataNotification(1, DlmsData.uint8(1), stamp, date_time_tagged=True),
    )
    add("notification-no-date-time", xdlms.DataNotification(1, DlmsData.uint8(1)))
    add("event-no-time", xdlms.EventNotificationRequest(att, DlmsData.uint16(42)))
    add("information-report", sn.InformationReportRequest(None, [0x3008], [DlmsData.uint8(1)]))
    add(
        "information-report-time",
        sn.InformationReportRequest(stamp, [0x3008, 0x3010], [DlmsData.uint8(1), DlmsData.null()]),
    )
    add(
        "read-response-block",
        sn.ReadResponse([sn.ReadResult(block_last=False, block_number=3, raw_data=b"\x01\x02")]),
    )
    add(
        "write-parameterised",
        sn.WriteRequest(
            [sn.VariableName(0x3010), sn.ParameterizedAccess(0x3008, 1, DlmsData.uint8(1))],
            [DlmsData.uint32(5), DlmsData.null()],
        ),
    )
    add("sn-read-data-block", bytes.fromhex("05010601000102aabb"))  # review-codec repro
    add(
        "sn-read-data-block-first",
        sn.ReadRequest(
            [
                sn.ReadDataBlockAccess(
                    False,
                    1,
                    sn.ReadRequest(
                        [sn.ParameterizedAccess(0x3058, 0, DlmsData.uint8(1))]
                    ).to_bytes()[1:],
                )
            ]
        ),
    )
    add(
        "sn-write-data-block",
        sn.WriteRequest(
            [sn.WriteDataBlockAccess(True, 2)], [DlmsData.octet_string(b"\x01\x02\x03")]
        ),
    )
    add("sn-read-block-number", sn.ReadResponse([sn.ReadResult(block_number=2)]))
    add("sn-write-block-number", sn.WriteResponse([sn.WriteBlockNumber(2)]))
    # Choice 5 with-list-and-first-block (layout per jDLMS; no Gurux form).
    add(
        "set-list-first-datablock",
        bytes.fromhex("c105c10100010000010000ff0200000000000103011105"),
    )
    add(
        "action-list-first-pblock",
        bytes.fromhex("c305c1010046000060030aff01000000000103011100"),
    )
    add("set-response-last-list-truncated", bytes.fromhex("c504c1020000"))
    add("initiate-no-response", xdlms.InitiateRequest(conf, 512, response_allowed=False))
    add("initiate-qos", xdlms.InitiateRequest(conf, 512, quality_of_service=3))
    add("initiate-dedicated-key", xdlms.InitiateRequest(conf, 512, dedicated_key=bytes(range(16))))
    add("initiate-response-qos", xdlms.InitiateResponse(conf, 512, quality_of_service=1))
    add("gbt-streaming", bytes.fromhex("e0c10001000006c401c1000900"))
    add("gbt-empty", bytes.fromhex("e0800003000200"))
    # ACCESS: the Table F.10 request, the annex I.2 response
    # (less its extra zero octet), each specification and result kind.
    from tests.test_access_service import F10_REQUEST, I2_RESPONSE

    add("access-f10-request", F10_REQUEST)
    add("access-i2-response", I2_RESPONSE)
    method = xdlms.MethodDescriptor(70, ObisCode.parse("0.0.96.3.10.255"), 1)
    access_specs = [
        xdlms.AccessRequestGet(att),
        xdlms.AccessRequestSet(att),
        xdlms.AccessRequestAction(method),
    ]
    access_data = [DlmsData.null(), DlmsData.uint32(5), DlmsData.int8(0)]
    lid = xdlms.long_invoke_id(0x123456, processing_option=xdlms.ProcessingOption.BREAK_ON_ERROR)
    add("access-request-kinds", xdlms.AccessRequest(lid, None, access_specs, access_data))
    add(
        "access-request-date-time",
        xdlms.AccessRequest(1, stamp, access_specs[:1], access_data[:1]),
    )
    add(
        "access-request-get-selection",
        xdlms.AccessRequest(
            1, None, [xdlms.AccessRequestGetWithSelection(att, sel)], [DlmsData.null()]
        ),
    )
    add(
        "access-request-set-selection",
        xdlms.AccessRequest(
            1, None, [xdlms.AccessRequestSetWithSelection(att, sel)], [DlmsData.uint8(1)]
        ),
    )
    ok = [
        xdlms.AccessResponseGet(DataAccessResult.SUCCESS),
        xdlms.AccessResponseSet(DataAccessResult.SUCCESS),
        xdlms.AccessResponseAction(ActionResult.SUCCESS),
    ]
    add(
        "access-response-kinds",
        xdlms.AccessResponse(
            lid, None, None, [DlmsData.uint32(7), DlmsData.null(), DlmsData.null()], ok
        ),
    )
    add(
        "access-response-errors",
        xdlms.AccessResponse(
            lid,
            None,
            None,
            [DlmsData.null()] * 3,
            [
                xdlms.AccessResponseGet(DataAccessResult.OBJECT_UNDEFINED),
                xdlms.AccessResponseSet(DataAccessResult.READ_WRITE_DENIED),
                xdlms.AccessResponseAction(ActionResult.OTHER_REASON),
            ],
        ),
    )
    add(
        "access-response-echo",
        xdlms.AccessResponse(lid, None, access_specs, [DlmsData.null()] * 3, ok),
    )
    return rows


def _ciphered() -> list[tuple[str, bytes]]:
    from pydlms.apdu import sn, xdlms
    from pydlms.apdu.acse import AARQ, ApplicationContext
    from pydlms.obis import ObisCode
    from pydlms.security import ciphering
    from pydlms.security.context import SecurityContext
    from tests.crypto.test_gurux_general_frames import FRAMES

    ctx = SecurityContext(EK, AK, client_system_title=b"ABCDEFGH", invocation_counter=5)
    ctx.set_dedicated_key(bytes(range(16)))
    get = xdlms.GetRequestNormal(
        0xC1, xdlms.AttributeDescriptor(3, ObisCode.parse("1.0.1.8.0.255"), 2)
    )
    initiate = xdlms.InitiateRequest(xdlms.Conformance.default_ln(), 512).to_bytes()
    rows = [
        ("ciphered-glo-get", ciphering.wrap(ctx, get.to_bytes())),
        ("ciphered-ded-get", ciphering.wrap(ctx, get.to_bytes(), dedicated=True)),
        ("ciphered-glo-initiate", ciphering.wrap(ctx, initiate)),
        ("ciphered-general-glo", ciphering.wrap_general_glo(ctx, get.to_bytes())),
        (
            "ciphered-glo-read",
            ciphering.wrap(ctx, sn.ReadRequest([sn.VariableName(0xFA08)]).to_bytes()),
        ),
        (
            "ciphered-aarq",
            AARQ(
                ApplicationContext.LN_CIPHERED,
                ciphering.wrap(ctx, initiate),
                mechanism=5,
                calling_authentication_value=b"C" * 16,
                calling_ap_title=b"ABCDEFGH",
            ).to_bytes(),
        ),
    ]
    rows += [(f"ciphered-{name}", frame) for name, frame in FRAMES.items()]
    return rows


def build() -> list[dict]:
    """``{"name", "apdu", "keys"}`` rows; keys are hex (encryption, authentication)."""
    from pydlms.recording import deframe
    from tests import test_apduxml as t
    from tests.meter_fixtures import all_names, load

    rows = [
        {"name": f"session-{i:02d}-{d}", "apdu": a.hex()} for i, (d, a) in enumerate(t._SESSION)
    ]
    rows += [
        {"name": f"hand-{i:02d}-{type(o).__name__}", "apdu": o.to_bytes().hex()}
        for i, o in enumerate(t._HAND_BUILT)
    ]
    rows += [{"name": n, "apdu": a.hex()} for n, a in _probes()]
    keys = [EK.hex(), AK.hex()]
    rows += [{"name": n, "apdu": a.hex(), "keys": keys} for n, a in _ciphered()]
    for name in all_names():
        fixture = load(name)
        framing = {"hdlc": "hdlc", "mbus": "mbus"}.get(fixture.transport, "apdu")
        for j, (_, apdu) in enumerate(
            deframe([(None, fixture.raw)], framing, verify_checksums=False)
        ):
            row = {"name": f"capture-{name}-{j}", "apdu": apdu.hex()}
            if fixture.encryption_key:
                row["keys"] = [
                    fixture.encryption_key.hex(),
                    (fixture.authentication_key or b"").hex(),
                ]
            rows.append(row)
    return rows


def translate(lines: list[str], keys: list[str] | None = None) -> list[str]:
    """Run ``P <hex>`` / ``X <base64>`` lines through GXDLMSTranslator."""
    extra = [keys[0], keys[1] or "00" * 16] if keys else []
    out = subprocess.run(
        ["docker", "run", "--rm", "-i", IMAGE, "translate", "simple", *extra],
        input="".join(line + "\n" for line in lines),
        capture_output=True,
        text=True,
        check=True,
        timeout=600,
    ).stdout.splitlines()
    if len(out) != len(lines):
        raise RuntimeError(f"translator answered {len(out)} of {len(lines)} lines")
    return out


def run(rows: list[dict]) -> list[dict]:
    """Add Gurux's XML (``xml`` or ``error``) and whether Gurux encodes its own
    XML back to the APDU (``self_round_trip``)."""
    groups: dict[tuple, list[dict]] = {}
    for row in rows:
        groups.setdefault(tuple(row.get("keys", ())), []).append(row)
    for keys, members in groups.items():
        answers = translate([f"P {r['apdu']}" for r in members], list(keys) or None)
        back = []
        for row, answer in zip(members, answers, strict=True):
            kind, _, body = answer.partition(" ")
            if kind == "X":
                row["xml"] = base64.b64decode(body).decode("utf-8")
                back.append(row)
            else:
                row["error"] = body
        replies = translate(
            ["X " + base64.b64encode(r["xml"].encode()).decode() for r in back], list(keys) or None
        )
        for row, reply in zip(back, replies, strict=True):
            kind, _, body = reply.partition(" ")
            row["self_round_trip"] = kind == "P" and body.lower() == row["apdu"]
    return rows


def main() -> int:
    rows = run(build())
    FIXTURE.write_text(json.dumps(rows, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"{len(rows)} APDUs, {sum('xml' in r for r in rows)} translated -> {FIXTURE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
