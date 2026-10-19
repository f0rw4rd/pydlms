"""dlms-cosem as an oracle: tests/interop/PROTOCOL.md on stdin/stdout.

Runs inside the pydlms-interop-dlms-cosem image only. Every value in a reply
comes out of dlms-cosem's own decoders (``DlmsDataParser``,
``XDlmsApduFactory``, ``GeneralGlobalCipher``); where dlms-cosem keeps a
Python object instead of the wire value (datetime, Conformance, enums) the
adapter maps it back with dlms-cosem's own encoder or enum value. Fields that
dlms-cosem does not model are left out (the comparison is a subset match).

A ``NotImplementedError`` or "Tag ... is not available" from dlms-cosem means
the library has no such feature and is answered ``unsupported``; any other
exception is a rejection.
"""

from __future__ import annotations

import json
import sys
import traceback
from importlib.metadata import version

from dlms_cosem import dlms_data as dd
from dlms_cosem import enumerations, time
from dlms_cosem.connection import XDlmsApduFactory
from dlms_cosem.protocol import acse, xdlms
from dlms_cosem.protocol.xdlms import action, get
from dlms_cosem.protocol.xdlms import set as set_mod
from dlms_cosem.protocol.xdlms.confirmed_service_error import ErrorFactory


class Unsupported(Exception):
    pass


NAMES = {
    dd.NullData: "null-data",
    dd.DataArray: "array",
    dd.DataStructure: "structure",
    dd.BooleanData: "boolean",
    dd.BitStringData: "bit-string",
    dd.DoubleLongData: "double-long",
    dd.DoubleLongUnsignedData: "double-long-unsigned",
    dd.OctetStringData: "octet-string",
    dd.VisibleStringData: "visible-string",
    dd.UTF8StringData: "utf8-string",
    dd.BCDData: "bcd",
    dd.IntegerData: "integer",
    dd.LongData: "long",
    dd.UnsignedIntegerData: "unsigned",
    dd.UnsignedLongData: "long-unsigned",
    dd.CompactArrayData: "compact-array",
    dd.Long64Data: "long64",
    dd.UnsignedLong64Data: "long64-unsigned",
    dd.EnumData: "enum",
    dd.Float32Data: "float32",
    dd.Float64Data: "float64",
    dd.DateTimeData: "date-time",
    dd.DateData: "date",
    dd.TimeData: "time",
}
BY_NAME = {name: cls for cls, name in NAMES.items()}
INTS = {
    dd.DoubleLongData,
    dd.DoubleLongUnsignedData,
    dd.IntegerData,
    dd.LongData,
    dd.UnsignedIntegerData,
    dd.UnsignedLongData,
    dd.Long64Data,
    dd.UnsignedLong64Data,
    dd.EnumData,
}


# --- data -------------------------------------------------------------------------------


def tree(item) -> dict:
    """dlms-cosem data object -> PROTOCOL.md data tree."""
    cls = type(item)
    if cls not in NAMES:
        raise Unsupported(f"no data-tree mapping for {cls.__name__}")
    name, v = NAMES[cls], item.value
    if cls is dd.NullData:
        return {"t": name, "v": None}
    if cls in (dd.DataArray, dd.DataStructure):
        return {"t": name, "v": [tree(x) for x in v]}
    if cls in INTS:
        return {"t": name, "v": int(v)}
    if cls is dd.BooleanData:
        return {"t": name, "v": bool(v)}
    if cls is dd.OctetStringData:
        return {"t": name, "v": bytes(v).hex()}
    if cls is dd.VisibleStringData:
        return {"t": name, "v": v}
    # dlms-cosem turns these into datetime objects; map back with its own encoder.
    if cls is dd.DateTimeData:
        dt, status = v
        return {"t": name, "v": time.datetime_to_bytes(dt, status).hex()}
    if cls is dd.DateData:
        return {"t": name, "v": time.date_to_bytes(v).hex()}
    if cls is dd.TimeData:
        return {"t": name, "v": time.time_to_bytes(v).hex()}
    raise Unsupported(f"no value mapping for {cls.__name__}")


def parse_one(raw: bytes):
    """One A-XDR Data value with dlms-cosem's parser; returns (item, octets used)."""
    parser = dd.DlmsDataParser()
    try:
        items = parser.parse(bytearray(raw), limit=1)
    except KeyError as exc:
        raise ValueError(f"unknown data tag {exc}") from exc
    if not items:
        raise ValueError("no data")
    return items[0], parser.pointer


def op_data(hex_: str) -> dict:
    raw = bytes.fromhex(hex_)
    item, used = parse_one(raw)
    if used < len(raw):
        raise ValueError(f"{len(raw) - used} trailing octets")
    # used > len(raw) is dlms-cosem reading past the end (get_bytes returns short
    # slices without complaint); reported as it decodes, not masked here.
    return tree(item)


def build(obj: dict):
    cls = BY_NAME[obj["t"]]
    v = obj.get("v")
    if cls in (dd.DataArray, dd.DataStructure):
        return cls([build(x) for x in v])
    if cls is dd.OctetStringData:
        return cls(bytes.fromhex(v))
    if cls is dd.BitStringData:
        bits = v + "0" * (-len(v) % 8)
        return cls(int(bits, 2).to_bytes(len(bits) // 8, "big") if bits else b"")
    if cls is dd.DateTimeData:
        return cls(time.datetime_from_bytes(bytes.fromhex(v)))
    if cls is dd.DateData:
        return cls(time.date_from_bytes(bytes.fromhex(v)))
    if cls is dd.TimeData:
        return cls(time.time_from_bytes(bytes.fromhex(v)))
    return cls(v)


def op_encode_data(obj: dict) -> dict:
    return {"hex": build(obj).to_bytes().hex()}


def data_or_none(raw) -> dict | None:
    """A Data value embedded in an APDU; None when dlms-cosem cannot map it."""
    try:
        # dlms-cosem neither checks trailing octets nor overruns here (its client
        # takes the first parsed value), so neither is checked on its behalf.
        return tree(parse_one(bytes(raw))[0])
    except (Unsupported, NotImplementedError):
        return None


# --- apdu -------------------------------------------------------------------------------


def iid(obj) -> int:
    return obj.invoke_id_and_priority.to_bytes()[0]


def obis(o) -> str:
    return ".".join(str(x) for x in (o.a, o.b, o.c, o.d, o.e, o.f))


def long_iid(obj) -> int:
    # The whole Long-Invoke-Id-And-Priority (as pydlms's long_invoke_id), re-encoded
    # by dlms-cosem from its parsed flags; reserved bits 24-27 are not kept.
    return int.from_bytes(obj.long_invoke_id_and_priority.to_bytes(), "big")


def attribute(a) -> dict:
    return {
        "kind": "attribute-descriptor",
        "class_id": int(a.interface),
        "instance_id": obis(a.instance),
        "attribute_id": a.attribute,
    }


def method(m) -> dict:
    return {
        "kind": "method-descriptor",
        "class_id": int(m.interface),
        "instance_id": obis(m.instance),
        "method_id": m.method,
    }


def access(sel) -> dict | None:
    if sel is None:
        return None
    raw = sel.to_bytes()  # dlms-cosem keeps datetimes; its encoder gives the wire form
    out = {"kind": "selective-access", "selector": raw[0]}
    params = data_or_none(raw[1:])
    if params is not None:
        out["parameters"] = params
    return out


def with_data(out: dict, key: str, raw) -> dict:
    value = data_or_none(raw)
    if value is not None:
        out[key] = value
    return out


def conformance(c) -> int:
    return int.from_bytes(c.to_bytes()[1:], "big")


def initiate(obj) -> dict:
    if isinstance(obj, xdlms.InitiateRequest):
        return {
            "kind": "initiate-request",
            "conformance": conformance(obj.proposed_conformance),
            "max_receive_pdu_size": obj.client_max_receive_pdu_size,
            "dlms_version": obj.proposed_dlms_version_number,
            "dedicated_key": obj.dedicated_key.hex() if obj.dedicated_key else None,
            "response_allowed": obj.response_allowed,
            "quality_of_service": obj.proposed_quality_of_service,
        }
    if isinstance(obj, xdlms.InitiateResponse):
        return {
            "kind": "initiate-response",
            "conformance": conformance(obj.negotiated_conformance),
            "max_receive_pdu_size": obj.server_max_receive_pdu_size,
            "dlms_version": obj.negotiated_dlms_version_number,
        }
    raise Unsupported(type(obj).__name__)


def user_info(ui) -> str:
    # dlms-cosem keeps the parsed xDLMS-Initiate object, not the octets: re-encode it.
    return "" if ui is None else ui.content.to_bytes().hex()


def apdu_json(obj) -> dict:  # noqa: C901 - one branch per APDU class
    if obj is None:
        raise ValueError("dlms-cosem's factory returned no APDU")
    if isinstance(obj, get.GetRequestNormal):
        return {
            "kind": "get-request-normal",
            "invoke_id": iid(obj),
            "attribute": attribute(obj.cosem_attribute),
            "access": access(obj.access_selection),
        }
    if isinstance(obj, get.GetRequestNext):
        return {"kind": "get-request-next", "invoke_id": iid(obj), "block_number": obj.block_number}
    if isinstance(obj, get.GetRequestWithList):
        return {
            "kind": "get-request-with-list",
            "invoke_id": iid(obj),
            "items": [
                [attribute(x.attribute), access(x.access_selection)]
                for x in obj.cosem_attributes_with_selection
            ],
        }
    if isinstance(obj, get.GetResponseNormal):
        result = with_data({"kind": "get-data-result", "error": None}, "data", obj.data)
        return {"kind": "get-response-normal", "invoke_id": iid(obj), "result": result}
    if isinstance(obj, get.GetResponseNormalWithError):
        result = {"kind": "get-data-result", "data": None, "error": int(obj.error)}
        return {"kind": "get-response-normal", "invoke_id": iid(obj), "result": result}
    if isinstance(obj, (get.GetResponseWithBlock, get.GetResponseLastBlock)):
        return {
            "kind": "get-response-with-datablock",
            "invoke_id": iid(obj),
            "last_block": isinstance(obj, get.GetResponseLastBlock),
            "block_number": obj.block_number,
            "raw_data": bytes(obj.data).hex(),
            "error": None,
        }
    if isinstance(obj, get.GetResponseLastBlockWithError):
        return {
            "kind": "get-response-with-datablock",
            "invoke_id": iid(obj),
            "last_block": True,
            "block_number": obj.block_number,
            "raw_data": None,
            "error": int(obj.error),
        }
    if isinstance(obj, get.GetResponseWithList):
        results = []
        for x in obj.response_data:
            if isinstance(x, enumerations.DataAccessResult):
                results.append({"kind": "get-data-result", "data": None, "error": int(x)})
            else:
                try:
                    results.append({"kind": "get-data-result", "data": tree(x), "error": None})
                except Unsupported:
                    results.append({"kind": "get-data-result", "error": None})
        return {"kind": "get-response-with-list", "invoke_id": iid(obj), "results": results}
    if isinstance(obj, set_mod.SetRequestNormal):
        out = {
            "kind": "set-request-normal",
            "invoke_id": iid(obj),
            "attribute": attribute(obj.cosem_attribute),
            "access": access(obj.access_selection),
        }
        return with_data(out, "value", obj.data)
    if isinstance(obj, set_mod.SetResponseNormal):
        return {"kind": "set-response-normal", "invoke_id": iid(obj), "result": int(obj.result)}
    if isinstance(obj, action.ActionRequestNormal):
        out = {
            "kind": "action-request-normal",
            "invoke_id": iid(obj),
            "method": method(obj.cosem_method),
        }
        if obj.data is None:
            out["parameters"] = None
            return out
        return with_data(out, "parameters", obj.data)
    if isinstance(obj, action.ActionResponseNormalWithData):
        out = {"kind": "action-response-normal", "invoke_id": iid(obj), "result": int(obj.status)}
        rd = with_data({"kind": "get-data-result", "error": None}, "data", obj.data)
        out["return_data"] = rd
        return out
    if isinstance(obj, action.ActionResponseNormalWithError):
        return {
            "kind": "action-response-normal",
            "invoke_id": iid(obj),
            "result": int(obj.status),
            "return_data": {"kind": "get-data-result", "data": None, "error": int(obj.error)},
        }
    if isinstance(obj, action.ActionResponseNormal):
        return {
            "kind": "action-response-normal",
            "invoke_id": iid(obj),
            "result": int(obj.status),
            "return_data": None,
        }
    if isinstance(obj, xdlms.DataNotification):
        try:
            return {"kind": "data-notification", **notification(obj)}
        except (Unsupported, NotImplementedError):
            return {"kind": "data-notification", "long_invoke_id": long_iid(obj)}
    if isinstance(obj, xdlms.ExceptionResponse):
        return {
            "kind": "exception-response",
            "state_error": int(obj.state_error),
            "service_error": int(obj.service_error),
            "invocation_counter": obj.invocation_counter_data,
        }
    if isinstance(obj, xdlms.ConfirmedServiceError):
        # dlms-cosem keeps only the error enum; the ConfirmedServiceError CHOICE
        # (initiate/read/write) is consumed and dropped, so "service" is omitted.
        types = [k for k, v in ErrorFactory.ERROR_TYPE_MAP.items() if v is type(obj.error)]
        return {"kind": "confirmed-service-error", "error_type": types[0], "value": int(obj.error)}
    if isinstance(obj, (xdlms.InitiateRequest, xdlms.InitiateResponse)):
        return initiate(obj)
    if isinstance(obj, acse.ApplicationAssociationRequest):
        return {
            "kind": "aarq",
            "application_context": 3 if obj.ciphered else 1,
            "mechanism": None if obj.authentication is None else int(obj.authentication),
            "calling_authentication_value": (
                obj.authentication_value.hex() if obj.authentication_value else None
            ),
            "calling_ap_title": obj.system_title.hex() if obj.system_title else None,
            "user_information": user_info(obj.user_information),
        }
    if isinstance(obj, acse.ApplicationAssociationResponse):
        diag = obj.result_source_diagnostics
        source = 2 if isinstance(diag, enumerations.AcseServiceProviderDiagnostics) else 1
        return {
            "kind": "aare",
            "application_context": 3 if obj.ciphered else 1,
            "result": int(obj.result),
            "diagnostic_source": source,
            "diagnostic": int(diag),
            "responding_ap_title": obj.system_title.hex() if obj.system_title else None,
            "mechanism": None if obj.authentication is None else int(obj.authentication),
            "responding_authentication_value": (
                obj.authentication_value.hex() if obj.authentication_value else None
            ),
            "user_information": user_info(obj.user_information),
        }
    if isinstance(obj, (acse.ReleaseRequest, acse.ReleaseResponse)):
        return {
            "kind": "rlrq" if isinstance(obj, acse.ReleaseRequest) else "rlre",
            "reason": None if obj.reason is None else int(obj.reason),
            "user_information": user_info(obj.user_information),
        }
    raise Unsupported(f"no JSON mapping for {type(obj).__name__}")


def decode_apdu(raw: bytes):
    try:
        return XDlmsApduFactory.apdu_from_bytes(raw)
    except KeyError as exc:
        if "not available in DLMS APDU Factory" in str(exc):
            raise Unsupported(str(exc)) from exc
        raise
    except ValueError as exc:
        # dlms-cosem is Logical-Name only and says so; that is a missing feature.
        if "Short Name" in str(exc):
            raise Unsupported(str(exc)) from exc
        raise


def op_apdu(hex_: str) -> dict:
    return apdu_json(decode_apdu(bytes.fromhex(hex_)))


# --- push / decrypt ---------------------------------------------------------------------


def plaintext(raw: bytes, ek: bytes, ak: bytes) -> bytes:
    obj = decode_apdu(raw)
    if not isinstance(obj, xdlms.GeneralGlobalCipher):
        raise Unsupported(f"dlms-cosem cannot decipher {type(obj).__name__}")
    return obj.to_plain_apdu(ek, ak)


def op_push(hex_: str, ek: str = "", ak: str = "") -> dict:
    raw = bytes.fromhex(hex_)
    if raw[:1] == b"\xdb":
        raw = plaintext(raw, bytes.fromhex(ek), bytes.fromhex(ak))
    obj = decode_apdu(raw)
    if not isinstance(obj, xdlms.DataNotification):
        raise ValueError(f"not a DataNotification: {type(obj).__name__}")
    return notification(obj)


def notification(obj) -> dict:
    """DataNotification fields; ``body`` before ``date_time`` so a lossy date-time
    (dlms-cosem keeps a datetime and drops the clock status) does not hide a body diff
    in the first-difference report."""
    body, used = parse_one(obj.body)
    if used != len(obj.body):
        raise ValueError(f"{len(obj.body) - used} octets after the notification body")
    date_time = None
    if obj.date_time is not None:
        date_time = time.datetime_to_bytes(obj.date_time).hex()
    return {"long_invoke_id": long_iid(obj), "body": tree(body), "date_time": date_time}


def op_decrypt(ek: str, ak: str, title: str, hex_: str) -> dict:
    del title  # general-glo-ciphering carries its own system title
    return {"plaintext": plaintext(bytes.fromhex(hex_), bytes.fromhex(ek), bytes.fromhex(ak)).hex()}


OPS = ["data", "encode-data", "apdu", "push", "decrypt"]


def answer(line: str) -> dict:
    op, _, rest = line.strip().partition(" ")
    args = rest.split()
    try:
        if op == "hello":
            commit = open("/etc/dlms-cosem-commit").read().strip()  # noqa: SIM115
            return {
                "ok": True,
                "library": "dlms-cosem",
                "version": f"{version('dlms-cosem')}+{commit[:7]}",
                "ops": OPS,
            }
        if op == "data":
            return {"ok": True, "result": op_data(args[0])}
        if op == "encode-data":
            return {"ok": True, "result": op_encode_data(json.loads(rest))}
        if op == "apdu":
            return {"ok": True, "result": op_apdu(args[0])}
        if op == "push":
            return {"ok": True, "result": op_push(*args)}
        if op == "decrypt":
            return {"ok": True, "result": op_decrypt(*args)}
        return {"ok": False, "unsupported": True, "error": f"unknown op {op}"}
    except (Unsupported, NotImplementedError) as exc:
        return {"ok": False, "unsupported": True, "error": f"{type(exc).__name__}: {exc}"}
    except Exception as exc:  # noqa: BLE001 - every library failure is a rejection
        traceback.print_exc(file=sys.stderr)
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def main() -> None:
    for line in sys.stdin:
        if not line.strip():
            continue
        sys.stdout.write(json.dumps(answer(line)) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
