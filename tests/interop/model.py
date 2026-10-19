"""pydlms's side of the oracle protocol: the reference JSON model (PROTOCOL.md)."""

from __future__ import annotations

import dataclasses
import enum
import struct

from pydlms.cosem.data import CompactArray, DlmsData, TypeDescription, decode_data, encode_data
from pydlms.cosem.enums import DataType
from pydlms.exceptions import DlmsError
from pydlms.obis import ObisCode

TYPE_NAMES = {
    DataType.NULL: "null-data",
    DataType.ARRAY: "array",
    DataType.STRUCTURE: "structure",
    DataType.BOOLEAN: "boolean",
    DataType.BIT_STRING: "bit-string",
    DataType.DOUBLE_LONG: "double-long",
    DataType.DOUBLE_LONG_UNSIGNED: "double-long-unsigned",
    DataType.OCTET_STRING: "octet-string",
    DataType.VISIBLE_STRING: "visible-string",
    DataType.UTF8_STRING: "utf8-string",
    DataType.BCD: "bcd",
    DataType.INTEGER: "integer",
    DataType.LONG: "long",
    DataType.UNSIGNED: "unsigned",
    DataType.LONG_UNSIGNED: "long-unsigned",
    DataType.COMPACT_ARRAY: "compact-array",
    DataType.LONG64: "long64",
    DataType.LONG64_UNSIGNED: "long64-unsigned",
    DataType.ENUM: "enum",
    DataType.FLOAT32: "float32",
    DataType.FLOAT64: "float64",
    DataType.DATE_TIME: "date-time",
    DataType.DATE: "date",
    DataType.TIME: "time",
    DataType.DONT_CARE: "dont-care",
    DataType.DELTA_INTEGER: "delta-integer",
    DataType.DELTA_LONG: "delta-long",
    DataType.DELTA_DOUBLE_LONG: "delta-double-long",
    DataType.DELTA_UNSIGNED: "delta-unsigned",
    DataType.DELTA_LONG_UNSIGNED: "delta-long-unsigned",
    DataType.DELTA_DOUBLE_LONG_UNSIGNED: "delta-double-long-unsigned",
}
BY_NAME = {name: tag for tag, name in TYPE_NAMES.items()}
_BYTES = {DataType.OCTET_STRING, DataType.DATE_TIME, DataType.DATE, DataType.TIME}


def description_json(desc: TypeDescription) -> dict:
    out: dict = {"t": TYPE_NAMES[desc.tag]}
    if desc.tag == DataType.STRUCTURE:
        out["members"] = [description_json(m) for m in desc.members]
    elif desc.tag == DataType.ARRAY and desc.array_of is not None:
        out["count"], of = desc.array_of
        out["of"] = description_json(of)
    return out


def json_description(obj: dict) -> TypeDescription:
    tag = BY_NAME[obj["t"]]
    if tag == DataType.STRUCTURE:
        return TypeDescription(tag, members=tuple(json_description(m) for m in obj["members"]))
    if tag == DataType.ARRAY:
        return TypeDescription(tag, array_of=(obj["count"], json_description(obj["of"])))
    return TypeDescription(tag)


def data_json(item: DlmsData) -> dict:
    tag, value = item.tag, item.value
    name = TYPE_NAMES[tag]
    if tag in (DataType.NULL, DataType.DONT_CARE):
        return {"t": name, "v": None}
    if tag in (DataType.ARRAY, DataType.STRUCTURE):
        return {"t": name, "v": [data_json(v) for v in value]}
    if tag == DataType.COMPACT_ARRAY:
        compact: CompactArray = value
        return {
            "t": name,
            "v": {
                "description": description_json(compact.description),
                "items": [data_json(v) for v in compact.items],
            },
        }
    if tag in _BYTES:
        return {"t": name, "v": bytes(value).hex()}
    if tag == DataType.BIT_STRING:
        return {"t": name, "v": "".join("1" if b else "0" for b in value)}
    if tag == DataType.FLOAT32:
        return {"t": name, "v": struct.pack(">f", value).hex()}
    if tag == DataType.FLOAT64:
        return {"t": name, "v": struct.pack(">d", value).hex()}
    if tag == DataType.BOOLEAN:
        return {"t": name, "v": bool(value)}
    if tag in (DataType.VISIBLE_STRING, DataType.UTF8_STRING):
        return {"t": name, "v": value}
    return {"t": name, "v": int(value)}


def json_data(obj: dict) -> DlmsData:
    tag = BY_NAME[obj["t"]]
    v = obj.get("v")
    if tag in (DataType.NULL, DataType.DONT_CARE):
        return DlmsData(tag)
    if tag in (DataType.ARRAY, DataType.STRUCTURE):
        return DlmsData(tag, [json_data(x) for x in v])
    if tag == DataType.COMPACT_ARRAY:
        return DlmsData(
            tag,
            CompactArray(json_description(v["description"]), [json_data(x) for x in v["items"]]),
        )
    if tag in _BYTES:
        return DlmsData(tag, bytes.fromhex(v))
    if tag == DataType.BIT_STRING:
        return DlmsData(tag, [c == "1" for c in v])
    if tag == DataType.FLOAT32:
        return DlmsData(tag, struct.unpack(">f", bytes.fromhex(v))[0])
    if tag == DataType.FLOAT64:
        return DlmsData(tag, struct.unpack(">d", bytes.fromhex(v))[0])
    return DlmsData(tag, v)


def _value_json(value):
    if isinstance(value, DlmsData):
        return data_json(value)
    if isinstance(value, ObisCode):
        return str(value)
    if isinstance(value, enum.Enum):
        return int(value.value)
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if dataclasses.is_dataclass(value):
        return _object_json(value)
    if isinstance(value, (list, tuple)):
        return [_value_json(v) for v in value]
    return value


def _object_json(obj) -> dict:
    out = {"kind": _kind(type(obj).__name__)}
    for f in dataclasses.fields(obj):
        out[f.name] = _value_json(getattr(obj, f.name))
    return out


def _kind(name: str) -> str:
    chars = []
    for i, ch in enumerate(name):
        if ch.isupper() and i and (name[i - 1].islower() or name[i - 1].isdigit()):
            chars.append("-")
        chars.append(ch.lower())
    return "".join(chars)


def apdu_json(apdu: bytes) -> dict:
    """Decode a plaintext APDU with pydlms into the protocol's JSON model."""
    from pydlms.apduxml import _decode_plain

    return _object_json(_decode_plain(apdu))


# --- the ops, as pydlms answers them ----------------------------------------------------


def op_data(hex_: str) -> dict:
    raw = bytes.fromhex(hex_)
    item, end = decode_data(raw)
    if end != len(raw):
        raise DlmsError(f"{len(raw) - end} trailing octets")
    return data_json(item)


def op_encode_data(obj: dict) -> dict:
    return {"hex": encode_data(json_data(obj)).hex()}


def op_apdu(hex_: str) -> dict:
    return apdu_json(bytes.fromhex(hex_))


def _key(value: str | None) -> str:
    """A key argument; ``-`` (or nothing) means absent (PROTOCOL.md)."""
    return "" if value in (None, "-") else value


def op_push(hex_: str, ek: str | None = None, ak: str | None = None) -> dict:
    from pydlms.apdu.xdlms import DataNotification, decode_apdu
    from pydlms.security.ciphering import is_ciphered_apdu

    apdu = bytes.fromhex(hex_)
    if is_ciphered_apdu(apdu):
        apdu = op_decrypt_bytes(_key(ek), _key(ak), None, apdu)
    obj = decode_apdu(apdu)
    if not isinstance(obj, DataNotification):
        raise DlmsError(f"not a DataNotification: {type(obj).__name__}")
    return {
        "long_invoke_id": obj.long_invoke_id,
        "date_time": obj.date_time.hex() if obj.date_time else None,
        "body": data_json(obj.body),
    }


def op_decrypt_bytes(ek: str, ak: str, title: str | None, apdu: bytes) -> bytes:
    """Decipher like the analysis tools do (``pydlms decode``): the keys
    decide, not a client policy, so ``strict=False``. The encryption key also
    serves as the dedicated key for ded- envelopes and as the broadcast key
    for content whose security control has bit 6 set."""
    from pydlms.security.ciphering import unwrap
    from pydlms.security.context import SecurityContext

    ek, ak = _key(ek), _key(ak)
    title = None if title in (None, "-") else title
    ctx = SecurityContext(
        bytes.fromhex(ek),
        bytes.fromhex(ak) if ak else None,
        server_system_title=bytes.fromhex(title) if title else None,
        allow_unverified_auth=not ak,
        replay_protection=False,
        broadcast_key=bytes.fromhex(ek),
    )
    ctx.set_dedicated_key(bytes.fromhex(ek))
    return unwrap(ctx, apdu, strict=False).plaintext


def op_decrypt(ek: str, ak: str, title: str, hex_: str) -> dict:
    return {"plaintext": op_decrypt_bytes(ek, ak, title, bytes.fromhex(hex_)).hex()}


def op_compact_data(template_hex: str, buffer_hex: str = "-") -> dict:
    """``compact-data``: the captures in a Compact data (IC 62) buffer.
    pydlms decodes exactly one capture (``-`` is an empty buffer)."""
    from pydlms.cosem.compact_data import decode_compact_buffer

    template = b"" if template_hex == "-" else bytes.fromhex(template_hex)
    buffer = b"" if buffer_hex == "-" else bytes.fromhex(buffer_hex)
    cells = decode_compact_buffer(template, buffer)
    return {"captures": [data_json(DlmsData.structure(cells))]}


def answer(line: str) -> dict:
    """pydlms's answer to one protocol line (used as the reference side)."""
    import json

    op, _, rest = line.strip().partition(" ")
    args = rest.split()
    try:
        if op == "hello":
            from pydlms import __version__

            return {
                "ok": True,
                "library": "pydlms",
                "version": __version__,
                "ops": ["data", "encode-data", "apdu", "push", "decrypt", "compact-data"],
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
        if op == "compact-data":
            return {"ok": True, "result": op_compact_data(*args)}
        return {"ok": False, "unsupported": True, "error": f"unknown op {op}"}
    except (DlmsError, ValueError, KeyError, IndexError, NotImplementedError) as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
