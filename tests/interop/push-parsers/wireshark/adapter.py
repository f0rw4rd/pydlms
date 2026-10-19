"""Oracle adapter (tests/interop/PROTOCOL.md) around Wireshark's DLMS dissector.

One long-lived ``tshark -r - -T pdml`` reads a pcap stream on its stdin. Each
request becomes one UDP packet to port 4059 carrying a DLMS wrapper frame;
the PDML of that packet is mapped back onto the JSON model. Only what the
dissector itself exposes is reported (labels, field values, the byte ranges
it assigns to each item); fields it does not dissect are left out, which the
protocol's subset comparison allows.

``data <hex>`` is wrapped as get-response-normal (``c4 01 c1 00 <data>``)
because the dissector decodes Data only inside an APDU.
"""

from __future__ import annotations

import json
import re
import struct
import subprocess
import sys
import xml.etree.ElementTree as ET

ETH = b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02\x08\x00"
FRAME_HEADER = len(ETH) + 20 + 8  # where the UDP payload starts
WRAPPER = 8
APDU_START = FRAME_HEADER + WRAPPER


class Rejected(Exception):
    pass


class Unsupported(Exception):
    pass


class Tshark:
    def __init__(self) -> None:
        self.proc = subprocess.Popen(  # noqa: S603,S607 - fixed argv
            ["tshark", "-l", "-n", "-r", "-", "-T", "pdml"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        self.proc.stdin.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        self.proc.stdin.flush()
        self.count = 0

    def dissect(self, apdu: bytes) -> tuple[ET.Element, bytes]:
        self.count += 1
        payload = b"\x00\x01\x00\x01\x00\x10" + struct.pack(">H", len(apdu)) + apdu
        udp = struct.pack("!HHHH", 4059, 50000, 8 + len(payload), 0) + payload
        ip = struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0, b"\n\0\0\2", b"\n\0\0\1"
        )
        frame = ETH + ip + udp
        record = struct.pack("<IIII", self.count, 0, len(frame), len(frame)) + frame
        self.proc.stdin.write(record)
        self.proc.stdin.flush()
        lines = []
        while True:
            line = self.proc.stdout.readline().decode("utf-8", "replace")
            if not line:
                raise RuntimeError("tshark exited")
            if line.lstrip().startswith("<packet>"):
                lines = []
            lines.append(line)
            if "</packet>" in line:
                break
        return ET.fromstring("".join(lines)), frame

    def close(self) -> None:
        self.proc.stdin.close()
        self.proc.wait(timeout=10)


def dissect(shark: Tshark, apdu: bytes) -> tuple[ET.Element, bytes]:
    """Dissect one APDU; datablocks again in a fresh tshark if that matters.

    The dissector keys its datablock reassembly on a constant (no addresses),
    so a block can be joined with blocks of an earlier, unrelated request in
    the same tshark run. Such a packet is re-dissected on its own.
    """
    packet, frame = shark.dissect(apdu)
    tainted = any(e.get("name") == "dlms.fragments" for e in packet.iter()) or any(
        e.get("show") == "Reassembled Data" for e in packet.iter()
    )
    if tainted:
        alone = Tshark()
        try:
            packet, frame = alone.dissect(apdu)
        finally:
            alone.close()
    return packet, frame


def tshark_version() -> str:
    out = subprocess.run(["tshark", "-v"], capture_output=True, text=True, check=False)  # noqa: S603,S607
    first = out.stdout.splitlines()[0] if out.stdout else "?"
    match = re.search(r"(\d+\.\d+\.\d+)", first)
    return match.group(1) if match else first


# --- PDML helpers ---------------------------------------------------------------------------


def children(el: ET.Element) -> list[ET.Element]:
    return [c for c in el if c.tag in ("field", "proto")]


def label(el: ET.Element) -> str:
    return el.get("showname") or el.get("show") or ""


def find_all(el: ET.Element, name: str) -> list[ET.Element]:
    return [f for f in el.iter() if f.get("name") == name]


def first(el: ET.Element, name: str) -> ET.Element | None:
    found = find_all(el, name)
    return found[0] if found else None


def span(frame: bytes, el: ET.Element) -> bytes:
    pos, size = int(el.get("pos", "0")), int(el.get("size", "0"))
    return frame[pos : pos + size]


def paren_int(text: str) -> int:
    match = re.search(r"\((\d+)\)\s*$", text)
    if not match:
        raise Rejected(f"no value in {text!r}")
    return int(match.group(1))


def ber_length(raw: bytes, pos: int) -> tuple[int, int]:
    first_octet = raw[pos]
    if first_octet < 0x80:
        return first_octet, pos + 1
    n = first_octet & 0x7F
    return int.from_bytes(raw[pos + 1 : pos + 1 + n], "big"), pos + 1 + n


# --- Data ------------------------------------------------------------------------------------

INT_LABELS = {
    "Double Long": "double-long",
    "Double Long Unsigned": "double-long-unsigned",
    "Integer": "integer",
    "Long": "long",
    "Unsigned": "unsigned",
    "Long Unsigned": "long-unsigned",
    "Long64": "long64",
    "Long64 Unsigned": "long64-unsigned",
    "Enum": "enum",
}


def data_tree(el: ET.Element, frame: bytes) -> dict:
    """A ``dlms.data`` item -> data tree, from its label and its byte range."""
    text = re.sub(r"^\[\d+\] ", "", label(el))
    raw = span(frame, el)
    subs = [c for c in children(el) if c.get("name") == "dlms.data"]
    if text == "Null":
        return {"t": "null-data", "v": None}
    if text.startswith("Array ("):
        return {"t": "array", "v": [data_tree(c, frame) for c in subs]}
    if text == "Structure":
        return {"t": "structure", "v": [data_tree(c, frame) for c in subs]}
    if text.startswith("Compact Array ("):
        return {"t": "compact-array", "v": {"items": [data_tree(c, frame) for c in subs]}}
    if text.startswith("Boolean: "):
        return {"t": "boolean", "v": text.endswith("true")}
    if text.startswith("BCD: 0x"):
        return {"t": "bcd", "v": int(text[7:], 16)}
    if text.startswith("Bit-string (bits: "):
        bits = int(re.match(r"Bit-string \(bits: (\d+)", text).group(1))
        content = raw[len(raw) - (bits + 7) // 8 :] if bits else b""
        value = "".join(f"{b:08b}" for b in content)[:bits]
        return {"t": "bit-string", "v": value}
    for prefix, name in (
        ("Octet String (length ", "octet-string"),
        ("Visible String (length ", "visible-string"),
        ("UTF8 String (length ", "utf8-string"),
    ):
        if text.startswith(prefix):
            n = int(re.match(r"[^(]*\(length (\d+)\)", text).group(1))
            content = raw[len(raw) - n :] if n else b""
            if len(content) != n:
                raise Rejected(f"{name} of {n} octets but the item spans {len(raw)}")
            if name == "octet-string":
                return {"t": name, "v": content.hex()}
            return {"t": name, "v": content.decode("utf-8" if name == "utf8-string" else "latin-1")}
    for prefix, name, size in (
        ("Float32: ", "float32", 4),
        ("Float64: ", "float64", 8),
        ("Date Time", "date-time", 12),
        ("Date", "date", 5),
        ("Time", "time", 4),
    ):
        if text.startswith(prefix):
            if len(raw) != 1 + size:
                raise Rejected(f"{name} item spans {len(raw)} octets")
            return {"t": name, "v": raw[1:].hex()}
    match = re.match(r"^([A-Za-z0-9 ]+): (-?\d+)$", text)
    if match and match.group(1) in INT_LABELS:
        return {"t": INT_LABELS[match.group(1)], "v": int(match.group(2))}
    raise Rejected(f"dissector label {text!r}")


def data_under(parent: ET.Element | None, frame: bytes) -> dict | None:
    if parent is None:
        return None
    items = [c for c in children(parent) if c.get("name") == "dlms.data"]
    return data_tree(items[0], frame) if items else None


def text_node(cosem: ET.Element, show: str) -> ET.Element | None:
    for c in children(cosem):
        if c.get("name") == "" and c.get("show") == show:
            return c
    return None


# --- APDU ------------------------------------------------------------------------------------

SUB_CHOICE = {
    192: "dlms.get_request",
    193: "dlms.set_request",
    195: "dlms.action_request",
    196: "dlms.get_response",
    197: "dlms.set_response",
    199: "dlms.action_response",
}
# APDU tags the dissector dissects although it names them "Unknown" / differently.
TAG_KINDS = {1: "initiate-request", 8: "initiate-response"}
NOT_DISSECTED = {5, 6, 12, 13, 14, 15, 22, 24}  # named or not, only the tag is shown


def check_errors(packet: ET.Element) -> None:
    for proto in packet.iter("proto"):
        if proto.get("name") == "_ws.malformed":
            raise Rejected("Malformed packet")
    for field in packet.iter("field"):
        if field.get("name") in (
            "dlms.planar_type",
            "dlms.compact_array.bad",
            "dlms.access_request_choice",
        ):
            raise Rejected(label(field))


def descriptor(cosem: ET.Element, title: str, kind: str, last: str) -> dict | None:
    node = text_node(cosem, title)
    if node is None:
        return None
    out = {
        "kind": kind,
        "class_id": paren_int(label(first(node, "dlms.class_id"))),
        "instance_id": re.search(r"\(([\d.]+)\)\s*$", label(first(node, "dlms.instance_id"))).group(
            1
        ),
    }
    out[last] = paren_int(label(first(node, f"dlms.{last}")))
    return out


def access(cosem: ET.Element, frame: bytes) -> dict | None:
    node = text_node(cosem, "Selective Access Descriptor")
    if node is None:
        return None
    selector = int(first(node, "dlms.access_selector").get("show"))
    if not selector:
        return None
    return {"kind": "selective-access", "selector": selector, "parameters": data_under(node, frame)}


def datablock(cosem: ET.Element, frame: bytes, title: str) -> dict:
    node = text_node(cosem, title)
    out: dict = {}
    if node is None:
        return out
    last = first(node, "dlms.last_block")
    if last is not None:
        out["last_block"] = last.get("show") in ("1", "True")
    number = first(node, "dlms.block_number")
    if number is not None:
        out["block_number"] = int(number.get("show"))
    raw = [c for c in children(node) if c.get("name") == "dlms.data"]
    if raw:
        content = span(frame, raw[0])
        n, pos = ber_length(content, 0)
        out["raw_data"] = content[pos : pos + n].hex()
    result = first(node, "dlms.data_access_result")
    if result is not None:
        out["error"] = int(result.get("show"))
    return out


def oid_arc(el: ET.Element | None) -> int | None:
    return int(el.get("show").rsplit(".", 1)[1]) if el is not None else None


def acse(cosem: ET.Element, kind: str) -> dict:
    out: dict = {"kind": kind}
    if kind in ("aarq", "aare"):
        name = "cosem.application_context_name" if kind == "aarq" else "cosem.aSO_context_name"
        out["application_context"] = oid_arc(first(cosem, name))
        mech = first(cosem, "cosem.mechanism_name")
        if mech is not None:
            out["mechanism"] = oid_arc(mech)
    if kind == "aare":
        out["result"] = int(first(cosem, "cosem.result").get("show"))
        diag = first(cosem, "cosem.result_source_diagnostic")
        if diag is not None:
            out["diagnostic_source"] = int(diag.get("show"))
            inner = children(diag)
            if inner:
                out["diagnostic"] = int(inner[0].get("show"))
    if kind in ("rlrq", "rlre"):
        reason = first(cosem, "cosem.reason")
        if reason is not None:
            out["reason"] = int(reason.get("show"))
    info = first(cosem, "cosem.user_information")
    if info is not None:
        out["user_information"] = info.get("value", "")
    return out


def initiate(cosem: ET.Element, kind: str) -> dict:
    out: dict = {"kind": kind}
    for name, key in (
        ("dlms.proposed_dlms_version_number", "dlms_version"),
        ("dlms.negotiated_dlms_version_number", "dlms_version"),
        ("dlms.client_max_receive_pdu_size", "max_receive_pdu_size"),
        ("dlms.server_max_receive_pdu_size", "max_receive_pdu_size"),
        ("dlms.objectname", "vaa_name"),
    ):
        el = first(cosem, name)
        if el is not None:
            out[key] = int(el.get("show"))
    conformance = first(cosem, "cosem.Conformance")
    if conformance is not None:
        out["conformance"] = int(conformance.get("value"), 16)
    return out


def apdu_json(packet: ET.Element, frame: bytes) -> dict:
    check_errors(packet)
    cosem = next((p for p in packet.iter("proto") if p.get("name") == "cosem"), None)
    if cosem is None:
        raise Rejected("no cosem layer")
    tag_el = first(cosem, "dlms.apdu")
    tag = int(tag_el.get("show"))
    name = re.match(r"APDU: (.*) \(\d+\)$", label(tag_el)).group(1)
    if tag in SUB_CHOICE:
        sub = first(cosem, SUB_CHOICE[tag])
        kind = re.match(r"[^:]*: (.*) \(\d+\)$", label(sub)).group(1)
        if kind.startswith("Unknown"):
            raise Unsupported(f"dissector has no name for {name} choice {sub.get('show')}")
    elif tag in TAG_KINDS:
        kind = TAG_KINDS[tag]
    elif name.startswith("Unknown"):
        raise Unsupported(f"dissector does not know APDU tag {tag}")
    else:
        kind = re.sub(r"(?<=[a-z])(?=[A-Z])", "-", name).lower()  # "ReadRequest"
    out: dict = {"kind": kind}
    inv = first(cosem, "dlms.invoke_id")
    if inv is not None:
        out["invoke_id"] = int(inv.get("unmaskedvalue") or inv.get("value"), 16)
    if tag in NOT_DISSECTED:
        return out
    if kind in ("aarq", "aare", "rlrq", "rlre"):
        return acse(cosem, kind)
    if kind in TAG_KINDS.values():
        return initiate(cosem, kind)
    attr = descriptor(cosem, "COSEM Attribute Descriptor", "attribute-descriptor", "attribute_id")
    meth = descriptor(cosem, "COSEM Method Descriptor", "method-descriptor", "method_id")
    data = data_under(text_node(cosem, "Data"), frame)
    if kind in ("get-request-normal", "set-request-normal", "set-request-with-first-datablock"):
        out["attribute"] = attr
        out["access"] = access(cosem, frame)
    if kind == "get-request-next" or kind == "set-response-datablock":
        out["block_number"] = int(first(cosem, "dlms.block_number").get("show"))
    if kind == "set-request-normal":
        out["value"] = data
    if kind in ("set-request-with-first-datablock", "set-request-with-datablock"):
        out.update(datablock(cosem, frame, "Datablock SA"))
    if kind == "get-response-normal":
        result = first(cosem, "dlms.data_access_result")
        if result is not None:
            out["result"] = {
                "kind": "get-data-result",
                "data": None,
                "error": int(result.get("show")),
            }
        else:
            out["result"] = {"kind": "get-data-result", "data": data, "error": None}
    if kind == "get-response-with-datablock":
        out.update(datablock(cosem, frame, "Datablock G"))
        if "error" in out:
            out["raw_data"] = None
        else:
            out["error"] = None
    if kind in ("set-response-normal", "set-response-last-datablock"):
        out["result"] = int(first(cosem, "dlms.data_access_result").get("show"))
    if kind == "set-response-last-datablock":
        out["block_number"] = int(first(cosem, "dlms.block_number").get("show"))
    if kind == "event-notification-request":
        out["attribute"] = attr
        out["value"] = data
    if kind == "action-request-normal":
        out["method"] = meth
        out["parameters"] = data
    if kind == "action-response-normal":
        out["result"] = int(first(cosem, "dlms.action_result").get("show"))
    if kind == "exception-response":
        out["state_error"] = int(first(cosem, "dlms.state_error").get("show"))
        out["service_error"] = int(first(cosem, "dlms.service_error").get("show"))
    return out


def op_data(shark: Tshark, raw: bytes) -> dict:
    packet, frame = dissect(shark, b"\xc4\x01\xc1\x00" + raw)
    check_errors(packet)
    cosem = next((p for p in packet.iter("proto") if p.get("name") == "cosem"), None)
    node = text_node(cosem, "Data") if cosem is not None else None
    items = [c for c in children(node) if c.get("name") == "dlms.data"] if node is not None else []
    if not items:
        raise Rejected("no Data item")
    end = int(items[0].get("pos")) + int(items[0].get("size")) - (APDU_START + 4)
    if end != len(raw):
        raise Rejected(f"dissector's Data item covers {end} of {len(raw)} octets")
    return data_tree(items[0], frame)


def main() -> int:
    shark = Tshark()
    version = tshark_version()
    for line in sys.stdin:
        op, _, rest = line.strip().partition(" ")
        args = rest.split()
        try:
            if op == "hello":
                reply = {
                    "ok": True,
                    "library": "wireshark packet-cosem (tshark)",
                    "version": version,
                    "ops": ["data", "apdu"],
                }
            elif op == "data":
                reply = {"ok": True, "result": op_data(shark, bytes.fromhex(args[0]))}
            elif op == "apdu":
                packet, frame = dissect(shark, bytes.fromhex(args[0]))
                reply = {"ok": True, "result": apdu_json(packet, frame)}
            else:
                raise Unsupported(f"op {op} not offered by the dissector adapter")
        except Unsupported as exc:
            reply = {"ok": False, "unsupported": True, "error": str(exc)}
        except (Rejected, ValueError, AttributeError, TypeError, IndexError) as exc:
            reply = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        sys.stdout.write(json.dumps(reply) + "\n")
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
