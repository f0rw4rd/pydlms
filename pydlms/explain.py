"""Annotated, layer-by-layer explanation of DLMS bytes (the ``pydlms decode`` tool).

:func:`explain` takes anything you captured - HDLC frames, M-Bus frames, a
TCP wrapper PDU or a bare APDU, as one buffer or several - and prints what
every layer means: frame fields and checksum verdicts, segmentation and
block-transfer reassembly, the security header (SC, IC, system title) and the
deciphered plaintext when keys are given, the decoded APDU, the COSEM data
tree with OBIS names, and finally the labelled push records.

Errors never stop the explanation: each layer reports what it could decode
and where it failed, which is the point when debugging a meter.
"""

from __future__ import annotations

from dataclasses import fields, is_dataclass

from pydlms.apdu.tags import Tag, tag_name
from pydlms.catalog import obis_name
from pydlms.cosem.data import DlmsData
from pydlms.cosem.enums import DataType, Unit, result_name
from pydlms.cosem.time import CosemDateTime
from pydlms.debug import hexstr
from pydlms.exceptions import DlmsError
from pydlms.obis import ObisCode

__all__ = ["explain", "format_data", "detect_framing"]


def detect_framing(data: bytes) -> str:
    if data[:1] == b"\x7e":
        return "hdlc"
    if data[:1] == b"\x68" and len(data) > 3 and data[3] == 0x68:
        return "mbus"
    from pydlms.mbus_link import starts_with_mbus_telegram

    if starts_with_mbus_telegram(data):
        return "mbus"
    if data[:2] == b"\x00\x01" and len(data) >= 8:
        length = int.from_bytes(data[6:8], "big")
        if length == len(data) - 8:
            return "wrapper"
    return "apdu"


def _ascii(raw: bytes) -> str:
    return "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in raw)


def _scalar(item: DlmsData) -> str:
    value = item.value
    tag = item.tag
    if tag == DataType.OCTET_STRING:
        raw = bytes(value)
        if len(raw) == 6:
            obis = ObisCode.from_bytes(raw)
            name = obis_name(obis)
            return f"{hexstr(raw)} = OBIS {obis}" + (f" ({name})" if name else "")
        if len(raw) == 12:
            try:
                return f"{hexstr(raw)} = {CosemDateTime.from_bytes(raw)}"
            except (DlmsError, ValueError):
                pass
        text = _ascii(raw)
        printable = sum(c != "." for c in text) >= max(1, len(raw) * 3 // 4)
        return hexstr(raw, 48) + (f' "{text}"' if printable and raw else "")
    if tag in (DataType.DATE_TIME,):
        return f"{hexstr(bytes(value))} = {CosemDateTime.from_bytes(bytes(value))}"
    if tag == DataType.ENUM:
        try:
            return f"{value} ({Unit(value).symbol or Unit(value).name})"
        except ValueError:
            return str(value)
    if tag == DataType.BIT_STRING:
        return "".join("1" if b else "0" for b in value)
    return repr(value)


def format_data(item: DlmsData, indent: str = "  ", label: str = "") -> list[str]:
    """Render a COSEM data tree, one line per node."""
    name = item.tag.name.lower().replace("_", "-")
    if item.tag in (DataType.ARRAY, DataType.STRUCTURE):
        lines = [f"{indent}{label}{name}[{len(item.value)}]"]
        for i, child in enumerate(item.value):
            lines += format_data(child, indent + "  ", f"[{i}] ")
        return lines
    if item.tag == DataType.COMPACT_ARRAY:
        lines = [
            f"{indent}{label}compact-array of {item.value.description.tag.name.lower()} "
            f"[{len(item.value.items)}]"
        ]
        for i, child in enumerate(item.value.items):
            lines += format_data(child, indent + "  ", f"[{i}] ")
        return lines
    return [f"{indent}{label}{name} {_scalar(item)}"]


def _long_invoke_id(value: int) -> str:
    """A Long-Invoke-Id-And-Priority with its fields spelled out."""
    from pydlms.apdu.xdlms import LongInvokeIdAndPriority

    f = LongInvokeIdAndPriority.from_int(value)
    return (
        f"0x{value:08X} (id {f.invoke_id}, {'high' if f.high_priority else 'normal'} priority, "
        f"{'confirmed' if f.confirmed else 'unconfirmed'}, "
        f"{'break' if f.processing_option else 'continue'} on error"
        f"{', self-descriptive' if f.self_descriptive else ''}"
        f"{f', reserved 0x{f.reserved:X}' if f.reserved else ''})"
    )


def _item(value) -> str:
    """One list entry of an APDU (an ACCESS specification or result)."""
    result = getattr(value, "result", None)
    if result is not None and getattr(value, "kind", None) is not None:
        return f"{value.kind.name.lower()} {result_name(result)}"
    return str(value)


def _describe_apdu(apdu) -> list[str]:
    if not is_dataclass(apdu):
        return [f"  {apdu!r}"]
    lines = [f"  {type(apdu).__name__}"]
    for f in fields(apdu):
        value = getattr(apdu, f.name)
        if isinstance(value, DlmsData):
            lines.append(f"    {f.name}:")
            lines += format_data(value, "      ")
        elif isinstance(value, bytes):
            lines.append(f"    {f.name}: {hexstr(value, 64)}")
        elif f.name == "invoke_id" and isinstance(value, int):
            lines.append(
                f"    invoke_id: 0x{value:02X} (id {value & 0x0F}, "
                f"{'high' if value & 0x80 else 'normal'} priority, "
                f"{'confirmed' if value & 0x40 else 'unconfirmed'})"
            )
        elif f.name == "long_invoke_id" and isinstance(value, int):
            lines.append(f"    long_invoke_id: {_long_invoke_id(value)}")
        elif isinstance(value, list) and any(isinstance(v, DlmsData) for v in value):
            lines.append(f"    {f.name}: {len(value)}")
            for index, item in enumerate(value):
                lines += format_data(item, "      ", f"[{index}] ")
        elif isinstance(value, list) and value and all(is_dataclass(v) for v in value):
            lines.append(f"    {f.name}: {len(value)}")
            lines += [f"      [{i}] {_item(v)}" for i, v in enumerate(value)]
        else:
            lines.append(f"    {f.name}: {value}")
    describe = getattr(apdu, "describe", None)
    if callable(describe):
        lines.append(f"    => {describe()}")
    return lines


class _Explainer:
    def __init__(
        self,
        encryption_key=None,
        authentication_key=None,
        verify_checksums=True,
        system_title=None,
        hdlc_modulus=8,
    ):
        from pydlms.hdlc.framing import HdlcModeTracker

        self.lines: list[str] = []
        #: HDLC numbering, followed across buffers: an SNRME answered by UA
        #: switches I and S frames to two-octet control fields.
        self.hdlc_mode = HdlcModeTracker(hdlc_modulus)
        self.security = None
        self.verify_checksums = verify_checksums
        if encryption_key:
            from pydlms.security.context import SecurityContext

            # Replay protection stays on: each APDU is explained once.
            self.security = SecurityContext(
                encryption_key,
                authentication_key,
                server_system_title=system_title,
                allow_unverified_auth=authentication_key is None,
            )

    def out(self, text: str = "") -> None:
        self.lines.append(text)

    # -- framing -------------------------------------------------------------------
    def hdlc(self, data: bytes) -> list[bytes]:
        from pydlms.hdlc.address import read_address
        from pydlms.hdlc.crc import crc16_x25
        from pydlms.hdlc.framing import FrameReader, strip_llc

        reader = FrameReader(verify_checksums=self.verify_checksums, tracker=self.hdlc_mode)
        frames = reader.feed(data)
        if reader.dropped:
            self.out(f"!! {reader.dropped} HDLC frame(s) dropped (bad checksum or malformed)")
        apdus = []
        buffer = bytearray()
        for n, frame in enumerate(frames, 1):
            raw = None
            self.out(f"== HDLC frame {n}: {frame.describe()}")
            fmt = None
            try:
                from pydlms.hdlc.framing import encode_frame

                raw = encode_frame(frame)
                fmt = int.from_bytes(raw[1:3], "big")
                pos = 3
                dest, pos = read_address(raw, pos)
                src, pos = read_address(raw, pos)
                self.out(
                    f"  format    {raw[1:3].hex(' ').upper()}  type 0xA, segmented="
                    f"{'yes' if fmt & 0x0800 else 'no'}, length {fmt & 0x7FF}"
                )
                self.out(
                    f"  dest      {raw[3 : 3 + len(dest.to_bytes())].hex(' ').upper()}  {dest}"
                )
                self.out(f"  src       {src.to_bytes().hex(' ').upper()}  {src}")
                control = frame.control_octets
                self.out(
                    f"  control   {control.hex(' ').upper()}  {frame.kind.name}"
                    f"{' P/F' if frame.poll_final else ''}"
                    f"{' (modulo 128)' if frame.extended else ''}"
                )
                if frame.info:
                    hcs = crc16_x25(raw[1 : pos + len(control)])
                    self.out(f"  HCS       {hcs.to_bytes(2, 'little').hex(' ').upper()}  ok")
                    llc = frame.info[:3]
                    note = (
                        " (LLC " + llc.hex(" ").upper() + ")"
                        if llc[:2] == b"\xe6\xe6" or llc[:2] == b"\xe6\xe7"
                        else ""
                    )
                    self.out(f"  info      {len(frame.info)} octets{note}")
            except DlmsError as exc:
                self.out(f"  (cannot re-render frame: {exc})")
            first = not buffer
            buffer += strip_llc(frame.info) if first else frame.info
            if frame.segmented:
                self.out("  -> segment; waiting for the rest")
                continue
            if buffer:
                apdus.append(bytes(buffer))
            buffer.clear()
        if buffer:
            self.out(f"!! incomplete segmented message ({len(buffer)} octets buffered)")
        return apdus

    def mbus(self, data: bytes) -> list[bytes]:
        from pydlms.mbus import HEADER_CI, MbusReader, decode_mbus_frame
        from pydlms.mbus_link import control_name, decode_link_frame

        pos = 0
        n = 0
        while pos < len(data):
            first = data[pos]
            if first == 0xE5:
                n += 1
                self.out(f"== M-Bus telegram {n}: E5 (single character acknowledgement)")
                pos += 1
                continue
            if first == 0x10 and pos + 5 <= len(data):
                n += 1
                try:
                    short = decode_link_frame(data[pos : pos + 5])
                except DlmsError as exc:
                    self.out(f"== M-Bus telegram {n}: {exc}")
                    break
                self.out(
                    f"== M-Bus telegram {n}: short frame C=0x{short.control:02X} "
                    f"({control_name(short.control)}) A=0x{short.address:02X} CS ok"
                )
                pos += 5
                continue
            if first != 0x68 or pos + 6 > len(data):
                break
            total = data[pos + 1] + 6
            raw = data[pos : pos + total]
            n += 1
            pos += total
            if len(raw) > 6 and not (raw[6] <= 0x1F or raw[6] in HEADER_CI):
                try:
                    link = decode_link_frame(raw)
                except DlmsError as exc:
                    self.out(f"== M-Bus frame {n}: {exc}")
                    continue
                self.out(
                    f"== M-Bus frame {n}: L={raw[1]} C=0x{link.control:02X} "
                    f"({control_name(link.control)}) A=0x{link.address:02X} CI=0x{link.ci:02X} "
                    f"(no DLMS data) CS ok, {len(link.data)} data octets"
                )
                continue
            try:
                frame = decode_mbus_frame(raw)
                header = frame.header
                if header is None:
                    form = f"segment {frame.sequence}{', final' if frame.final else ''}"
                else:
                    kind = "long" if header.long else "short"
                    form = f"{kind} header, {header.direction}, unsegmented"
                self.out(
                    f"== M-Bus frame {n}: L={raw[1]} C=0x{frame.control:02X} "
                    f"A=0x{frame.address:02X} CI=0x{frame.ci:02X} ({form}) STSAP={frame.stsap} "
                    f"DTSAP={frame.dtsap} CS ok, {len(frame.data)} data octets"
                )
                if header is not None and header.long:
                    self.out(
                        f"  ident {header.identification_number} manufacturer "
                        f"0x{header.manufacturer:04X} version {header.version} "
                        f"device type 0x{header.device_type:02X}"
                    )
                if header is not None:
                    self.out(
                        f"  ACC=0x{header.access_number:02X} STS=0x{header.status:02X} "
                        f"CF=0x{header.configuration:04X} (no M-Bus encryption)"
                    )
            except DlmsError as exc:
                self.out(f"== M-Bus frame {n}: {exc}")
        return MbusReader().feed(data)

    def wrapper(self, data: bytes) -> list[bytes]:
        from pydlms.wrapper import decode_wrapper

        pdu = decode_wrapper(data)
        self.out(
            f"== TCP/UDP wrapper: version 1, wPort {pdu.source} -> {pdu.destination}, "
            f"{len(pdu.apdu)} octets"
        )
        return [pdu.apdu]

    # -- APDU ------------------------------------------------------------------------
    def apdus(self, apdus: list[bytes]) -> None:
        from pydlms.apdu.gbt import GbtReassembler, decode_gbt

        gbt = GbtReassembler()
        for apdu in apdus:
            if apdu[:1] == bytes([Tag.GENERAL_BLOCK_TRANSFER]):
                block = decode_gbt(apdu)
                self.out(
                    f"== general-block-transfer block {block.block_number}"
                    f"{' (last)' if block.last else ''}: streaming={block.streaming} "
                    f"window={block.window} ack={block.block_number_ack} "
                    f"{len(block.data)} octets"
                )
                complete = gbt.add(block)
                if complete is None:
                    continue
                self.out(f"   -> reassembled {len(complete)} octets")
                apdu = complete
            self.apdu(apdu)

    def apdu(self, apdu: bytes) -> None:
        from pydlms.security.ciphering import is_ciphered_apdu

        self.out(f"== APDU {tag_name(apdu[0])} (0x{apdu[0]:02X}), {len(apdu)} octets")
        if is_ciphered_apdu(apdu):
            self.ciphered(apdu)
            return
        if apdu[0] in (Tag.AARQ, Tag.AARE, Tag.RLRQ, Tag.RLRE):
            from pydlms.apdu.acse import decode_acse

            acse = decode_acse(apdu)
            self.lines += _describe_apdu(acse)
            info = getattr(acse, "user_information", b"")
            if info:
                self.out("  user-information:")
                self.apdu(info)
            return
        if apdu[0] == Tag.DATA_NOTIFICATION:
            self.notification(apdu)
            return
        if apdu[0] in (
            Tag.READ_REQUEST,
            Tag.READ_RESPONSE,
            Tag.WRITE_REQUEST,
            Tag.WRITE_RESPONSE,
            Tag.INFORMATION_REPORT_REQUEST,
        ):
            from pydlms.apdu.sn import decode_sn_apdu

            self.lines += _describe_apdu(decode_sn_apdu(apdu))
            return
        from pydlms.apdu.xdlms import decode_apdu

        self.lines += _describe_apdu(decode_apdu(apdu, strict=False))

    def _general_header(self, apdu: bytes) -> int:
        """Print the five octet-string header fields of 0xDD/0xDF."""
        from pydlms.axdr import decode_length

        pos = 1
        for name in ("transaction-id", "originator", "recipient", "date-time", "other-info"):
            length, pos = decode_length(apdu, pos)
            value = apdu[pos : pos + length]
            shown = f'{hexstr(value)} "{_ascii(value)}"' if value else "(absent)"
            self.out(f"  {name:<13} {shown}")
            pos += length
        return pos

    def _key_info(self, apdu: bytes, pos: int) -> int:
        from pydlms.axdr import decode_length

        if apdu[pos] == 0:
            self.out("  key-info      absent (global unicast key)")
            return pos + 1
        choice = apdu[pos + 1]
        if choice == 0:
            self.out(
                f"  key-info      identified key-id {apdu[pos + 2]} "
                f"({'broadcast' if apdu[pos + 2] == 1 else 'unicast'})"
            )
            return pos + 3
        if choice == 1:
            length, start = decode_length(apdu, pos + 3)
            self.out(f"  key-info      wrapped key ({length} octets, KEK id {apdu[pos + 2]})")
            return start + length
        params_len, start = decode_length(apdu, pos + 2)
        scheme = apdu[start]
        data_len, data_at = decode_length(apdu, start + params_len)
        name = {1: "one-pass Diffie-Hellman", 2: "static unified model"}.get(scheme, scheme)
        self.out(f"  key-info      agreed key, {name}, {data_len} octets key data")
        return data_at + data_len

    def ciphered(self, apdu: bytes) -> None:
        from pydlms.axdr import decode_length
        from pydlms.security.suites import SecurityControl

        pos = 1
        if apdu[0] in (Tag.GENERAL_CIPHERING, Tag.GENERAL_SIGNING):
            pos = self._general_header(apdu)
            if apdu[0] == Tag.GENERAL_SIGNING:
                content_len, start = decode_length(apdu, pos)
                end = start + content_len
                if end < len(apdu):
                    sig_len, sig_at = decode_length(apdu, end)
                    self.out(f"  signature     {sig_len} octets (r||s)")
                else:
                    self.out("  signature     MISSING")
                self.out(f"  signed content {content_len} octets:")
                if self.security is not None and self.security.peer_signing_key is None:
                    self.out("  (signature not verified: no peer signing key given)")
                self.apdu(apdu[start:end])
                return
            pos = self._key_info(apdu, pos)
        if apdu[0] in (Tag.GENERAL_GLO_CIPHERING, Tag.GENERAL_DED_CIPHERING):
            title_len, pos = decode_length(apdu, 1)
            title = apdu[pos : pos + title_len]
            self.out(f'  system title  {hexstr(title)} "{_ascii(title)}"')
            pos += title_len
        length, pos = decode_length(apdu, pos)
        if pos + 5 <= len(apdu):
            sc = SecurityControl.from_byte(apdu[pos])
            ic = int.from_bytes(apdu[pos + 1 : pos + 5], "big")
            self.out(f"  {sc.describe()}")
            self.out(f"  invocation counter {ic} (0x{ic:08X})")
            self.out(f"  ciphered content {length - 5} octets")
        if self.security is None:
            self.out("  (no key given: pass --key / --auth-key to decipher)")
            return
        from pydlms.security.ciphering import unwrap

        if (
            apdu[0]
            not in (Tag.GENERAL_GLO_CIPHERING, Tag.GENERAL_DED_CIPHERING, Tag.GENERAL_CIPHERING)
            and self.security.server_system_title is None
        ):
            self.out("  (key-specific ciphering: pass --system-title of the sender to decipher)")
            return
        result = unwrap(self.security, apdu, strict=False)
        verdict = (
            "tag verified"
            if result.authenticated
            else (
                "NOT authenticated (no AK)"
                if result.security_control.authenticated
                else "no authentication in this mode"
            )
        )
        self.out(f"  -> deciphered {len(result.plaintext)} octets, {verdict}")
        self.apdu(result.plaintext)

    def notification(self, apdu: bytes) -> None:
        from pydlms.push import decode_notification

        note, records, complete = decode_notification(apdu)
        self.out(f"  long-invoke-id 0x{note.long_invoke_id:08X}")
        if note.date_time:
            stamp = note.timestamp
            self.out(
                f"  date-time     {hexstr(note.date_time)} = {stamp}"
                f"{' (Data-tagged 09 0C form)' if note.date_time_tagged else ''}"
            )
        if note.body.tag != DataType.NULL:
            self.out("  body:")
            self.lines += format_data(note.body, "    ")
        if not complete:
            self.out("  !! body damaged; records below are the intact prefix")
        self.out("== records")
        for record in records:
            name = obis_name(record.obis)
            self.out(f"  {record}" + (f"   [{name}]" if name else ""))

    def run(self, buffers: list[bytes], framing: str) -> str:
        for data in buffers:
            kind = detect_framing(data) if framing == "auto" else framing
            try:
                if kind == "hdlc":
                    apdus = self.hdlc(data)
                elif kind == "mbus":
                    apdus = self.mbus(data)
                elif kind == "wrapper":
                    apdus = self.wrapper(data)
                else:
                    apdus = [data]
                self.apdus(apdus)
            except DlmsError as exc:
                self.out(f"!! {type(exc).__name__}: {exc}")
            except (ValueError, NotImplementedError) as exc:
                self.out(f"!! cannot decode further: {exc}")
        return "\n".join(self.lines)


def explain(
    data: bytes | list[bytes],
    encryption_key: bytes | None = None,
    authentication_key: bytes | None = None,
    framing: str = "auto",
    verify_checksums: bool = True,
    system_title: bytes | None = None,
    hdlc_modulus: int = 8,
) -> str:
    """Return a multi-line explanation of ``data`` (see the module docstring).

    ``hdlc_modulus`` is the HDLC numbering the frames start in (8, or 128
    for a capture that begins after an SNRME); an SNRME or SNRM answered by
    UA in the data switches it either way."""
    buffers = [data] if isinstance(data, (bytes, bytearray)) else list(data)
    if len(buffers) > 1 and all(detect_framing(b) == "hdlc" for b in buffers):
        buffers = [b"".join(buffers)]  # segmented frames given one per line
    if len(buffers) > 1 and all(detect_framing(b) == "mbus" for b in buffers):
        buffers = [b"".join(buffers)]
    elif (
        len(buffers) > 1
        and detect_framing(buffers[0]) == "mbus"
        and all(detect_framing(b) in ("mbus", "apdu") for b in buffers)
    ):
        # A polled M-Bus session read in pieces (E5, short frames, long
        # frames split over several reads): one telegram stream.
        buffers = [b"".join(buffers)]
    return _Explainer(
        encryption_key, authentication_key, verify_checksums, system_title, hdlc_modulus
    ).run([bytes(b) for b in buffers], framing)
