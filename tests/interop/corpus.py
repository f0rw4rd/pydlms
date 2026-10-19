"""Inputs every oracle sees: APDUs, data values, pushes, ciphered APDUs."""

from __future__ import annotations

import functools

from pydlms.cosem.data import DlmsData, encode_data


@functools.cache
def apdus() -> list[tuple[str, str]]:
    """(name, hex) of every plaintext APDU in the Gurux XML corpus."""
    from pydlms.security.ciphering import is_ciphered_apdu
    from tests.gurux_xml_corpus import build

    return [
        (r["name"], r["apdu"])
        for r in build()
        if "keys" not in r and not is_ciphered_apdu(bytes.fromhex(r["apdu"]))
    ]


def _walk(item: DlmsData, out: list[DlmsData]) -> None:
    out.append(item)
    if item.tag in (1, 2):
        for member in item.value:
            _walk(member, out)


@functools.cache
def data_values() -> list[tuple[str, str]]:
    """(name, hex) of every distinct A-XDR Data value inside the corpus APDUs."""
    from pydlms.apduxml import _decode_plain

    seen: dict[str, str] = {}
    for name, hex_ in apdus():
        try:
            obj = _decode_plain(bytes.fromhex(hex_))
        except Exception:  # noqa: BLE001 - corpus includes deliberately odd APDUs
            continue
        found: list[DlmsData] = []
        _collect(obj, found)
        for i, item in enumerate(found):
            try:
                raw = encode_data(item).hex()
            except Exception:  # noqa: BLE001
                continue
            seen.setdefault(raw, f"{name}#{i}")
    edge = {
        "int8-min": "0f80",
        "int16-min": "108000",
        "int32-min": "0580000000",
        "uint64-max": "15ffffffffffffffff",
        "int64-min": "148000000000000000",
        "float32-nan": "177fc00000",
        "float64-neg-zero": "188000000000000000",
        "bits-0": "0400",
        "bits-12": "040cabc0",
        "bcd": "0d12",
        "utf8-multibyte": "0c03e282ac",
        "visible-empty": "0a00",
        "octets-long-len": "09820100" + "00" * 256,
        "array-long-len": "018180" + "1100" * 128,
        "date": "1a07e80101ff",
        "time": "1b0c000000",
        "date-time": "1907e8010101000000ff800000",
    }
    for name, raw in edge.items():
        seen.setdefault(raw, f"edge-{name}")
    return [(name, raw) for raw, name in seen.items()]


def _collect(obj, out: list[DlmsData]) -> None:
    import dataclasses

    if isinstance(obj, DlmsData):
        _walk(obj, out)
    elif dataclasses.is_dataclass(obj):
        for f in dataclasses.fields(obj):
            _collect(getattr(obj, f.name), out)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _collect(v, out)


@functools.cache
def pushes() -> list[tuple[str, str, str, str]]:
    """(name, apdu hex, ek hex, ak hex) of every real push capture."""
    from pydlms.recording import deframe
    from tests.meter_fixtures import all_names, load

    out = []
    for name in all_names():
        f = load(name)
        framing = {"hdlc": "hdlc", "mbus": "mbus"}.get(f.transport, "apdu")
        for j, (_, apdu) in enumerate(deframe([(None, f.raw)], framing, verify_checksums=False)):
            out.append(
                (
                    f"{name}-{j}",
                    apdu.hex(),
                    (f.encryption_key or b"").hex(),
                    (f.authentication_key or b"").hex(),
                )
            )
    return out
