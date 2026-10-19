"""Minimal pcap writer (stdlib only) for feeding frames to tshark.

Each payload becomes one Ethernet/IPv4/UDP packet between a client and a
server on the DLMS port 4059, so Wireshark's ``dlms`` dissector (registered on
udp.port 4059 from 4.6) picks it up.
"""

from __future__ import annotations

import struct


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _packet(payload: bytes, outbound: bool) -> bytes:
    client, server = bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])
    src, dst = (client, server) if outbound else (server, client)
    sport, dport = (50000, 4059) if outbound else (4059, 50000)
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip_header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0, src, dst)
    ip_header = ip_header[:10] + struct.pack("!H", _checksum(ip_header)) + ip_header[12:]
    ether = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00"
    return ether + ip_header + udp


def write_pcap(path, frames: list[tuple[str, bytes]]) -> None:
    """``frames``: ``("TX"|"RX", payload)`` in order (FrameRecorder format)."""
    with open(path, "wb") as handle:
        handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, (direction, payload) in enumerate(frames):
            packet = _packet(payload, direction == "TX")
            handle.write(struct.pack("<IIII", 1_700_000_000 + index, 0, len(packet), len(packet)))
            handle.write(packet)
