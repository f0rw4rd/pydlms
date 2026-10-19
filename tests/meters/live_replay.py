"""Replay tests for redacted live-meter recordings.

A fixture under ``tests/meters/recordings/`` is a ``pydlms redact`` output with
a metadata header the maintainer adds after redaction::

    # fixture-source: meter          (or: simulator, for tool tests only)
    # fixture-device: <vendor> <model>, firmware <id from the IC report>
    # fixture-recorded: <YYYY-MM-DD>, own bench meter, <transport>
    # fixture-keys: none             (or: test keys, published below)
    # fixture-script: register=<obis> profile=<obis>

:func:`load_fixture` refuses a file without that header or one that is not
redacted, :func:`replay_client` serves it with :class:`pydlms.replay.ReplayMeter`
and :func:`read_only_script` is the fixed script the recording was made with,
so the replay test runs exactly what the meter answered.

Recording (reads only; see the doc for the safety rules)::

    python -m tests.meters.live_replay record tcp://192.0.2.10:4059 \\
        --register 1.0.1.8.0.255 --profile 1.0.99.1.0.255 -o session.hex \\
        -- --client 16
"""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from pydlms.apdu.xdlms import entry_descriptor
from pydlms.client import DlmsClient
from pydlms.ic_report import ic_report
from pydlms.recording import parse_recording
from pydlms.redact import HEADER, redact_recording
from pydlms.replay import ReplayMeter
from pydlms.simulator import serve

RECORDINGS = Path(__file__).parent / "recordings"
SOURCES = ("meter", "simulator")


@dataclass
class Fixture:
    name: str
    text: str
    meta: dict[str, str] = field(default_factory=dict)

    @property
    def source(self) -> str:
        return self.meta["source"]

    @property
    def script(self) -> dict[str, str]:
        """``register`` and ``profile`` OBIS the recording's script read."""
        return dict(item.split("=", 1) for item in self.meta.get("script", "").split())


def load_fixture(name: str, directory: Path = RECORDINGS) -> Fixture:
    """Read a recording fixture and check its header and redaction."""
    text = (directory / name).read_text(encoding="utf-8")
    meta = {}
    for line in text.splitlines():
        if line.startswith("# fixture-"):
            key, _, value = line[len("# fixture-") :].partition(":")
            meta[key.strip()] = value.strip()
    if meta.get("source") not in SOURCES:
        raise ValueError(f"{name}: '# fixture-source: meter|simulator' header missing")
    if HEADER.splitlines()[1] not in text:
        raise ValueError(f"{name}: not a pydlms redact output")
    _, log = redact_recording(text)
    if log.replaced or log.dropped:
        raise ValueError(f"{name}: redacting it again still changes it:\n{log}")
    return Fixture(name, text, meta)


@contextlib.contextmanager
def replay_client(fixture: Fixture, keys: dict | None = None, **client) -> Iterator:
    """Yield ``(client, replay_meter)`` for a fixture served over TCP.

    ``keys`` go to :class:`ReplayMeter` (``encryption_key=...`` for a ciphered
    test-key session); ``client`` to :meth:`DlmsClient.tcp`.
    """
    meter = ReplayMeter(parse_recording(fixture.text), **(keys or {}))
    server = serve(meter)
    try:
        with DlmsClient.tcp(*server.server_address, timeout=5, **client) as connected:
            yield connected, meter
    finally:
        server.shutdown()
        server.server_close()


def read_only_script(client: DlmsClient, register: str, profile: str) -> dict:
    """The fixed read-only script: object list, clock, one register with its
    scaler_unit, the last two profile rows, and the IC report. Nothing is
    written to the meter."""
    view = client.get_association_view()
    clock = client.get_clock()
    value = client.get_register(register)
    entries = client.get(profile, 7, 7).value  # entries_in_use
    rows = client.read_profile(profile, entry_descriptor(max(1, entries - 1), entries))
    return {
        "objects": len(view),
        "clock": str(clock),
        "register": [value.value, value.unit_symbol],
        "profile_rows": len(rows.rows),
        "ic_report": ic_report(client),
    }


def _record(argv: list[str]) -> int:
    from pydlms import cli
    from pydlms.debug import FrameRecorder

    parser = argparse.ArgumentParser(prog="live_replay record")
    parser.add_argument("endpoint")
    parser.add_argument("--register", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("-o", "--output", required=True)
    args, connection = parser.parse_known_args(argv)
    connection = [a for a in connection if a != "--"]
    options = cli.build_parser().parse_args(["list", args.endpoint, *connection])
    options.record = None
    client = cli.build_client(options)
    recorder = FrameRecorder()
    client.link.transport.recorder = recorder
    try:
        with client:
            result = read_only_script(client, args.register, args.profile)
    finally:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(recorder.dump() + "\n")
    print(json.dumps(result, indent=2, default=str))
    return 0


if __name__ == "__main__":  # pragma: no cover - manual tool
    if sys.argv[1:2] != ["record"]:
        raise SystemExit("usage: python -m tests.meters.live_replay record ENDPOINT ...")
    sys.exit(_record(sys.argv[2:]))
