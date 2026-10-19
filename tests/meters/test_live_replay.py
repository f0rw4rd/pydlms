"""Replay tests for redacted session recordings.

``simulator-example.hex`` was recorded from ``pydlms simulate`` (the example
meter), not from a real meter: it exercises the record, redact and replay
tooling and makes no claim about any device. Real-meter fixtures added under
``tests/meters/recordings/`` get a test of this shape each.
"""

from __future__ import annotations

import pytest

from pydlms.redact import HEADER
from tests.meters.live_replay import RECORDINGS, load_fixture, read_only_script, replay_client


@pytest.mark.parametrize("name", sorted(p.name for p in RECORDINGS.glob("*.hex")))
def test_every_fixture_is_labelled_and_redacted(name):
    load_fixture(name)  # raises on a missing header or an unredacted file


def test_simulator_example_replays():
    fixture = load_fixture("simulator-example.hex")
    assert fixture.source == "simulator"  # tooling evidence only, not a meter
    with replay_client(fixture) as (client, meter):
        result = read_only_script(client, **fixture.script)
    assert meter.misses == []
    assert result["objects"] == 11
    assert result["clock"] == "2024-05-01 12:00:00.00 +02:00"
    assert result["register"] == [12345678, "Wh"]
    assert result["profile_rows"] == 2
    report = result["ic_report"]
    assert report["manufacturer"] == "PYD"  # the FLAG id survives redaction
    assert report["invocation_counters"] == []


def test_unlabelled_or_unredacted_fixture_is_refused(tmp_path):
    fixture = (RECORDINGS / "simulator-example.hex").read_text()
    (tmp_path / "nolabel.hex").write_text(
        "\n".join(line for line in fixture.splitlines() if "fixture-source" not in line)
    )
    with pytest.raises(ValueError, match="fixture-source"):
        load_fixture("nolabel.hex", tmp_path)
    serial_read = [
        "TX-APDU c0018100010000600100ff0200",
        "RX-APDU c40181000a0d" + b"PYD0000000001".hex(),
    ]
    (tmp_path / "plain.hex").write_text("\n".join(["# fixture-source: meter", *serial_read]))
    with pytest.raises(ValueError, match="not a pydlms redact output"):
        load_fixture("plain.hex", tmp_path)
    # The redact header pasted onto an unredacted recording does not pass either.
    (tmp_path / "pasted.hex").write_text(
        "\n".join(["# fixture-source: meter", *HEADER.splitlines(), *serial_read])
    )
    with pytest.raises(ValueError, match="still changes it"):
        load_fixture("pasted.hex", tmp_path)
