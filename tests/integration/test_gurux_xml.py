"""The Gurux XML dialect against a live GXDLMSTranslator, both directions.

Image: ``docker build -t pydlms-gurux-client tests/integration/gurux_client``
(``translate`` mode of ``Program.cs``). The offline, frozen variant is
``tests/test_gurux_xml.py``; this test also catches the fixture going stale
when the pinned Gurux commit changes.
"""

from __future__ import annotations

import base64
import shutil
import subprocess

import pytest

from pydlms.gurux_xml import GuruxXmlWriter, to_text
from tests.gurux_xml_corpus import IMAGE, build, run, translate
from tests.test_gurux_xml import ROWS, _keys

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def live():
    pytest.importorskip("cryptography")
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    try:
        subprocess.run(  # noqa: S603,S607 - fixed argv, test-only
            ["docker", "image", "inspect", IMAGE], check=True, capture_output=True
        )
    except subprocess.CalledProcessError:
        pytest.skip(
            f"image {IMAGE} missing: docker build -t {IMAGE} tests/integration/gurux_client"
        )
    return {row["name"]: row for row in run(build())}


def test_frozen_fixture_matches_the_live_translator(live):
    for row in ROWS:
        assert live[row["name"]].get("xml") == row.get("xml"), row["name"]
        assert live[row["name"]].get("self_round_trip") == row.get("self_round_trip"), row["name"]


def test_gurux_encodes_pydlms_xml_wherever_it_encodes_its_own(live):
    """XmlToPdu of pydlms's text gives the APDU for every APDU whose own Gurux
    XML Gurux encodes correctly (Gurux's XmlToPdu rebuilds ACSE from its own
    settings and wraps GBT again, so that is the most it can do)."""
    groups: dict[tuple, list[dict]] = {}
    for row in live.values():
        groups.setdefault(tuple(row.get("keys", ())), []).append(row)
    ours_ok = gurux_ok = 0
    failures = []
    for keys, rows in groups.items():
        texts = []
        for row in rows:
            el = GuruxXmlWriter(*_keys(row), secrets=True).apdu(bytes.fromhex(row["apdu"]))
            texts.append(None if el.tag == "Raw" else to_text(el))
        sendable = [(row, text) for row, text in zip(rows, texts, strict=True) if text]
        replies = translate(
            ["X " + base64.b64encode(text.encode()).decode() for _, text in sendable],
            list(keys) or None,
        )
        for (row, _), reply in zip(sendable, replies, strict=True):
            kind, _, body = reply.partition(" ")
            ok = kind == "P" and body.lower() == row["apdu"]
            ours_ok += ok
            gurux_ok += bool(row.get("self_round_trip"))
            if row.get("self_round_trip") and not ok:
                failures.append((row["name"], reply[:80]))
    assert not failures
    assert ours_ok >= gurux_ok
