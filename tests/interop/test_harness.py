"""The interop harness itself, against pydlms as its own oracle (no Docker)."""

from __future__ import annotations

import json

from tests.interop import compare, corpus
from tests.interop.model import answer


class SelfOracle:
    hello = answer("hello")

    def supports(self, op):
        return op in self.hello["ops"]

    def ask(self, line):
        return json.loads(json.dumps(answer(line)))


def test_pydlms_agrees_with_itself_on_the_whole_corpus():
    rows = compare.run(SelfOracle())
    assert rows and {r["outcome"] for r in rows} <= {"agree", "both-reject"}
    assert sum(r["op"] == "data" for r in rows) == len(corpus.data_values())


def test_encode_data_round_trips_every_value():
    for _, hex_ in corpus.data_values():
        tree = answer(f"data {hex_}")["result"]
        assert answer("encode-data " + json.dumps(tree))["result"]["hex"] == hex_


def test_subset_comparison():
    ours = {"kind": "x", "a": 1, "b": {"t": "unsigned", "v": 2}}
    assert compare.subset_equal({"kind": "x", "a": 1}, ours) is None
    assert compare.subset_equal({"a": 2}, ours) == ".a: 2 vs pydlms 1"
    assert "no such field" in compare.subset_equal({"c": 1}, ours)


def test_dont_care_maps_both_ways():
    assert answer("data ff") == {"ok": True, "result": {"t": "dont-care", "v": None}}
    assert answer('encode-data {"t": "dont-care", "v": null}')["result"] == {"hex": "ff"}
