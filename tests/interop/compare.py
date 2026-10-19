"""Run the corpus through pydlms (model.answer) and an oracle; classify each item.

python -m tests.interop.compare pydlms-interop-<lib> [--op data] [--json out.json]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter

from tests.interop import corpus
from tests.interop.model import answer


def subset_equal(theirs, ours, path="") -> str | None:
    """None when every key the oracle reports equals pydlms's; else where it differs."""
    if isinstance(theirs, dict) and isinstance(ours, dict):
        for key, value in theirs.items():
            if key not in ours:
                return f"{path}.{key}: pydlms has no such field"
            diff = subset_equal(value, ours[key], f"{path}.{key}")
            if diff:
                return diff
        return None
    if isinstance(theirs, list) and isinstance(ours, list):
        if len(theirs) != len(ours):
            return f"{path}: {len(theirs)} items vs pydlms {len(ours)}"
        for i, (a, b) in enumerate(zip(theirs, ours, strict=True)):
            diff = subset_equal(a, b, f"{path}[{i}]")
            if diff:
                return diff
        return None
    return None if theirs == ours else f"{path}: {theirs!r} vs pydlms {ours!r}"


def classify(line: str, oracle) -> dict:
    ours = answer(line)
    theirs = oracle.ask(line)
    row = {"input": line, "pydlms": ours, "oracle": theirs}
    if theirs.get("unsupported"):
        row["outcome"] = "unsupported"
    elif ours["ok"] and theirs["ok"]:
        diff = subset_equal(theirs["result"], ours["result"])
        row["outcome"] = "agree" if diff is None else "disagree"
        if diff:
            row["diff"] = diff
    elif not ours["ok"] and not theirs["ok"]:
        row["outcome"] = "both-reject"
    else:
        row["outcome"] = "only-pydlms-rejects" if not ours["ok"] else "only-oracle-rejects"
    return row


def lines(op: str) -> list[tuple[str, str]]:
    if op == "data":
        return [(n, f"data {h}") for n, h in corpus.data_values()]
    if op == "apdu":
        return [(n, f"apdu {h}") for n, h in corpus.apdus()]
    if op == "push":
        return [
            (n, " ".join(("push", h, ek or "-", ak or "-"))) for n, h, ek, ak in corpus.pushes()
        ]
    if op == "encode-data":
        out = []
        for n, h in corpus.data_values():
            ref = answer(f"data {h}")
            if ref["ok"]:
                out.append((n, "encode-data " + json.dumps(ref["result"], separators=(",", ":"))))
        return out
    raise ValueError(op)


def run(oracle, ops=("data", "encode-data", "apdu", "push")) -> list[dict]:
    rows = []
    for op in ops:
        if not oracle.supports(op):
            continue
        for name, line in lines(op):
            row = classify(line, oracle)
            row.update(op=op, name=name)
            rows.append(row)
    return rows


def main() -> int:
    from tests.interop.oracle import Oracle

    p = argparse.ArgumentParser()
    p.add_argument("image")
    p.add_argument("args", nargs="*", help="extra arguments for the image (e.g. a subcommand)")
    p.add_argument("--op", action="append")
    p.add_argument("--json")
    args = p.parse_args()
    oracle = Oracle(args.image, *args.args)
    try:
        rows = run(oracle, args.op or ("data", "encode-data", "apdu", "push"))
    finally:
        oracle.close()
    for row in rows:
        if row["outcome"] not in ("agree", "both-reject", "unsupported"):
            print(
                row["op"],
                row["name"],
                row["outcome"],
                row.get("diff") or row["oracle"].get("error") or row["pydlms"].get("error"),
            )
    print(json.dumps(Counter(f"{r['op']}:{r['outcome']}" for r in rows), indent=1))
    if args.json:
        with open(args.json, "w") as out:
            json.dump(rows, out, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
