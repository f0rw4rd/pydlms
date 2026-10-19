# Oracle line protocol

Every library under test runs in its own Docker image
(`tests/interop/<lib>/Dockerfile`, pinned commit or version) with an adapter
that reads one request per line on stdin and writes exactly one JSON object
per line on stdout (flush after each). The image's default command is the
adapter. Nothing else may be written to stdout (logs go to stderr).

## Requests

| Line | Meaning |
|---|---|
| `hello` | `{"ok": true, "library": "...", "version": "...", "ops": ["data", ...]}` |
| `data <hex>` | decode one A-XDR COSEM `Data` value |
| `encode-data <json>` | encode a data tree (below) to A-XDR |
| `apdu <hex>` | decode one plaintext APDU |
| `push <hex> [<ek> [<ak>]]` | decode a push APDU (DataNotification, possibly general-glo/glo ciphered) |
| `decrypt <ek> <ak> <system-title-hex> <hex>` | decipher one glo-/ded-/general-glo APDU, return its plaintext |
| `compact-data <template-hex> <buffer-hex>` | decode a Compact data (IC 62) `compact_buffer` with its `template_description` (`-`: empty) |

A key or system-title argument of `-` means "absent" (so later arguments
keep their position). pydlms answers `push`/`decrypt` the way its analysis
tools do (`pydlms decode`, `strict=False`): the given keys decide, not a
client security policy, and the encryption key doubles as the dedicated and
the broadcast key.

Responses:

- success: `{"ok": true, "result": ...}`
- the library rejects the input: `{"ok": false, "error": "<message>"}`
- the adapter does not implement the op or the library has no such feature:
  `{"ok": false, "unsupported": true, "error": "..."}`

## JSON model (what `result` holds)

`data`, `encode-data`: a data tree `{"t": <type>, "v": <value>}`. Types are
the A-XDR CHOICE names: `null-data`, `boolean`, `bit-string`, `double-long`,
`double-long-unsigned`, `octet-string`, `visible-string`, `utf8-string`,
`bcd`, `integer`, `long`, `unsigned`, `long-unsigned`, `compact-array`,
`long64`, `long64-unsigned`, `enum`, `float32`, `float64`, `date-time`,
`date`, `time`, `array`, `structure`, `dont-care` (tag 255, no value),
`delta-integer`, `delta-long`, `delta-double-long`, `delta-unsigned`,
`delta-long-unsigned`, `delta-double-long-unsigned` (tags 28..33, integer
values like their base type). Values: integers as JSON numbers,
`boolean` as true/false, octet-string/date/time/date-time as lowercase hex,
strings as text, bit-string as `"0101..."`, float32/float64 as lowercase hex
of the IEEE-754 big-endian bytes (exact), array/structure as a list of trees,
compact-array as `{"description": <type-description>, "items": [trees]}`
where a type-description is `{"t": type}`, plus `"members": [...]` for a
structure or `"count": n, "of": desc` for an array. `encode-data` returns
`{"hex": "..."}`.

`apdu`: an object with `"kind"` plus fields; see `tests/interop/model.py`
(`apdu_json`), which is the reference. Field names are snake_case pydlms
dataclass fields; OBIS as `"a.b.c.d.e.f"`; bytes as lowercase hex; nested
data as data trees; enums as integers. **An adapter may return any subset of
fields**: the comparison checks only the keys it returns, plus `kind`.

`push`: `{"long_invoke_id": n, "date_time": hex|null, "body": tree}`.

`decrypt`: `{"plaintext": hex}`.

`compact-data`: `{"captures": [tree, ...]}`, one structure tree per capture
found in the buffer (pydlms decodes exactly one capture and rejects
trailing octets).

Comparison (`tests/interop/compare.py`) runs the same input through pydlms
(`model.py`) and the oracle. Outcomes: `agree`, `disagree`, `both-reject`,
`only-pydlms-rejects`, `only-oracle-rejects`, `unsupported`.
