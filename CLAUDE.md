# CLAUDE.md

This file provides guidance to Claude Code and other AI coding assistants when
working in this repository.

## Project overview

`pydlms` is a pure-Python **DLMS/COSEM client library** (IEC 62056) for reading
smart meters. It is a general-purpose interface library, NOT a security tool.
Packet definitions use the `construct` library; higher layers orchestrate them.

The PyPI distribution is `pydlms-client`; the import name is `pydlms`. The
package supports Python 3.10 and newer. `construct>=2.10,<3` is the only
required runtime dependency (keep that pin); `cryptography` (extra `crypto`)
adds AES-GCM ciphering, HLS and suites 1/2, `pyserial` (extra `serial`) adds
HDLC, optical and M-Bus transports. Status is alpha (`pydlms.__version__`); the
public surface is unstable until 1.0.

Dual-licensed GPL-3.0-only + commercial, mirroring the sibling libs profinet-py
and hartip-py.

This is an unofficial implementation. Changes involving a real meter must be
tested against a meter you own or are authorised to read, never against
utility-operated production infrastructure.

## Repository layout

`docs/` (design notes, research, backlog) is gitignored and exists only in
the maintainer's checkout; nothing tracked may point into it.

- Codec: `pydlms/axdr.py`, `obis.py`, `cosem/` (`data`, `types`, `enums`,
  `time`, `scaler`, `access`, `interface_classes`, `model`, `profile`,
  `compact_data`, `delta`), `catalog.py` + `data/obis_names.csv`
- Framing: `hdlc/` (`crc`, `address`, `framing`, `frmr`, `connection`),
  `wrapper.py`, `mbus.py` + `mbus_link.py`, `apdu/gbt.py`; interface
  `link.ApduLink`
- Transports: `transports/` (`base`, `tcp`, `serial`, `iec62056_21` for the
  optical sign-on and mode C/E)
- Security: `security/` (`suites`, `context`, `gcm`, `ciphering`, `general`,
  `hls`, `keywrap`, `ec`, `keyagreement`, `certificates`, `thirdparty`,
  `provider`, `v44`)
- APDUs: `apdu/` (`tags`, `xdlms`, `acse`, `sn`), `sn_methods.py`
- `association.py`, `client.py` (`DlmsClient`), `objects.py` (typed objects),
  `image.py` (image transfer), `counters.py` + `ic_report.py` (invocation
  counters), `push.py`, `profiles/` (national and companion-standard profiles,
  `presets`)
- Tooling: `debug.py` (logging, recorder), `redact.py`, `explain.py`
  (`pydlms decode`), `cli.py`, `simulator.py` (in-process meter for tests and
  examples), `recording.py` + `replay.py` (`simulate --replay` of a `--record`
  file), `apduxml.py` (APDU <-> XML, `decode --xml` / `encode`),
  `gurux_xml.py` (the Gurux translator dialect, `--dialect gurux`)
- Tests: `tests/` unit and end-to-end against the simulator, `tests/crypto/`
  (the crypto gate below), `tests/meters/` (vendored real captures under
  `tests/fixtures/`, loaded by `tests/meter_fixtures.py`), `tests/interop/`
  (other DLMS implementations as Docker oracles), `tests/integration/` (socat
  PTY, Gurux simulator, tshark)
- `examples/`: numbered scripts that run against the simulator unless
  `DLMS_HOST` is set; `tests/test_examples.py` runs them all.

Package data: `py.typed`, `data/*.csv`, `data/*.yaml` via
`[tool.setuptools.package-data]`. Do not move or rename package data without
updating `pyproject.toml`. The sdist adds `tests/` and `examples/`
(`MANIFEST.in`); the wheel is the package only.

## Protocol stack and design constraints

The stack is transport (TCP | serial | optical IEC 62056-21) -> framing (HDLC |
TCP/UDP wrapper | M-Bus) -> security transform -> xDLMS / ACSE -> client.
Upper layers depend only on the layer directly below. Transports are byte
streams with timeouts (`send`, `recv`, `recv_exact`); each framing implements
`link.ApduLink`, so HDLC sequencing, wrapper reassembly and segmentation never
leak upward. The security layer is a pure transform on APDU bytes plus key
material and never touches sockets.

- **construct for byte-level structures.** RawCopy + Checksum for the HDLC
  HCS/FCS and the M-Bus checksum; a construct `Struct` for the wrapper header;
  custom `Construct` classes for A-XDR lengths and the recursive COSEM Data.
  The xDLMS (A-XDR) and ACSE (BER) APDU codecs are hand-written; keep new
  code consistent with the module it lands in.
- Support BOTH Logical-Name and Short-Name referencing, and BOTH full and
  compact push payload forms (compact = no inline OBIS, e.g. Kaifa HAN lists).

Meter data is untrusted:

- Validate lengths, element counts, tags, HCS/FCS, wrapper lengths, invocation
  counters and result codes before use.
- Never return plaintext from an authenticated mode whose tag failed; raise.
- Avoid logging or `repr`-ing encryption keys, authentication keys, LLS
  passwords, HLS challenges or decrypted authentication material.
- Never weaken replay/invocation-counter checks or authentication defaults to
  make a test pass.
- Errors come from `pydlms/exceptions.py` (`DlmsError` and subclasses; decode
  errors also subclass `ValueError`). Use those, not ad-hoc types.

## Public API

`pydlms/__init__.py` exports the supported entry points (`DlmsClient`,
`SecurityContext`, `Mechanism`, `PushDecoder`, `explain`, `enable_debug`, data
types, exceptions). Update `__all__` deliberately when adding public API.

```python
from pydlms.obis import ObisCode
from pydlms.cosem.data import DlmsData, encode_data, decode_data

ObisCode.parse("1.0.1.8.0.255").to_bytes()      # b"\x01\x00\x01\x08\x00\xff"
raw = encode_data(DlmsData.uint32(1234))        # 06000004d2
value, consumed = decode_data(raw)
```

## Development setup and checks

```bash
pip install -e ".[dev]"
```

Run before every commit (CI runs the same; see `.github/workflows/ci.yml`):

```bash
pytest -v                          # integration deselected by default
pytest --collect-only -q
ruff check pydlms/
ruff format --check pydlms/
vulture pydlms/ vulture_whitelist.py
bandit -c pyproject.toml -r pydlms/
```

`pre-commit` runs ruff, ruff format and vulture on commit, bandit and
`pytest tests/ -x -q` on push, and `.githooks/no-ai-coauthor` on commit-msg.
CI tests Python 3.10 to 3.15 (3.15 as a pre-release). Ruff targets py310 with a
100-character line length.

Integration tests are marked `integration` and deselected by `addopts`; run
them explicitly with `pytest -m integration`. They need one of the interop
targets below, never a production meter. The normal suite must not require
network (loopback to the in-process simulator is fine), Docker or serial
access.

Interop / sim targets (separate processes, no code entanglement):

- Gurux.DLMS.Simulator.Net in Docker (`-p 4059 -x Templates/LN-v2-High.xml`).
- `tests/interop/`: OpenMUC jDLMS, cB-Sigma dlms (Go), Gurux.DLMS.Net and
  GuruxDLMS.c, dlms-cosem, the Rust DLMS crates, opendlms and push parsers,
  each built from its own Dockerfile (protocol in `tests/interop/PROTOCOL.md`).
- `tshark` `packet-cosem` as an independent decoder of our built frames.
- Serial: a scripted fake port for the mode C/E sign-on and baud switch;
  `socat` PTY pair (integration), `loop://` and `socket://` for plain HDLC.

## Testing expectations

- Every construct gets a round-trip test (`parse(build(x)) == x`) plus a fixed
  known-good hex vector from the spec or a public capture.
- Add malformed and truncated input cases for every parser.
- Crypto gate: no crypto function merges without a known-answer test from a
  named source, a tamper/negative test parametrized over every byte, and, where
  a real frame exists, an end-to-end decrypt of a field capture. Missing
  `cryptography` skips the crypto suite; it never silently passes.
- Test vectors and captures come from licence-compatible public sources, each
  listed in `THIRD_PARTY.md`: esphome-libs/dlms_parser dumps (Apache-2.0),
  published standard examples (Green Book excerpts, NIST, RFC, OMS, ITU-T),
  cB-Sigma vectors (Apache-2.0), and output of other implementations used as
  test data. NOT smartmeter-datacollector (GPL-2.0). Keep vendored fixtures
  byte-identical.
- Bug fixes include a regression test that fails without the fix.
- Do not turn an integration failure into a unit-test skip; reproduce the
  behaviour with a captured byte fixture instead.

## Code quality and contribution rules

- Use logging rather than `print()` for library diagnostics (examples may
  print).
- Keep public functions and methods typed (`py.typed` ships).
- Give a checkable source for every new OBIS code, tag, enum value, unit or
  table entry (Blue/Green Book clause, a capture, or a dissector table) and say
  when a value is unverified or seen on only one meter.
- Sources must be lawfully obtained: public DLMS UA excerpts, standards
  previews, national adoptions published for free, or a licensed copy. Never
  use unlicensed copies of IEC or DLMS UA documents; the commercial licence
  depends on clean provenance.
- No OBIS/unit tables copied from GPL-2.0 Gurux or BSL dlms-cosem.
  Hand-author the factual table; cite sources in `THIRD_PARTY.md`.
- One coherent purpose per commit and per pull request.
- Update `README.md` (including its verification status), `__all__`, tests and
  `examples/` when a public API or supported-feature claim changes.

## Releases

Bump `__version__` in `pydlms/__init__.py`, commit, then push a tag
`vX.Y.Z` from the host. `.github/workflows/release.yml` refuses a tag that
does not match `__version__`, reruns CI, builds, and publishes to PyPI through
trusted publishing after approval in the `pypi` environment.

## Commits

Conventional commits, lowercase after the colon. No emoji, no signing, no
AI co-author trailers (the `.githooks/no-ai-coauthor` hook enforces this).
