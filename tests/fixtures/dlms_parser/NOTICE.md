# Vendored test vectors: esphome-libs/dlms_parser

Source: https://github.com/esphome-libs/dlms_parser
Commit: a80697723e9c52887e9cfdcb2729821dc47cc619 (2026-09-07)
License: Apache-2.0 (copy in `LICENSE` next to this file)

Files are copied **byte-identical** and must stay that way:

- `dumps/*.log`, `dumps/*.key`, `dumps/*.gak`: raw meter captures and the
  throwaway keys published with them (`tests/dumps/` upstream).
- `expected/*.h`: upstream's expected decoded values for each capture
  (`tests/expected/` upstream). pydlms parses the C arrays and maps out of
  these headers in `tests/meter_fixtures.py`; no upstream code is used.

Known upstream quirk: the second M-Bus segment of `mbus_kaifa_ma309m` carries
`47 83` where the transport SAPs `01 67` belong, so only the plaintext of the
first segment is valid (upstream's own decoded log shows garbage after
element 8). Tests assert only on that part.

Second upstream quirk: `hdlc_landis_gyr_zmf100` has `06 09` where the OBIS
octet-string header `09 06` belongs for three current registers, and its FCS
does not verify. pydlms decodes the 7 intact leading objects (with checksum
verification explicitly disabled) and flags the push incomplete.

`dumps/mbus_kmswest.log` has no `expected/*.h` and no `.key` upstream: it is
a single M-Bus frame carrying general-glo-ciphering with security control
0x20 (encryption only, no tag) and no key was ever published, so it cannot
be deciphered (upstream's own decoded log ends at "No key provided").
`tests/meters/test_meter_dumps.py::test_kmswest_is_ciphered_without_key`
pins the readable header (system title, SC, invocation counter 21535,
72-octet ciphertext) and the exact errors pydlms raises without a key and
with a wrong one.

`dumps/raw_sagecom_xt211.log` is upstream's file name for the capture whose
expected header is `expected/raw_sagemcom_xt211.h`.
