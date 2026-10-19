# Third-party material

`pydlms` contains no third-party source code. This file records external
material used as **reference** or as **test vectors**, with its license.

## Test vectors / capture fixtures

- **esphome-libs/dlms_parser** — https://github.com/esphome-libs/dlms_parser —
  **Apache-2.0**. Real smart-meter frame dumps (`tests/dumps/*.log`) with
  published keys (`.key` / `.gak`) for Kaifa MA309M (Netz NÖ P1 / M-Bus),
  Landis+Gyr E450 (CII / HDLC), Iskra AM550, Sagemcom XT211, Norway HAN, etc.
  Any vendored fixture retains the Apache-2.0 notice and attribution here.
  **Vendored** at commit `a80697723e9c52887e9cfdcb2729821dc47cc619` into
  `tests/fixtures/dlms_parser/` (dumps, keys and `tests/expected/*.h`
  byte-identical, with `LICENSE` and `NOTICE.md`).

- **Published standard test vectors** used as known-answer tests (facts, not
  code): IEC 62056-5-3 Green Book suite-0 ciphering and HLS-GMAC examples and
  the Green Book v10 AARQ/AARE examples (the latter as quoted in
  dlms-cosem's MIT-licensed tests at commit `0747b15`); McGrew/Viega GCM test
  case 4; RFC 6979 A.2.5 (ECDSA P-256); RFC 5903 section 8.1 (ECDH P-256);
  RFC 3394 section 4.1 (AES key wrap); FIPS-197 Appendix C.1 (AES-128).
  IEC 62056-5-3:2023 annex I.2 one-pass Diffie-Hellman example (client
  signing key pair, ephemeral public key and its signature) as transcribed
  in cB-Sigma dlms (**Apache-2.0**) `cosem/iec6205653_vectors_test.go` at
  commit `26360a1`; only the example bytes are used
  (`tests/crypto/vectors.py`), cross-checked by deriving the public keys
  from the private ones. The annex I.2 request (header fields, EK-GC-C and
  ciphered content, same file and commit) is used only to pin that its tag
  verifies under neither general-ciphering AAD.

- **OMS Specification Vol. 2 Primary Communication**, Issue 5.0.1 / 2023-12,
  and its **Annex N** (message examples, Release E), Open Metering System
  Group e.V., publicly downloadable from oms-group.org. The wired M-Bus
  frame of Annex N N.2.2 is used as a known-answer vector in
  `tests/test_mbus_ci.py` (example bytes only); Table 1, Annex D and
  7.2.4 Table 18 are the source of the M-Bus data-header layout in
  `pydlms/mbus.py` (facts, no text copied). The wired REQ-UD2 and RSP-UD telegrams of
  Annex N N.4.3-N.4.5 are known-answer vectors in `tests/test_mbus_link.py`.

- **M-Bus Usergroup, "The M-Bus: A Documentation" Rev. 4.8**, publicly
  downloadable from m-bus.com. Source of the wired link layer in
  `pydlms/mbus_link.py` (telegram formats, C field codes, timing and
  repetition, FCB/FCV rules, selection; facts, no text copied); its printed
  telegrams (6.1, 6.2, 6.4.1, 6.4.2) are known-answer vectors in
  `tests/test_mbus_link.py`.

- **DLMS UA public excerpts** (DLMS User Association, freely downloadable,
  "All Rights Reserved"; facts only, no text or table copied):
  *DLMS UA 1000-1 Ed. 13 Excerpt* (Blue Book, 2019-05-08), 4.3.2 Table 4,
  the source of the unit codes 128..174 in `pydlms/cosem/enums.py`; and
  *DLMS UA 1000-1 Ed. 17 Part 2 Excerpt* V1.0 (2025-02-28), whose table of
  contents names class 66 and class 86.

- **ITU-T Recommendation V.44 (11/2000)** "Data compression procedures"
  and its Corrigendum 1 (03/2002), free from https://www.itu.int/rec/T-REC-V.44.
  The Appendix II examples (II.1 octets of Table II.1 and string
  collection, II.2 codes and string collection) are known-answer tests in
  `tests/test_v44.py`; the decoder in `pydlms/security/v44.py` is written
  from the clause text.

## Reference only (NOT copied into this repo)

The wire format is authored from primary standards and our own reading. The
following are consulted for behaviour/cross-checking but their code and data
tables are **not** copied in:

- **IEC 62056** (DLMS UA Blue Book Ed. 17 / Green Book Ed. 12, public excerpts). OBIS codes, the
  unit table and interface-class ids are "All Rights Reserved" to DLMS UA and
  are **not** redistributed; `pydlms` ships only a hand-authored factual table.
  Confirm redistribution terms with DLMS UA before the first public release.
- **gurux-dlms** (GPL-2.0-only) and **Gurux.DLMS.Simulator.Net** (GPL-2.0 /
  commercial) — used only as a black-box interop/CI target and as a
  behavioural reference (HLS argument order, mechanism-2 convention, SN method
  offsets), never as a code or OBIS-data source. The 0xDD/0xDF APDUs in
  `tests/crypto/test_gurux_general_frames*.py` are output of the Gurux client
  library run by `tests/integration/gurux_client/` (test data, not code).
  Likewise the 0xDD/0xDF APDUs in `tests/crypto/go_dlms_frames.py` and
  `tests/crypto/go_dlms_thirdparty_frames.py` are output of the cB-Sigma
  dlms (Apache-2.0) server at commit `26360a1`, run by
  `tests/interop/go-dlms/` (test data, not code). The annex J.3 example
  in `tests/crypto/test_thirdparty.py` (`01 || C4 01 41 00 12 5A 0A`) is
  the vector of its `cosem/thirdparty_internal_test.go`.
  `tests/fixtures/gurux_xml/translator.json` is `GXDLMSTranslator` output for
  pydlms-built APDUs (test data, not code); the element names and enum
  spellings in `pydlms/gurux_xml.py` were taken from that output, not from
  Gurux source, except the six delta-type element names (`Delta-Int8` ..
  `Delta-UInt32`, tags 28..33), which are the spellings in Gurux's
  `TranslatorSimpleTags.cs` (names only, no code; unconfirmed against
  translator output). The delta tag numbers are also listed in Gurux
  `Enums/DataType.cs`, as a cross-check of the Green Book values.
  `tests/fixtures/object_lists/gurux_sim_ln_v2.hex` is an object list read
  from the simulator (test data, not code).
- **cB-Sigma/schc** `v44/` (**Apache-2.0**, v0.2.0) - behaviour
  cross-check for the V.44 decoder only (packet method and its B.1.2
  defaults, decoder error conditions); no code copied.
- **OpenMUC jDLMS** (GPL-3.0-or-later) - black-box interop target only.
  `tests/fixtures/object_lists/jdlms_ln_v1.hex` is an object list read from
  a jDLMS 1.8.0 server (test data, not code). The access-mode values in
  `pydlms/cosem/access.py` were cross-checked against the jDLMS and Gurux
  enums, not copied from them.
- **rscada/libmbus** (BSD-3-Clause) and **addiva-elektronik/mbus-device**
  (MIT, on the addiva-elektronik/libmbus fork) - black-box interop peers
  for the wired M-Bus link layer, built at pinned commits by
  `tests/interop/mbus/Dockerfile`, never shipped; `tests/interop/mbus/master.c`
  is our own test harness linking libmbus. The secondary-address notation
  `IIIIIIIIMMMMVVDD` of `MbusLink` follows libmbus's command-line
  convention; no code copied.
- **dlms-cosem** (pwitab/u9n) — MIT through commit `0747b15` (2022-12-29), then
  Business Source License 1.1. Used only as a behavioural reference; no code or
  BSL-era data copied.
- **Wireshark `packet-cosem.c`** (GPL-2.0-or-later) — used only via `tshark` as
  an independent decoder in interop tests, never as a code source.
- **smartmeter-datacollector** (GPL-2.0-only) — reference only; its test
  vectors are **not** copied (incompatible for our redistribution).
- **Kaifa "Norwegian HAN spesification - OBIS Codes", KFM_001** (list version
  09.11.2018, published by NEK) — the source of the positional layouts in
  `pydlms/profiles/norway.py` (facts: positions, OBIS codes, units, scalers).
  **toreamun/amshan** `han/kaifa.py` was consulted only to confirm that the
  single-phase lists omit the "NA" values (9 and 14 values); nothing copied.
- **Netbeheer Nederland, DSMR v4.2.2 Final P3 companion standard**
  (2014-03-14, public PDF) - the source of the presets in
  `pydlms/profiles/dsmr_p3.py` (facts: client SAPs, mechanism, suite,
  policy, OBIS codes). OSGP open-smart-grid-platform (Apache-2.0) was the
  second source; nothing copied.
- **IS 15959 Parts 1 (2011, Amendments 1 to 5), 2 (2016, Amendments 1
  and 2) and 3 (2017)**, Bureau of Indian Standards, public copies on
  archive.org (`gov.in.is.15959.*`) and law.resource.org - the source of
  `pydlms/profiles/india.py` (facts: client SAPs, OBIS codes, event code
  numbers and categories, ESW bit numbers; descriptions are our own). The
  cB-Sigma dlms `is15959/` catalogue (Apache-2.0, commit `26360a1`) was the
  second reading; nothing copied. The HLS mechanism default and the ESW
  bit order are cross-checked against RelySys/3-Phase-Smart-Meter
  (Renesas IS 15959-2 reference firmware, no licence stated, commit
  `0cd9daf`; facts only) and waseeldev/gosem (MIT, commit `53a1580`;
  facts only).
- **Wiener Netze, "Smart Meter Kundenschnittstelle"** web page
  (wienernetze.at, read 2026-10-16) - the source of the `wiener-netze`
  layouts in `pydlms/profiles/austria.py` (facts: OBIS codes, order, types).
  Units and scaler from bernikr/esphome-wienernetze-smartmeter (MIT, commit
  `0c8f3d6`) and tofuSCHNITZEL/wiener_netze_smartmeter (MIT, commit
  `0c2ea2e`); facts only, no code or frames copied.
- **Gurux/Gurux.DLMS.DeviceProfiles** (CC0-1.0, commit `137f6ad`) - device
  files read for invocation-counter locations (MetCom MCS301/MCS501, Meter
  Italia EG4 EVO, L&T Regor, L+G E350); facts only, nothing vendored.
- **M-Bus data header cross-checks**: the
  public preview of IEC 62056-7-3:2017 (Figure 2, 5.4.2), the Vorarlberg
  Netz "KSMWest H1 interface" CI table, wmbusmeters `src/wmbus.cc`
  (GPL-3.0; CI names and long-header field sizes read, nothing copied) and
  Gurux.DLMS.Net `GetWirelessMBusData` (GPL-2.0; behaviour only: SAPs after
  the short header).
- **reitermarkus/dlms-cosem-rs** (MIT or Apache-2.0) - second source for unit
  enumeration values 66 (g/cm2) and 67 (atm), `src/unit.rs:76-77`, and for the
  Long-Invoke-Id-And-Priority bit positions, `src/data_notification.rs:36-66`.
  Facts only, no code copied. Blue Book / Green Book editions unverified.
