# Frozen Association LN object lists

`object_list` (class 15 attribute 2 of `0.0.40.0.0.255`) as A-XDR hex, read
by pydlms from independent servers on 2026-10-16 with the public client
(SAP 16, no security). Test data produced by running the servers, not code.

| File | Server | Association LN version |
|------|--------|------------------------|
| `gurux_sim_ln_v2.hex` | Gurux.DLMS.Simulator.Net, image `tests/integration/gurux` at Gurux.DLMS.Net commit `6f263019`, template `GMacWithAuthenticationEncyption.xml`, wrapper | 2 |
| `jdlms_ln_v1.hex` | OpenMUC jDLMS 1.8.0, `tests/interop/jdlms/src/Server.java` (`server` mode) | 1 |

Re-capture: start the server as in `tests/integration/test_gurux.py` or
`tests/interop/test_jdlms.py`, then
`encode_data(meter.get("0.0.40.0.0.255", 15, 2)).hex()`.
