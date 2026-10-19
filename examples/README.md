# pydlms Examples

## Quick Start

```python
from pydlms import DlmsClient

with DlmsClient.tcp("192.0.2.10", 4059) as meter:  # public client, no security
    print(meter.get_register("1.0.1.8.0.255"))  # e.g. "12345678 Wh"
    print(meter.get_clock())
```

## Running

Every example runs as is: without `DLMS_HOST` it starts the built-in meter
simulator (`pydlms.simulator`) on a free local port and talks to that.

```bash
pip install "pydlms-client[all]"
cd examples
python3 00_read_register.py                     # against the simulator
DLMS_HOST=192.0.2.10 python3 00_read_register.py   # against a meter
```

Point the examples only at a meter you own or are authorised to read, never at
utility-operated infrastructure. `05_get_many_and_set.py` writes the clock and
asks first when `DLMS_HOST` is set.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DLMS_HOST` | (simulator) | Meter IP or host name |
| `DLMS_PORT` | `4059` | TCP port |
| `DLMS_HDLC` | `0` | `1`: HDLC over TCP instead of the TCP wrapper |
| `DLMS_CLIENT` | `16` (`1` in 04) | Client SAP |
| `DLMS_EK`, `DLMS_AK` | Green Book example keys | Encryption / authentication key, hex (04) |
| `DLMS_PROFILE` | `1.0.99.1.0.255` | Load profile OBIS code (02) |
| `DLMS_SERIAL` | (none) | Serial device or pyserial URL (06, 09) |
| `DLMS_BAUD` | `9600` | Serial baud rate (09) |
| `DLMS_LAYERS` | (all) | Comma-separated logger layers to trace (08) |

## Examples

### Reading

| File | Description | Needs |
|------|-------------|-------|
| `00_read_register.py` | Identity, clock and registers with scaler and unit | |
| `01_object_list.py` | Association view with access rights and OBIS names | |
| `02_load_profile.py` | Load profile with typed timestamps and scaled values | |
| `03_typed_objects.py` | Typed COSEM objects: attributes by name, methods | |
| `05_get_many_and_set.py` | GET-with-list in one round trip, then SET the clock | |

### Security

| File | Description | Needs |
|------|-------------|-------|
| `04_secured_hls_gmac.py` | HLS-GMAC association, suite 0, ciphered APDUs | `crypto` |

### Push and Decoding

| File | Description | Needs |
|------|-------------|-------|
| `06_decode_push.py` | Decrypt and decode an M-Bus push (Netz NÖ capture or a serial port) | `crypto` |
| `07_explain_frames.py` | Explain raw bytes layer by layer (`pydlms decode`) | |
| `08_debug_logging.py` | Trace a session with frame hexdumps | |

### Transports

| File | Description | Needs |
|------|-------------|-------|
| `09_serial_hdlc.py` | HDLC over a serial line or any pyserial URL | `serial` |

`crypto` and `serial` are the pip extras (`pydlms-client[crypto]`,
`pydlms-client[serial]`, both in `pydlms-client[all]`).

`_meter.py` holds the shared setup: the `DLMS_*` variables and the fallback
to the simulator. `tests/test_examples.py` runs every example against the
simulator.
