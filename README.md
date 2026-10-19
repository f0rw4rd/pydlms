# pydlms

[![CI](https://github.com/f0rw4rd/pydlms/actions/workflows/ci.yml/badge.svg)](https://github.com/f0rw4rd/pydlms/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/pydlms-client)](https://pypi.org/project/pydlms-client/)
[![Python](https://img.shields.io/pypi/pyversions/pydlms-client)](https://pypi.org/project/pydlms-client/)
[![License](https://img.shields.io/github/license/f0rw4rd/pydlms)](https://github.com/f0rw4rd/pydlms/blob/main/LICENSE)
[![Code style: ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

A Python library for reading smart meters over DLMS/COSEM (IEC 62056), the
protocol most electricity meters in Europe and many other regions speak.

pydlms talks to a meter over TCP, a serial line, an optical probe or a wired
M-Bus, sets up a plain or secured association, and reads and writes COSEM
objects. It also decodes the pushes that meters send on customer interfaces
such as the Austrian, Dutch and Norwegian P1/HAN ports. Packets are defined
with the [construct](https://construct.readthedocs.io/) library.

> Status: **alpha**. The API may change before 1.0.

## Features

- **Transports**: TCP and UDP (wrapper), HDLC over TCP or serial, IEC 62056-21
  optical probes including battery-meter wake-up, and wired M-Bus
- **Associations**: Logical-Name and Short-Name referencing, every
  authentication level from none and LLS up to HLS-GMAC and ECDSA
- **Services**: GET, SET, ACTION with block transfer, with-list requests,
  selective access, general-block-transfer and ACCESS
- **Security**: suites 0, 1 and 2 (AES-GCM, ECDH, ECDSA), dedicated and
  broadcast keys, key transfer and agreement, certificates, invocation-counter
  checks, and keys kept in an HSM if you want
- **Push decoding**: DataNotification, EventNotification and DSMR P1
  telegrams, with profiles for Norwegian HAN, Austrian P1 and Wiener Netze
- **COSEM model**: typed objects for 48 interface classes, load profiles with
  timestamps and scalers, access rights, an OBIS name catalogue
- **Tooling**: a CLI, a frame explainer, session recording and redaction,
  and a built-in meter simulator to try everything without hardware

## Installation

```bash
pip install pydlms-client            # core
pip install "pydlms-client[all]"     # + encryption (cryptography) and serial ports (pyserial)
```

The package is published as `pydlms-client` because `pydlms` is too close to
an existing PyPI name. You still `import pydlms`.

## Usage

Read a few values from a meter's public client:

```python
from pydlms import DlmsClient

with DlmsClient.tcp("192.0.2.10", 4059) as meter:
    print(meter.get_register("1.0.1.8.0.255"))    # 12345678 Wh
    print(meter.get_clock())
    for entry in meter.get_association_view():
        print(entry)
```

A secured association (HLS-GMAC, suite 0) over HDLC on a serial port:

```python
from pydlms import DlmsClient, Mechanism, SecurityContext

security = SecurityContext(
    encryption_key=bytes.fromhex("000102030405060708090A0B0C0D0E0F"),
    authentication_key=bytes.fromhex("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF"),
    client_system_title=b"PYDLMS01",
    invocation_counter=1234,     # continue from the meter's last counter
)
with DlmsClient.serial("/dev/ttyUSB0", 9600, client_sap=1,
                       mechanism=Mechanism.HLS_GMAC, security=security) as meter:
    profile = meter.read_profile("1.0.99.1.0.255", typed=True, scalers=True)
    for stamp, energy in profile.rows:
        print(stamp.to_datetime(), energy)
```

Decode the encrypted pushes from a customer interface:

```python
from pydlms import PushDecoder, SecurityContext
from pydlms.profiles import get_profile
from pydlms.security.suites import SecurityPolicy

security = SecurityContext(bytes.fromhex("36C6..."), policy=SecurityPolicy.ENCRYPTED)
decoder = PushDecoder("mbus", security, profile=get_profile("netz-noe-p1"))
for message in decoder.feed(serial_bytes):
    print(message.get("1.0.1.8.0.255"), message.get("1.0.32.7.0.255"))
```

`DlmsClient.optical()` and `DlmsClient.mbus()` work the same way for optical
probes and wired M-Bus.

More:

- [`examples/`](https://github.com/f0rw4rd/pydlms/tree/main/examples) has
  runnable scripts for each topic. They use the built-in simulator unless
  you point them at a meter.
- [GUIDE.md](https://github.com/f0rw4rd/pydlms/blob/main/GUIDE.md) covers
  connection options, security (suites 1/2, key management, HSMs, broadcast),
  pushes, companion standards, the CLI and debugging in detail.

### CLI

```bash
pydlms read tcp://192.0.2.10:4059 --obis 1.0.1.8.0.255 --register
pydlms profile serial:///dev/ttyUSB0?baud=9600 --obis 1.0.99.1.0.255 --last 4
pydlms push /dev/ttyUSB0 --framing mbus --key 36C666... --profile netz-noe-p1
pydlms decode 7EA08BCEFF0313EEE1E6E700E04000... --key ... --auth-key ...
pydlms simulate --port 4059        # a local meter to try things against
```

### Debugging a meter

`-v` logs every frame and APDU, `-vv` adds hexdumps. `--record session.hex`
saves a session; `pydlms decode --file session.hex` explains it layer by
layer, `pydlms simulate --replay session.hex` serves it again as a test
meter, and `pydlms redact` removes serial numbers, system titles and secrets
before you share it. Keys never appear in logs or `repr`.

## Verification status

pydlms is an unofficial implementation. It is checked against public sources
and other implementations, not certified: DLMS UA certifies meters, and no
certification exists for client libraries.

- **Target editions**: Green Book Ed. 12 (IEC 62056-5-3:2023) and Blue Book
  Ed. 17, written from the public DLMS UA excerpts, national adoptions,
  companion standards and published test vectors. Details no public source
  confirms are marked *unverified* in the code.
- **Cross-checked** against Gurux (.NET and C), OpenMUC jDLMS, cB-Sigma dlms,
  dlms-cosem, the Rust DLMS crates and opendlms, with Wireshark decoding the
  frames pydlms builds, and 16 real meter push captures.
- **Not yet**: tested in a live session with a real meter. Push setup v3,
  Disconnect control v2 and the Attestation class from recent Blue Book
  editions are not modelled yet.

Reports from real meters help most: please use the
[meter compatibility](https://github.com/f0rw4rd/pydlms/issues/new?template=device_compat.yml)
issue template. Only connect to meters you own or are authorised to read.

## Development

```bash
git clone https://github.com/f0rw4rd/pydlms.git
cd pydlms
pip install -e ".[dev]"
pytest                    # unit, crypto known-answer tests, real captures, end to end
pytest -m integration     # serial PTY, Gurux simulator, interop peers (Docker)
```

See [CONTRIBUTING.md](https://github.com/f0rw4rd/pydlms/blob/main/CONTRIBUTING.md)
before opening a pull request.

## Support

If you find this project useful, consider supporting development:

[![Ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/f0rw4rd)

## License

Dual-licensed under
[GPL-3.0](https://github.com/f0rw4rd/pydlms/blob/main/LICENSE) and a
[commercial license](https://github.com/f0rw4rd/pydlms/blob/main/LICENSE-COMMERCIAL.md).

Free for open source use under GPL-3.0. If you want to use pydlms in
proprietary products without GPL obligations, a commercial license is
available. Third-party test vectors and reference material are listed in
[THIRD_PARTY.md](https://github.com/f0rw4rd/pydlms/blob/main/THIRD_PARTY.md).

## Trademarks

All marks belong to their owners; used nominatively to describe
interoperability; no endorsement implied.
