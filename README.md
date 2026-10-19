# pydlms

A DLMS/COSEM client library for Python (IEC 62056), with packet definitions
expressed using the [`construct`](https://construct.readthedocs.io/) declarative
binary library.

DLMS/COSEM is the dominant smart-meter protocol across Europe and much of the
world. `pydlms` aims to be a **maintained, readable, well-tested** client
that talks to as many real meters as possible: over TCP, over HDLC (serial /
optical), over a wired M-Bus, and over the M-Bus customer ports used by
Austrian and other EU operators.

> Status: **alpha**, pre-1.0. The API is unstable.

## Features

- **Transports:** TCP and UDP with the IEC 62056-47 wrapper; HDLC (IEC
  62056-46) over TCP or serial with parameter negotiation (including the
  SNRM/UA user data subfield), segmentation and an opt-in transmit window
  > 1 with go-back-N recovery (`--hdlc-window N`), and opt-in ISO/IEC 13239
  modulo-128 numbering (SNRME, windows up to 127, `--hdlc-modulo 128`) that
  falls back to SNRM when the meter refuses it; unconfirmed and broadcast
  sends (HDLC UI frames, the wrapper broadcast wPort) and the HDLC push
  trigger; HDLC inter-octet and inactivity time-outs (`LinkLostError`
  instead of sending into a link the meter has dropped);
  IEC 62056-21 optical mode E sign-on and mode C data readout, with the
  break (B0), sign-off (B1) and the normal and fast wake-up of
  battery-powered meters; M-Bus
  long-frame customer ports (segmented pushes, and single-frame APDUs
  behind a long or short M-Bus data header, CI 0x60/0x61/0x7C/0x7D;
  M-Bus-layer encryption is refused); DLMS over a wired M-Bus (IEC
  62056-7-3) with the client as M-Bus master over a serial line (2400 8E1)
  or a TCP gateway: SND_NKE, SND_UD segments and REQ_UD2 polling with the
  FCB rules, repetition of lost answers, primary or secondary addressing
  (`DlmsClient.mbus`, `mbus://`, `mbus+tcp://`; link layer checked
  against libmbus and mbus-device, no DLMS-capable wired M-Bus peer
  exists); any pyserial URL
  (`rfc2217://`, `socket://`).
- **Association:** AARQ/AARE/RLRQ/RLRE, conformance negotiation,
  Logical-Name and Short-Name referencing, every authentication level:
  none, LLS, HLS manufacturer (mechanism 2), MD5, SHA-1, GMAC, SHA-256, ECDSA.
- **Services:** GET / SET / ACTION including block transfer (both
  directions, ACTION return data in pblocks), with-list (`get_many`,
  `set_many`, `action_many`; lists too long for the meter's PDU are split,
  and an item that still does not fit goes as SET/ACTION
  with-list-and-first-block) and selective access (by range / entry),
  general-block-transfer both ways (long requests sent in windowed GBT
  blocks when negotiated, opt-in proposal with `propose_gbt=True`; a lost
  block is asked for again in either direction, bounded by
  `gbt_max_retransmissions`), the ACCESS service (`access`: gets, sets
  and actions in one request, opt-in `propose_access=True`), a split
  Long-Invoke-Id-And-Priority
  (`pydlms.apdu.xdlms.long_invoke_id`), push decoding of DataNotification (full, flat,
  self-descriptive and compact payloads), EventNotification and SN
  InformationReport, SN Read/Write requests too long for the meter's PDU in
  read-/write-data-block-access blocks, Security Setup key transfer and key
  agreement (`transfer_keys`, `agree_keys`), `security_activate` and the
  certificate methods, firmware
  image transfer (IC 18, `transfer_image`) with resume and resend of lost
  blocks.
- **Security:** suites 0/1/2: AES-GCM authenticated encryption,
  authentication-only and encryption-only, `glo-`/`ded-`/general-glo/general
  ciphering, dedicated keys, broadcast-key sends (`broadcast_set`,
  `broadcast_action`), invocation-counter replay protection that refuses
  IV reuse by construction, AES key wrap, ECDH/ECDSA. Keys never appear in
  `repr` or logs; with a pluggable crypto provider they need not be in the
  process at all (HSM, TPM, KMS). Compressed APDUs (security-control bit 7)
  are refused unless `SecurityContext(decompressor=...)` is set; the hook
  runs only after the tag verified (suites 1/2, general ciphering
  envelopes). `v44_decompressor()` is an opt-in ITU-T V.44 packet-method
  decoder for it; DLMS does not negotiate the V.44 parameters, so its
  defaults (annex B.1.2: 1525 codewords, strings up to 255) may need
  setting per meter.
- **COSEM model:** interface-class registry, date/time types, units and
  scalers, association access rights (Association LN v0 to v3), OBIS name
  catalogue, profiles for compact pushes (Norwegian HAN,
  Austrian P1, Wiener Netze), IS 15959 events and event status word,
  association presets (DSMR P3, IS 15959) and DSMR/SMR 5 P1 telegrams (NL, BE, LU Smarty, with CRC and
  ciphering).
- **Debugging:** per-layer logging with hexdumps, a session recorder, a
  layer-by-layer frame explainer (`pydlms decode`), APDU <-> XML conversion,
  a built-in meter simulator and replay of recorded sessions.

## Install

```bash
pip install pydlms-client                 # core (TCP, decode)
pip install "pydlms-client[all]"          # + cryptography (ciphering) + pyserial (serial)
```

The distribution is `pydlms-client` (the name `pydlms` is too close to an
existing PyPI project); the import name is `pydlms`.

## Quick start

Runnable scripts for each topic are in [`examples/`](examples/); they use the
built-in meter simulator unless `DLMS_HOST` is set.

```python
from pydlms import DlmsClient

with DlmsClient.tcp("192.0.2.10", 4059) as meter:          # public client, no security
    print(meter.get_register("1.0.1.8.0.255"))            # e.g. "12345678 Wh"
    print(meter.get_clock())
    for entry in meter.get_association_view():
        print(entry)
```

Secured association (HLS-GMAC, suite 0) over HDLC on a serial port:

```python
from pydlms import DlmsClient, Mechanism, SecurityContext

security = SecurityContext(
    encryption_key=bytes.fromhex("000102030405060708090A0B0C0D0E0F"),
    authentication_key=bytes.fromhex("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF"),
    client_system_title=b"PYDLMS01",
    invocation_counter=1234,          # continue from the meter's last counter
)
with DlmsClient.serial("/dev/ttyUSB0", 9600, client_sap=1,
                       mechanism=Mechanism.HLS_GMAC, security=security) as meter:
    profile = meter.read_profile("1.0.99.1.0.255")
```

A battery-powered meter behind an optical probe sleeps until an IEC 62056-21
Annex B wake-up; `wake_up="fast"` ends the session with the sign-off B1 on
close, and `break_before_sign_on=True` sends the break B0 first (with its
BCC; `break_form="crlf"`, CLI `--optical-break-form crlf`, sends Gurux's
`SOH B0 ETX CR LF` for meters that read lines without an inter-character
timeout):

```python
with DlmsClient.optical("/dev/ttyUSB0", wake_up="fast", break_before_sign_on=True) as meter:
    print(meter.get_register("1.0.1.8.0.255").value)
```

A meter on a wired M-Bus is polled by the client as M-Bus master
(IEC 62056-7-3): `primary_address` is its M-Bus address (0..250, 254 point
to point), or `secondary_address` selects it; `tcp://host:port` reaches an
M-Bus gateway instead of a serial line:

```python
with DlmsClient.mbus("/dev/ttyUSB0", primary_address=5) as meter:   # 2400 8E1
    print(meter.get_register("1.0.1.8.0.255").value)
with DlmsClient.mbus("tcp://192.0.2.20:10001", secondary_address="12345678FFFFFFFF") as meter:
    view = meter.get_association_view()
```

Connection options of the constructors (`tcp`, `udp`, `serial`, `optical`, `mbus`);
invalid values raise `ValueError` before any I/O:

| Option | Endpoints | Meaning |
|---|---|---|
| `client_sap`, `server_logical` | all | client SAP and server logical device (defaults 16 and 1) |
| `server_physical` | HDLC | physical (lower) server address |
| `address_size` | HDLC | server address length 1, 2 or 4 octets (default: shortest that fits) |
| `physical_from_serial=(serial, vendor)` | HDLC | physical address by vendor rule (`landis+gyr`, `elgama`, `emh`, `milur`); not with `server_physical` |
| `hdlc_parameters` | HDLC | SNRM proposal, e.g. `HdlcParameters(window_tx=3)` |
| `hdlc_modulus`, `hdlc_modulus_fallback` | HDLC | `128`: set up with SNRME (modulo-128 numbering, outside IEC 62056-46; windows up to 127 via `HdlcParameters(window_tx=N, modulus=128)`), SNRM if refused unless the fallback is `False`; default 8 |
| `client_wport` | wrapper (`tcp`, `udp`) | source wPort 0-65535 when it differs from `client_sap` |
| `primary_address`, `secondary_address` | M-Bus | the meter's M-Bus address 0..250 (254: test address), or its secondary address (16 hex digits `IIIIIIIIMMMMVVDD`, `F` wildcards) selected through address 253; `client_sap` / `server_logical` are the STSAP / DTSAP |
| `baudrate`, `parity`, `reply_timeout`, `retries`, `max_segment` | M-Bus | line settings (default 2400, `"E"`), reply time-out (default 330 bit periods + 50 ms + 0.25 s, 2 s over TCP), repetitions of a lost answer (2), DLMS octets per segment (250) |
| any other keyword | all | client option (`discover_invocation_counter`, `counter_store`, ...) or an `AssociationSettings` field: `password` (the secret), `mechanism`, `security`, `max_receive_pdu_size`, `conformance`, `protection`, `use_dedicated_key`, `expected_server_system_title`, `gbt_window`, `invocation_counter_retry`, `require_verified_release`, `third_party`, ... |

```python
with DlmsClient.tcp("192.0.2.10", hdlc=True, address_size=4,
                     physical_from_serial=("12345678", "landis+gyr"),
                     max_receive_pdu_size=1024, gbt_window=4) as meter:
    print(meter.get_clock())
```

Profile rows are plain values by default; `typed=True` turns date-time
cells into `CosemDateTime`, and `scalers=True` turns register values into
`RegisterValue` (each register's scaler_unit is read once, then cached):

```python
profile = meter.read_profile("1.0.99.1.0.255", typed=True, scalers=True,
                             fill_timestamps=True)   # rebuild null (compressed) timestamps
for stamp, energy in profile.rows:                   # profile.cells: the raw Data
    print(stamp.to_datetime(), energy)               # 2024-05-01 00:15:00+00:00 1007 Wh

compact = meter.read_compact_data("0.0.66.0.1.255", typed=True)  # Compact data (IC 62)
print(compact.columns, compact.values)
```

Delta-typed cells (data types 28..33) are kept as received. The provisional
opt-in `read_profile(..., resolve_deltas=True)` (also on
`read_compact_data`, or `pydlms.cosem.delta.resolve_deltas` on any `Data`)
adds each delta to the previous absolute value in its column. The Green
Book accumulation rule was not read and no other implementation resolves
deltas, so the reading may change; `cells` keep the raw deltas.

Invocation counters: a ciphered association fails if the client's counter
is not above the last one the meter saw. pydlms can find it for you:

```python
from pydlms.counters import CounterStore

with DlmsClient.tcp("192.0.2.10", client_sap=1, mechanism=Mechanism.HLS_GMAC,
                    security=security,
                    discover_invocation_counter=True,   # read it via the public client
                    invocation_counter_retry=True,      # or retry from the meter's hint
                    counter_store=CounterStore("ic.json")) as meter:  # remember it
    ...
```

Suites 1/2 (ECDH/ECDSA): `SecurityContext(..., suite=1, signing_key=...,
key_agreement_key=..., peer_signing_key=..., peer_key_agreement_key=...)` with
`mechanism=Mechanism.HLS_ECDSA` and `protection="glo"`, `"general-ciphering"`
(identified, wrapped or agreed keys), `"general-signing"` or `"glo+signing"`.
The peer's key and system title can come from its X.509 certificate instead:
`SecurityContext(..., suite=1, peer_certificate=pem_or_der)` (EC key on the
suite's curve, system title as 16 hex characters in the subject CN; see
`pydlms.security.load_certificate`).

general-ciphering and general-signing have two readings in the field: pydlms
and Gurux authenticate `SC || AK` and sign the bare content, cB-Sigma dlms
also authenticates the five header fields and signs the content with its
length. No standard example settles either, so the defaults stay and the
other form is an explicit opt-in per context, used both ways and logged as a
warning: `SecurityContext(..., general_aad=GeneralAad.WITH_HEADER,
signing_form=SigningForm.LENGTH_PREFIXED_CONTENT)`. A peer using the other
form fails closed; the form is never guessed.

Third-party protection (IEC 62056-5-3:2023 annex J, suites 1/2): a third
party such as a head-end with its own keys signs and/or ciphers each request
inside the client's own protection, and the meter answers with its layers for
the third party inside the client's layer. `AssociationSettings(third_party=
ThirdParty(system_title, signing_key=..., policy=SecurityPolicy..., key_agreement_key=...,
authentication_key=...))` applies them to every service APDU; the client's
protection must be `"general-glo"`, `"general-ciphering"` or
`"general-ciphering+signing"`. The third party's general-ciphering always
uses a key agreed for the APDU (one-pass DH or static unified model, IC 0).
Each answer must carry the layers the third party applied (signed and/or
ciphered, verified, in order); the annex J.3 answer with no protection is
refused unless `accept_unprotected_responses=True`. cB-Sigma meters need
`general_aad=GeneralAad.WITH_HEADER, signing_form=SigningForm.LENGTH_PREFIXED_CONTENT`
on the `ThirdParty`. `pydlms.security.thirdparty.nest` / `unnest` are the pure
transforms.

Key management (Security Setup, IC 64): `transfer_keys({KeyId.GLOBAL_UNICAST_ENCRYPTION:
new_key})` wraps new global keys under the context's master key (KEK);
`agree_keys([KeyId.GLOBAL_UNICAST_ENCRYPTION])` (suites 1/2, needs
`signing_key`, `peer_signing_key` and both system titles) runs
`key_agreement`: each side signs a fresh ephemeral key, the meter's
signature and point are checked and the keys come from the ECDH/KDF of
IEC 62056-5-3 annex I.1. Both return without changing the context; the
meter switches after answering, so reconnect with a `SecurityContext`
holding the new keys. Agreeing the master key is refused (its KDF
AlgorithmID is not pinned by a checkable source).
`security_activate(policy)` (method 1) raises the meter's policy: a
`SecurityPolicyV0` value for a version 0 Security Setup, `SecurityPolicyBits`
for version 1. The two encodings overlap, so the version comes from the
association view (or `version=`), never a guess; `refuse_weakening=True`
reads the current policy first and refuses one that drops a protection.
Certificates (methods 4-8, suites 1/2): `generate_key_pair(KeyType...)`,
`certificate_request(KeyType...)` (the PKCS #10 request is parsed and its
curve, ECDSA hash and self-signature checked), `import_certificate(cert)`,
`export_certificate(CertificateSelector.by_entity_type(...)` or
`.by_serial_issuer(...))` returning a `DlmsCertificate`, and
`remove_certificate(selector)`. An exported certificate is **not** trusted
and never installed as `peer_certificate`: pydlms does no chain validation,
so check it against your CA before giving it to a `SecurityContext`.

Keys in an HSM (crypto provider): every key of a `SecurityContext` (and
`AssociationSettings.signing_key` / a mechanism-2 `secret`) may be an opaque
handle of `SecurityContext(..., provider=...)`. The default
`SoftwareProvider` takes raw bytes; any object with `gcm_seal`, `gcm_open`,
`ctr` and `gmac` (plus `aes_ecb_block`, `ecdsa_sign`, `public_key`, `ecdh`
or `ecdh_kdf`, `aes_wrap`/`aes_unwrap`, `key_fingerprint` for the keys
that need them) can hold the keys instead:

```python
from pydlms import SecurityContext

ctx = SecurityContext(hsm.handle("meter-ek"), hsm.handle("meter-ak"),
                      client_system_title=b"PYDLMS01", provider=hsm)
```

The provider computes only primitives; IV, AAD and SC assembly, the
12-octet tag, invocation counters, replay and policy checks stay in pydlms.
Every output is checked (tag length, plaintext type and length, signature
size) and a malformed one raises `CryptoProviderError`; `gcm_open` must
raise `AuthenticationError` on a bad tag, never return a flag. DLMS puts
the authentication key into the GCM AAD, so the provider receives the AAD as
segments with an `AadKey(handle)` marker to resolve inside the HSM. Session
keys pydlms makes itself (dedicated key, unwrapped or ephemeral-agreed
content keys) reach the provider as raw bytes. No PKCS#11 adapter ships in
core; `pydlms/security/provider.py` describes how to write one.

Broadcast: with `SecurityContext(..., broadcast_key=...)` in a ciphered
association (`glo` or `general-glo` protection),
`broadcast_set(obis, class_id, attribute, value)` and
`broadcast_action(obis, class_id, method, params=None)` send an unconfirmed
SET/ACTION ciphered with the global broadcast key to every meter on the link
(wrapper wPort 0x007F, HDLC UI frame to the all-station address) and read
nothing back, so there is no result. The invocation counter is the
context's one outbound counter, shared with unicast APDUs; it cannot be
passed in. **A broadcast key is shared by the whole group:** every meter
holding it can read, and forge, what is sent with it, and one compromised
meter exposes the key for all of them. A broadcast authenticates the group,
not this client.

ACCESS (conformance bit 17) runs several operations in one request. It is
proposed only on request, and `access()` raises `ProtocolError` unless the
meter granted it:

```python
from pydlms import AccessAction, AccessGet, AccessSet, DlmsData

with DlmsClient.tcp("192.0.2.10", propose_access=True) as meter:
    serial, energy, written, cut = meter.access(
        [
            AccessGet("0.0.96.1.0.255"),
            AccessGet("1.0.1.8.0.255", 3, "value"),
            AccessSet("0.0.42.0.0.255", 1, 2, DlmsData.octet_string(b"X")),
            AccessAction("0.0.96.3.10.255", 70, "remote_disconnect", DlmsData.int8(0)),
        ],
        break_on_error=True,   # the meter stops at the first failure
    )
    print(serial.data, energy.ok, written.result, cut.result)
```

Each answer is an `AccessOutcome` (`result`, `data`, `ok`); failures are
results, not exceptions. ACCESS has no `glo-`/`ded-` ciphered form, so in a
ciphered association it goes as general-glo (general-ded with a dedicated
key) even with `protection="glo"` (logged once at INFO);
`protection="glo+signing"` cannot carry it and raises. A request longer
than the meter's PDU needs general-block-transfer.

Pinning the meter: `expected_server_system_title=bytes.fromhex("...")` (8
octets, an association setting, so also a `DlmsClient.tcp(...)` keyword)
makes the association refuse an AARE whose responding-AP-title is another
meter's, or missing, with `AssociationError` before its user-information is
opened or HLS pass 3 is sent. A `server_system_title` given to
`SecurityContext` (or taken from `peer_certificate`) pins the same way; a
setting that contradicts it is refused when the association is built.
**Behaviour change:** before this, a configured `server_system_title` was
silently replaced by the title in the AARE; a context configured with the
wrong title now fails to associate. Leave it unset to learn the title from
the AARE as before.

Release: in a ciphered context the RLRQ carries the AARQ's InitiateRequest
ciphered again, and the meter's RLRE is checked like any reply: its
user-information must be a glo-/ded-InitiateResponse that opens under the
policy and the invocation-counter check (authenticated and encrypted when a
dedicated key was sent). `client.association.release_status` reports
`"plain"`, `"verified"`, `"unverified"` (no authenticated user-information)
or `"failed"`. `require_verified_release=True` makes `close()` raise
`AuthenticationError` when a ciphered release is not verified; the link is
disconnected and the counter stored first. It is off by default because
some servers send a malformed RLRE (the Gurux.DLMS.Net simulator does).

Typed objects (nested structures, arrays and methods of 48 interface classes):

```python
with DlmsClient.tcp("192.0.2.10") as meter:
    clock = meter.object("0.0.1.0.0.255")      # class from the association view
    print(clock.time)                          # CosemDateTime
    clock.shift_time(-30)                      # method with a typed parameter
    profile = meter.object("1.0.99.1.0.255")
    for column in profile.capture_objects:     # list[CaptureObject]
        print(column.logical_name, column.attribute_index)
    meter.object("0.0.96.3.10.255").remote_disconnect()
```

Access rights come with the association view (`entry.rights`, an
`AccessRights` from `pydlms.cosem.access`). `meter.can_read(obis, class_id,
attribute)` answers from them: `True`, `False`, or `None` when the view does
not say (many meters list only the attributes they support).
`CosemObject.read_all()` leaves out attributes the view marks unreadable
(`skip_unreadable=False` reads them anyway); `get()` always asks the meter.

Sending a firmware image (Image transfer, IC 18). This writes to the meter:
use only a meter you own or are authorised to update.

```python
from pathlib import Path
from pydlms import transfer_image

with DlmsClient.tcp("192.0.2.10", client_sap=1, mechanism=..., security=...) as meter:
    result = transfer_image(meter, Path("fw.bin").read_bytes(), b"FW-2.0",
                            activate=False, progress=lambda n, total: print(n, total))
    print(result.blocks, result.rounds, result.status)
```

It checks `image_transfer_enabled` and the block size against the
negotiated PDU before writing anything, resumes a partial transfer, resends
the blocks the meter's bit-string reports missing (`max_rounds`), and polls
`image_transfer_status` while the meter verifies or activates. A meter that
drops the association on activation yields `activation_confirmed=False`.

Decoding pushes from a customer interface:

```python
from pydlms import PushDecoder, SecurityContext
from pydlms.profiles import get_profile
from pydlms.security.suites import SecurityPolicy

# Netz NÖ pushes are encrypted only (SC 0x20): say so, or they are refused.
security = SecurityContext(bytes.fromhex("36C6..."), policy=SecurityPolicy.ENCRYPTED)
decoder = PushDecoder("mbus", security, profile=get_profile("netz-noe-p1"))
for message in decoder.feed(serial_bytes):
    print(message.get("1.0.1.8.0.255"), message.get("1.0.32.7.0.255"))
```

When the push setup's `push_object_list` is known (read attribute 2 of the
IC 40 object, or list it), decode positionally instead of by heuristics; IDIS
pushes need this because they carry no OBIS labels:

```python
objects = [(40, "0.0.25.9.0.255", 1), (1, "0.0.42.0.0.255", 2),
           (8, "0.0.1.0.0.255", 2), (3, "1.0.1.8.0.255", 2)]
decoder = PushDecoder("hdlc", capture_objects=objects)

# or let the meter say: GET attribute 2 of the push setup (default 0.0.25.9.0.255)
with DlmsClient.tcp("192.0.2.10", 4059) as meter:
    decoder = meter.push_decoder_from_meter(framing="mbus")
```

A malformed list (not an array of 4-field structures, or empty) raises
`DecodeError`. `pydlms push --capture-objects FILE` takes the list from a file,
`--from-meter URL` reads it from the meter (`--push-setup`, `--meter-client`,
`--meter-password`). The file is text, one `class_id obis attribute [data_index]`
per line with `#` comments, or a JSON array of `[class_id, "obis", attribute
[, data_index]]` arrays or `{"class_id", "logical_name", "attribute_index",
"data_index"}` objects:

```
40 0.0.25.9.0.255 1
3  1.0.1.8.0.255  2   # active energy import
```

Inbound ciphered APDUs must meet the context's `policy` (authenticated
and/or encrypted) and `suite`; an APDU whose security control asks for less
raises `AuthenticationError`, because the sender chooses that byte.

A meter that pushes on the association's own connection does not disturb a
request: a DataNotification, EventNotification or InformationReport arriving
before the response is checked like a reply (policy, counter, system title),
queued, and returned once by `meter.read_push()`. Over the wrapper, pushes to
another client wPort are queued with `WrapperLink(..., push_wports={0x66})`.

Companion standards fix the client SAP, mechanism and security of their
associations; `pydlms.profiles.presets` carries them as data (DSMR 4.2.2 P3,
IS 15959). Keys stay yours:

```python
from pydlms.profiles.presets import get_preset

preset = get_preset("dsmr-p3-management")   # client 1, HLS-GMAC, suite 0, policy 3
with DlmsClient.tcp("192.0.2.10", security=context, **preset.client_kwargs()) as meter:
    ...
```

IS 15959 never names its HLS mechanism id; its presets default to HLS 2
(AES-128, what field implementations use) and take another one from
`client_kwargs(mechanism=...)`. `pydlms.profiles.india` adds the IS 15959
event codes and `decode_esw()` for the 128-bit event status word of
IS 15959-2 event pushes.

## CLI

```bash
pydlms read tcp://192.0.2.10:4059 --obis 1.0.1.8.0.255 --register
pydlms list tcp+hdlc://192.0.2.10:4059 --auth lls --password 12345678  # access: r=1-3 w=2 x=1
pydlms read tcp+hdlc://192.0.2.10 --hdlc-window 7 --obis 1.0.1.8.0.255   # up to 7 frames per ack
pydlms read tcp+hdlc://192.0.2.10 --hdlc-modulo 128 --hdlc-window 32 --obis 1.0.1.8.0.255  # SNRME
pydlms clock tcp+hdlc://192.0.2.10 --address-size 4 --physical-from-serial 12345678:landis+gyr
pydlms profile serial:///dev/ttyUSB0?baud=9600 --obis 1.0.99.1.0.255 --last 4
pydlms clock optical:///dev/ttyUSB0 --optical-wake-up fast --optical-break  # battery meter
pydlms read mbus:///dev/ttyUSB0?address=5 --obis 1.0.1.8.0.255 --register  # wired M-Bus, 2400 8E1
pydlms list mbus+tcp://192.0.2.20:10001?secondary=12345678FFFFFFFF          # M-Bus gateway
pydlms profile tcp://192.0.2.10 --obis 1.0.99.1.0.255 --typed --scalers  # dates and "1007 Wh"
pydlms push /dev/ttyUSB0 --framing mbus --key 36C666... --profile netz-noe-p1  # --suite 1 for Kaifa
pydlms push - --framing raw --capture-objects objects.txt     # positional decode, no OBIS labels needed
pydlms push /dev/ttyUSB0 --from-meter tcp://192.0.2.10:4059   # read the list from the meter, then listen
pydlms decode 7EA08BCEFF0313EEE1E6E700E04000... --key ... --auth-key ...
pydlms read tcp://meter --client 1 --auth gmac --key ... --auth-key ... \
    --discover-ic --ic-store ic.json --obis 1.0.1.8.0.255
pydlms image-transfer tcp://meter fw.bin --identifier 4657322E30 --activate --yes
pydlms simulate --port 4059          # a local meter to try things against
pydlms simulate --hdlc --hdlc-window 3   # HDLC meter offering a receive window of 3
pydlms simulate --hdlc --hdlc-modulo 128 --hdlc-window 64   # also takes SNRME
pydlms --record raw.hex clock tcp://meter && pydlms redact raw.hex -o session.hex
pydlms discover-ic tcp://meter --report   # invocation-counter evidence, no values
```

`image-transfer` writes to the meter and refuses to run without `--yes`.

`--auth` accepts `none lls hls md5 sha1 gmac sha256 ecdsa`; ECDSA takes PEM keys
via `--signing-key` / `--server-key`.

The constructor options have flags: `--address-size 1|2|4`,
`--physical-from-serial SERIAL:VENDOR` (HDLC endpoints only),
`--client-wport N` (`tcp://`, `udp://` only), `--max-pdu N`,
`--conformance 007E1F` or `--conformance get,set,selective_access`,
`--protection glo|general-glo|general-ciphering|general-signing|glo+signing|general-ciphering+signing`
and `--dedicated-key` (both need `--key`), `--client-title HEX` (alias of
`--system-title`), `--expect-server-title HEX`, `--gbt-window N`,
`--invocation-counter-retry` (alias of `--ic-retry`) and
`--require-verified-release`. A flag on an endpoint it does not apply to
exits with a message, like `--hdlc-window` on `tcp://`.

HDLC modulo 128 is not part of IEC 62056-46 and no DLMS meter is known to
need it; it exists for ISO/IEC 13239 peers. `--hdlc-modulo 128` sends SNRME
and, if the meter answers DM or FRMR or nothing, SNRM with the window capped
to 7 (`--no-hdlc-modulo-fallback` makes that an error). `pydlms decode`
and recordings follow an SNRME/UA exchange by themselves;
`decode --hdlc-modulo 128` reads a capture that starts after it.

## Debugging a meter

- `-v` logs one line per frame and APDU; `-vv` adds hexdumps of every buffer
  (`TRACE`). `--log-layers hdlc,security` narrows it down. From Python:
  `pydlms.enable_debug("TRACE", layers=["hdlc"])`.
- `--record session.hex` writes every TX/RX buffer plus the deciphered
  APDUs; `pydlms decode --file session.hex` shows each layer annotated (frame
  fields, checksum verdicts, segmentation, security header, deciphered APDU,
  data tree with OBIS names).
- `pydlms simulate --replay session.hex` serves the recorded meter again, so a
  field problem becomes a test without the meter (keys and client profiles via
  `--key`, `--auth-key`, `--client 1:5`).
- `pydlms redact session.hex -o shareable.hex` replaces serial numbers, the
  logical device name (after its FLAG id), system titles, the LLS password,
  HLS challenges and other identifying attributes with same-length
  placeholders, rebuilds HCS/FCS and wrapper lengths, and drops raw
  AARQ/AARE and ciphered frames unless `--test-keys`. The result still
  decodes and replays; the scrub log shows counts only. Do this before
  attaching a recording anywhere.
- `pydlms discover-ic ENDPOINT --report` prints, as JSON for an issue, where
  the meter keeps its invocation counters (object list, vendor table or blind
  probing) through the public client, without counter values, serials or
  system titles.
- `pydlms decode --file session.hex --xml > session.xml` writes the session as
  XML; `pydlms encode session.xml` turns it (edited or not) back into APDUs,
  `--recording` into a file `--replay` accepts. Passwords, challenges and
  dedicated keys are redacted unless `--show-secrets`. `--dialect gurux`
  writes the Gurux translator ("simple XML") dialect instead, and `encode`
  reads either, including XML that Gurux tools wrote. Gurux's own output
  drops data for a few APDUs (error results in GET-with-list, the
  ExceptionResponse invocation counter, NULs and non-ASCII in strings);
  pydlms writes the complete form there, and anything the dialect cannot hold
  stays a `<Raw>` element so the bytes survive. Neither format is the DLMS UA
  XML schema.
- Errors name the layer and the reason (`AssociationError` with the AARE
  diagnostic, `ServiceError` with the data-access result, `ReplayError`,
  `AuthenticationError`, `ChecksumError`).
- Key material is redacted in every `repr` and log line.

## Verification status

pydlms is an unofficial implementation, checked against public sources and
other implementations; it is not certified. DLMS UA certifies meters
(servers): its test tool is itself a client, and no certification exists for
a client library.

- **Target editions:** Green Book Ed. 12 (DLMS UA 1000-2, IEC 62056-5-3:2023)
  and Blue Book Ed. 17 (DLMS UA 1000-1). The code is written from the public
  DLMS UA excerpts, national adoptions, companion standards and published
  test vectors, not from the full member-only texts. Clauses no public source
  confirms are marked *unverified* in the code (52 places).
- **Cross-checked:** interop runs against Gurux (.NET and C), OpenMUC jDLMS,
  cB-Sigma dlms (Go), dlms-cosem (Python), the Rust DLMS crates and opendlms;
  frames pydlms builds are decoded by Wireshark's `tshark`; 16 real meter
  push captures decode end to end.
- **Not yet:** no recorded client session with a real meter. Recent Blue
  Book class versions are not modelled: Push setup v3 and Disconnect control
  v2 objects get the attribute names of v2 and v0 (attributes added later are
  reachable by index only), and the Attestation class (170) is unknown, so
  its attributes are plain Data.

Reports from real meters are the most useful contribution: see the device
compatibility issue template.

## Testing

```bash
pip install -e ".[dev]"
pytest                    # unit, crypto (KATs), real-meter captures, end to end
pytest -m integration     # socat PTY serial/optical/M-Bus, Gurux simulator, interop peers (docker)
```

The suite includes Green Book, NIST and RFC known-answer vectors, per-byte
tamper tests, 16 real meter captures (Kaifa, Landis+Gyr, Iskra, Kamstrup,
Sagemcom, Aidon, ...) decoded end to end and checked against independently
produced values, and full client sessions against the simulator for every
authentication level. Changes involving a real meter must be tested against a
meter you own or are authorised to read.

## License

`pydlms` is dual-licensed:

- **Open source:** [GNU General Public License v3.0](https://github.com/f0rw4rd/pydlms/blob/main/LICENSE).
- **Commercial / OEM:** see [LICENSE-COMMERCIAL.md](https://github.com/f0rw4rd/pydlms/blob/main/LICENSE-COMMERCIAL.md) for use
  in proprietary products without GPL obligations.

Third-party reference material and test vectors, with their own licenses, are
listed in [THIRD_PARTY.md](https://github.com/f0rw4rd/pydlms/blob/main/THIRD_PARTY.md).
