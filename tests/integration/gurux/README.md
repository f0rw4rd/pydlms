# Gurux DLMS simulator interop target

[Gurux.DLMS.Simulator.Net](https://github.com/Gurux/Gurux.DLMS.Net/tree/development/Gurux.DLMS.Simulator.Net)
(GPL-2.0-only) used as a black-box meter for `pytest -m integration`. It is
built from source in the container and only reached over TCP; none of its
code or templates are copied into pydlms.

- Source: `https://github.com/Gurux/Gurux.DLMS.Net`, commit
  `6f263019caab62eb038dad7b1fa130edc7097081` (2026-09-22), pinned in the
  `Dockerfile` (`GURUX_COMMIT` build arg). The standalone
  `Gurux.DLMS.Simulator.Net` repository no longer exists; the simulator is a
  subdirectory of `Gurux.DLMS.Net`.
- The Dockerfile patches its local copy: library built for `netstandard2.1`
  only, simulator retargeted from `net9.0` to `net8.0`, and the
  `Console.ReadKey()` wait loop replaced by a sleep when stdin is not a
  console (otherwise it exits under `docker run` without `-it` or `nohup`).

## Build and run

```bash
docker build -t pydlms-gurux-sim tests/integration/gurux

# a. LN, no security, TCP/IP wrapper
docker run -d --rm --name gurux-wrapper -p 127.0.0.1:4061:4060 pydlms-gurux-sim
# b. LN, HDLC over TCP
docker run -d --rm --name gurux-hdlc -p 127.0.0.1:4062:4060 -e SIM_IFACE=HDLC pydlms-gurux-sim
# c. same template, used for the HLS / ciphered associations
docker run -d --rm --name gurux-hls -p 127.0.0.1:4063:4060 pydlms-gurux-sim
```

Environment variables: `SIM_PORT` (in-container port, default 4060),
`SIM_IFACE` (`WRAPPER` or `HDLC`), `SIM_TEMPLATE` (file name under
`/templates`, or an absolute path to a template mounted with `-v`),
`SIM_TRACE` (`Error`, `Warning`, `Info`, `Verbose`; `Verbose` logs every
frame). Extra arguments after the image name go to the simulator.

Without docker (8.0 SDK): apply the three `sed` edits from the Dockerfile to
a checkout of the pinned commit, then

```bash
dotnet build -c Release -o out Gurux.DLMS.Simulator.Net/Gurux.DLMS.Simulator.Net.csproj
nohup dotnet out/Gurux.DLMS.Simulator.Net.dll -p 4061 -i WRAPPER -t Verbose \
    -x Gurux.DLMS.Simulator.Net/GMacWithAuthenticationEncyption.xml </dev/null >sim.log 2>&1 &
```

Do not pass `-h`: it makes the simulator rewrite IP setup objects in the
template from the host's interfaces.

## Default template: `GMacWithAuthenticationEncyption.xml`

The only shipped template with both a no-security association and a
ciphered HLS one. All associations use server logical address 1 (HDLC:
server upper address 1, lower/physical address default).

| Client SAP | Association LN | Mechanism | Context | Notes |
|---|---|---|---|---|
| 16 | 0.0.40.0.1.255 | 0 none | LN (1) | conformance GET only |
| 18 | 0.0.40.0.3.255 | 2 HLS (manufacturer specific) | LN (1) | secret `Gurux` |
| 1 | 0.0.40.0.4.255 | 5 HLS-GMAC | LN ciphered (3) | suite 0, see keys below |
| 44 | 0.0.40.0.9.255 | 7 HLS-ECDSA | LN (1) | suite 1, policy 0xFC; keys in the template |

Keys for client 1 (security setup 0.0.43.0.0.255, suite 0, AES-GCM-128):

- block cipher key (GUEK): `000102030405060708090A0B0C0D0E0F`
- authentication key (GAK): `D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF`
- broadcast key (GBEK): `000102030405060708090A0B0C0D0E0F`
- KEK: `31313131313131313131313131313131`
- server system title: `4752580000000001` (`GRX\0\0\0\0\x01`)
- client system title: any 8 octets (tested with `GXClient`)
- client invocation counter must be greater than the value of
  0.0.43.1.0.255 (43 in the template). The server answers SC `0x30`
  (authenticated and encrypted) even though the security setup has no
  policy set.

Objects in the association view of client 16 (values as read by pydlms):

| OBIS | Class | Attribute value |
|---|---|---|
| 0.0.42.0.0.255 | 1 Data | octet-string `GRX2` (logical device name) |
| 0.0.43.1.0.255 | 1 Data | double-long-unsigned 43 (invocation counter) |
| 0.0.43.1.1.255 | 1 Data | double-long-unsigned 149 |
| 0.0.0.1.0.0 | 3 Register | value visible-string `"220"`, scaler_unit (0, 35 = V) |
| 0.0.1.0.0.255 | 8 Clock | host's current local time, deviation 0, status 0 |
| 1.0.99.1.0.255 | 7 Profile generic | capture objects clock/2 and 0.0.0.1.0.0/2, capture period 1 |
| 0.0.40.0.0.255, 0.0.40.0.1.255 | 15 Association LN | |

Client 1 sees 0.0.40.0.0.255, 0.0.42.0.0.255, 0.0.43.1.0.255,
0.0.43.0.0.255 (class 64) and 0.0.40.0.4.255; the clock is not in its view
and GET on it returns `read-write-denied`.

## Other shipped templates (`/templates`)

`crystal.xml`: client 16 no auth; device name `CRY0000AS0000001`, serial
0.0.96.1.0.255 `AS0000001`, clock, 0.0.43.1.2..5.255.
`Templates/LN-v{2,3}-*.xml` are minimal (3 to 8 objects: the logical device
name 0.0.42.0.0.255, 0.0.43.1.x.255 counters and the association). pydlms
results are from the run on 2026-10-11:

| Template | Client SAP | Mechanism | pydlms |
|---|---|---|---|
| LN-v2-Low.xml | 17 | 1 LLS, password `Gurux` | works |
| LN-v2-High.xml, LN-v3-High.xml | 18 | 2 HLS (manufacturer specific), secret `Gurux` | works (tested via client 18 of the default template) |
| LN-v3-Low.xml | 18 | 1 LLS, password `Gurux` | not tried |
| LN-v2-Md5.xml | 1 | 3 HLS-MD5, secret `Gurux` | works |
| LN-v2-Sha1.xml | 1 | 4 HLS-SHA1, secret `Gurux` | not tried |
| LN-v2-Sha256.xml | 1 | 6 HLS-SHA256, secret `Gurux` | needs a client system title |
| LN-v2-GMac.xml | 16 none (GET only) + 1 GMAC | GMAC ctx 1, policy 3 |
| LN-v2-GMacWithAuthenticationEncyption*.xml | 16 none + 1 GMAC | GMAC ctx 3, policy 3 |

All GMAC templates use the keys and server system title listed above.

## Known simulator quirks

- The RLRE it sends has wrong BER lengths, for example
  `63 11 80 01 00 BE 0F 04 0E 08 00 06 5F 1F 04 00 00 00 10 04 00 00 07`:
  the outer length says 17 but 21 octets follow, and `BE 0F` wraps 16
  octets. pydlms logs `release failed: BER value of tag 0x00 runs past the
  end`; the association is released anyway, with
  `Association.release_status == "failed"` (also in ciphered contexts), so
  `require_verified_release=True` cannot be used against this simulator.
