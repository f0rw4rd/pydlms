"""``pydlms`` command line.

::

    pydlms read  tcp://192.0.2.10:4059 --obis 1.0.1.8.0.255 --register
    pydlms list  tcp+hdlc://192.0.2.10:4059 --auth lls --password 12345678
    pydlms clock serial:///dev/ttyUSB0?baud=9600
    pydlms profile tcp://meter --obis 1.0.99.1.0.255 --last 4
    pydlms push  /dev/ttyUSB0 --framing mbus --key 36C666... --profile netz-noe-p1
    pydlms decode 7EA08BCEFF0313... --key ... --auth-key ...
    pydlms decode --file session.hex --xml > session.xml
    pydlms decode --file session.hex --xml --dialect gurux > gurux.xml
    pydlms encode session.xml --recording > edited.hex
    pydlms simulate --port 4059 --replay edited.hex
    pydlms redact session.hex -o session.redacted.hex
    pydlms discover-ic tcp://meter --report
    pydlms image-transfer tcp://meter fw.bin --identifier 4657322E30 --yes

Endpoints: ``tcp://host[:port]`` (IEC 62056-47 wrapper), ``tcp+hdlc://``,
``udp://``, ``serial://<device>?baud=9600`` (HDLC), ``optical://<device>``
(IEC 62056-21 mode E; ``--optical-wake-up normal|fast`` wakes a
battery-powered meter, ``--optical-break`` sends B0 first),
``mbus://<device>?address=5`` (wired M-Bus, IEC 62056-7-3; ``baud=2400``,
``parity=E``, ``secondary=<16 hex digits>`` instead of ``address``),
``mbus+tcp://host:port?address=5`` (wired M-Bus through a TCP gateway), or a
bare device path (serial).

Addressing and association: ``--address-size 1|2|4`` and
``--physical-from-serial SERIAL:VENDOR`` (HDLC endpoints), ``--client-wport``
(wrapper endpoints), ``--max-pdu``, ``--conformance``, ``--protection``,
``--dedicated-key``, ``--client-title``, ``--expect-server-title``,
``--gbt-window``, ``--invocation-counter-retry`` and
``--require-verified-release`` map to the DlmsClient constructor options and
AssociationSettings fields of the same meaning.

Debugging: ``-v`` logs one line per frame/APDU, ``-vv`` adds hexdumps of every
buffer (TRACE); ``--log-layers hdlc,security`` limits output to those layers;
``--record FILE`` writes every TX/RX buffer as hex plus the deciphered
TX-APDU/RX-APDU lines, readable with ``pydlms decode --file FILE`` (``--xml``
for XML) and servable with ``pydlms simulate --replay FILE``. Keys are never
logged.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
from urllib.parse import parse_qs, urlparse

from pydlms import __version__
from pydlms.association import MIN_SERVER_MAX_PDU
from pydlms.debug import TRACE, FrameRecorder, enable_debug
from pydlms.exceptions import DlmsError
from pydlms.hdlc.address import SERIAL_ADDRESS_RULES
from pydlms.obis import ObisCode
from pydlms.security.hls import Mechanism

__all__ = ["main", "build_client", "parse_endpoint"]

_AUTH = {
    "none": Mechanism.NONE,
    "lls": Mechanism.LLS,
    "hls": Mechanism.HLS,
    "ecdsa": Mechanism.HLS_ECDSA,
    "md5": Mechanism.HLS_MD5,
    "sha1": Mechanism.HLS_SHA1,
    "gmac": Mechanism.HLS_GMAC,
    "sha256": Mechanism.HLS_SHA256,
}


#: Values of AssociationSettings.protection (Association._protect).
_PROTECTIONS = (
    "glo",
    "general-glo",
    "general-ciphering",
    "general-signing",
    "glo+signing",
    "general-ciphering+signing",
)

#: Smallest --max-pdu: the floor pydlms already applies to the server's
#: max-receive-pdu-size (pydlms.association.MIN_SERVER_MAX_PDU).
_MIN_PDU = MIN_SERVER_MAX_PDU


def _title(value: str | None, flag: str) -> bytes | None:
    raw = _hex(value)
    if raw is not None and len(raw) != 8:
        raise SystemExit(f"{flag} must be 8 octets of hex, got {len(raw)}")
    return raw


def _conformance(text: str):
    """--conformance: hex (``007E1F``, ``0x7e1f``) or a comma list of names."""
    from pydlms.apdu.xdlms import Conformance

    digits = text.strip().lower().removeprefix("0x")
    if digits and all(ch in "0123456789abcdef" for ch in digits):
        value = int(digits, 16)
        if value > 0xFFFFFF:
            raise SystemExit(f"--conformance {text!r} is wider than the 24-bit block")
    else:
        value = 0
        for name in text.split(","):
            key = name.strip().upper().replace("-", "_")
            if key not in Conformance.__members__:
                known = ", ".join(m.lower() for m in Conformance.__members__)
                raise SystemExit(f"--conformance: unknown bit {name.strip()!r} (known: {known})")
            value |= Conformance[key]
    if value == 0:
        raise SystemExit("--conformance must set at least one bit")
    return Conformance(value)


def _physical_from_serial(text: str) -> tuple[str, str]:
    serial, sep, vendor = text.rpartition(":")
    if not sep or not serial or not vendor:
        raise SystemExit(f"--physical-from-serial wants SERIAL:VENDOR, got {text!r}")
    if vendor.lower() not in SERIAL_ADDRESS_RULES:
        known = ", ".join(sorted(SERIAL_ADDRESS_RULES))
        raise SystemExit(f"--physical-from-serial: no rule for vendor {vendor!r} (known: {known})")
    return serial, vendor


def _hex(value: str | None) -> bytes | None:
    if value is None:
        return None
    cleaned = value.replace(" ", "").replace(":", "")
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        raise SystemExit(f"not a hex string: {value!r}") from None


def parse_endpoint(text: str) -> tuple[str, dict]:
    """Split an endpoint into ``(kind, params)``."""
    if "://" not in text:
        return "serial", {"port": text}
    url = urlparse(text)
    query = {k: v[-1] for k, v in parse_qs(url.query).items()}
    scheme = url.scheme.lower()
    if scheme in ("tcp", "tcp+hdlc", "udp"):
        if not url.hostname:
            raise SystemExit(f"endpoint {text!r} has no host")
        return scheme, {"host": url.hostname, "port": url.port or 4059, **query}
    if scheme in ("serial", "optical", "mbus"):
        device = (url.netloc + url.path) or query.get("port", "")
        return scheme, {"port": device, **query}
    if scheme == "mbus+tcp":
        if not url.hostname or url.port is None:
            raise SystemExit(f"endpoint {text!r} needs a host and a port")
        return scheme, {"host": url.hostname, "port": url.port, **query}
    raise SystemExit(f"unsupported endpoint scheme {scheme!r}")


def _association_options(args, ciphered: bool) -> dict:
    """AssociationSettings fields from the common flags, validated."""
    out: dict = {}
    if args.max_pdu is not None:
        if not _MIN_PDU <= args.max_pdu <= 0xFFFF:
            raise SystemExit(f"--max-pdu must be {_MIN_PDU}-65535, got {args.max_pdu}")
        out["max_receive_pdu_size"] = args.max_pdu
    if args.conformance is not None:
        out["conformance"] = _conformance(args.conformance)
    for flag, value in (("--protection", args.protection), ("--dedicated-key", args.dedicated_key)):
        if value and not ciphered:
            raise SystemExit(f"{flag} needs ciphering (--key)")
    if args.protection is not None:
        out["protection"] = args.protection
    if args.dedicated_key:
        out["use_dedicated_key"] = True
    title = _title(args.expect_server_title, "--expect-server-title")
    if title is not None:
        out["expected_server_system_title"] = title
    if args.gbt_window is not None:
        if not 1 <= args.gbt_window <= 63:
            raise SystemExit(f"--gbt-window must be 1-63, got {args.gbt_window}")
        out["gbt_window"] = args.gbt_window
    if args.require_verified_release:
        out["require_verified_release"] = True
    return out


def _addressing_options(args, kind: str) -> dict:
    """Constructor addressing keywords from the common flags; HDLC-only and
    wrapper-only flags are refused on the other endpoints."""
    out: dict = {}
    hdlc = kind in _HDLC_KINDS
    if args.address_size is not None:
        if not hdlc:
            raise SystemExit("--address-size needs an HDLC endpoint (tcp+hdlc, serial, optical)")
        out["address_size"] = args.address_size
    if args.physical_from_serial is not None:
        if not hdlc:
            raise SystemExit(
                "--physical-from-serial needs an HDLC endpoint (tcp+hdlc, serial, optical)"
            )
        if args.physical is not None:
            raise SystemExit("give --physical or --physical-from-serial, not both")
        out["physical_from_serial"] = _physical_from_serial(args.physical_from_serial)
    if args.client_wport is not None:
        if kind not in ("tcp", "udp"):
            raise SystemExit("--client-wport needs a wrapper endpoint (tcp://, udp://)")
        out["client_wport"] = args.client_wport
    return out


_HDLC_KINDS = ("tcp+hdlc", "serial", "optical")
_MBUS_KINDS = ("mbus", "mbus+tcp")


def _mbus_client(args, kind: str, params: dict, common: dict, settings: dict):
    """DlmsClient.mbus for an ``mbus://`` or ``mbus+tcp://`` endpoint."""
    from pydlms.client import DlmsClient

    if args.physical is not None:
        raise SystemExit("--physical needs an HDLC endpoint; M-Bus takes ?address=")
    secondary = params.get("secondary")
    if secondary is not None and "address" in params:
        raise SystemExit("give ?address= or ?secondary=, not both")
    try:
        address = int(params.get("address", 0))
    except ValueError:
        raise SystemExit(f"M-Bus address {params['address']!r} is not a number") from None
    if kind == "mbus+tcp":
        target = f"tcp://{params['host']}:{params['port']}"
        line = {}
    else:
        target = params["port"]
        if not target:
            raise SystemExit("mbus:// endpoint needs a device")
        parity = params.get("parity", "E").upper()
        if parity not in ("N", "E", "O"):
            raise SystemExit(f"M-Bus parity must be N, E or O, not {parity!r}")
        line = {"baudrate": int(params.get("baud", 2400)), "parity": parity}
    return DlmsClient.mbus(
        target, address, secondary_address=secondary, **line, **common, **settings
    )


def build_client(args):
    from pydlms.client import DlmsClient

    kind, params = parse_endpoint(args.endpoint)
    security = None
    if args.key:
        from pydlms.security.context import SecurityContext

        security = SecurityContext(
            _hex(args.key),
            _hex(args.auth_key),
            client_system_title=_title(args.system_title, "--system-title/--client-title")
            or b"PYDLMS01",
            invocation_counter=args.invocation_counter,
        )
    settings = {
        "mechanism": _AUTH[args.auth],
        "password": args.password,
        "security": security,
        "logical_names": not args.short_names,
    }
    if args.ic_retry:
        settings["invocation_counter_retry"] = True
    if args.discover_ic:
        settings["discover_invocation_counter"] = True
    if args.ic_store:
        from pydlms.counters import CounterStore

        settings["counter_store"] = CounterStore(args.ic_store)
    system_title = _title(args.system_title, "--system-title/--client-title")
    if system_title is not None and security is None:
        settings["client_system_title"] = system_title
    settings.update(_association_options(args, security is not None))
    if args.signing_key or args.server_key:
        from cryptography.hazmat.primitives import serialization

        if args.signing_key:
            with open(args.signing_key, "rb") as handle:
                settings["signing_key"] = serialization.load_pem_private_key(
                    handle.read(), password=None
                )
        if args.server_key:
            with open(args.server_key, "rb") as handle:
                settings["server_public_key"] = serialization.load_pem_public_key(handle.read())
    common = {"client_sap": args.client, "server_logical": args.server, "timeout": args.timeout}
    window = getattr(args, "hdlc_window", None)
    modulo = getattr(args, "hdlc_modulo", None)
    for option, value in (("--hdlc-window", window), ("--hdlc-modulo", modulo)):
        if value is not None and kind not in _HDLC_KINDS:
            raise SystemExit(f"{option} needs an HDLC endpoint (tcp+hdlc, serial, optical)")
    if modulo is not None:
        common["hdlc_modulus"] = modulo
        common["hdlc_modulus_fallback"] = not args.no_hdlc_modulo_fallback
    elif getattr(args, "no_hdlc_modulo_fallback", False):
        raise SystemExit("--no-hdlc-modulo-fallback needs --hdlc-modulo 128")
    if window is not None:
        from pydlms.hdlc.connection import HdlcParameters, max_window

        limit = max_window(modulo or 8)
        if window > limit:
            raise SystemExit(f"--hdlc-window {window} needs --hdlc-modulo 128 (modulo 8: 1-7)")
        common["hdlc_parameters"] = HdlcParameters(window_tx=window, modulus=modulo or 8)
    common.update(_addressing_options(args, kind))
    optical_options = (
        args.optical_wake_up != "none" or args.optical_break or args.optical_break_form != "bcc"
    )
    if optical_options and kind != "optical":
        raise SystemExit(
            "--optical-wake-up, --optical-break and --optical-break-form need an "
            "optical:// endpoint"
        )
    # The constructors validate addressing (sizes, ranges, wPort) before
    # any I/O; their ValueError is a usage error here.
    try:
        if kind in ("tcp", "tcp+hdlc"):
            client = DlmsClient.tcp(
                params["host"],
                params["port"],
                hdlc=kind == "tcp+hdlc",
                server_physical=args.physical,
                **common,
                **settings,
            )
        elif kind == "udp":
            client = DlmsClient.udp(params["host"], params["port"], **common, **settings)
        elif kind == "serial":
            client = DlmsClient.serial(
                params["port"],
                int(params.get("baud", 9600)),
                server_physical=args.physical,
                **common,
                **settings,
            )
        elif kind in _MBUS_KINDS:
            client = _mbus_client(args, kind, params, common, settings)
        else:
            client = DlmsClient.optical(
                params["port"],
                server_physical=args.physical,
                max_baud=int(params.get("baud", 19200)),
                wake_up=args.optical_wake_up,
                break_before_sign_on=args.optical_break,
                break_form=args.optical_break_form,
                **common,
                **settings,
            )
    except ValueError as exc:
        raise SystemExit(f"invalid connection options: {exc}") from None
    if args.record:
        recorder = FrameRecorder()
        client.link.transport.recorder = recorder
        args._recorder = recorder
    return client


def _cell(value):
    """Render profile cells: 12-octet date-times as text, the rest as is."""
    if isinstance(value, bytes) and len(value) == 12:
        from pydlms.cosem.time import CosemDateTime

        try:
            return str(CosemDateTime.from_bytes(value))
        except (DlmsError, ValueError):
            return value.hex()
    return value


def _typed_cell(value):
    """Render a typed profile cell: date-times and register values as text."""
    from pydlms.cosem.scaler import RegisterValue
    from pydlms.cosem.time import CosemDateTime

    if isinstance(value, (CosemDateTime, RegisterValue)):
        return str(value)
    return value


def _json_default(value):
    if isinstance(value, bytes):
        return value.hex()
    return str(value)


def _emit(args, rows: list[dict]) -> None:
    if args.json:
        print(json.dumps(rows, default=_json_default, indent=2))
        return
    for row in rows:
        print("  ".join(str(v) for v in row.values()))


def cmd_read(args) -> int:
    from pydlms.catalog import obis_name

    rows = []
    with build_client(args) as meter:
        classes: dict[str, int] = {}
        if args.class_id is None and not args.register:
            # Look the interface class up instead of guessing it.
            try:
                classes = {str(e.logical_name): e.class_id for e in meter.get_association_view()}
            except DlmsError as exc:
                print(
                    f"pydlms: cannot read the object list ({exc}); assuming class 1",
                    file=sys.stderr,
                )
        for obis in args.obis:
            if args.register:
                value = meter.get_register(obis, args.class_id or 3)
                rows.append(
                    {
                        "obis": obis,
                        "value": value.value,
                        "unit": value.unit_symbol,
                        "name": obis_name(obis) or "",
                    }
                )
            else:
                class_id = args.class_id or classes.get(str(ObisCode.parse(obis)), 1)
                data = meter.get(obis, class_id, args.attr)
                rows.append(
                    {"obis": obis, "value": data.to_python(), "name": obis_name(obis) or ""}
                )
    _emit(args, rows)
    return 0


def cmd_list(args) -> int:
    from pydlms.catalog import obis_name
    from pydlms.cosem.interface_classes import lookup

    with build_client(args) as meter:
        view = meter.get_association_view()
    rows = []
    for entry in view:
        ic = lookup(entry.class_id, entry.version)
        rows.append(
            {
                "obis": str(entry.logical_name),
                "class": entry.class_id,
                "version": entry.version,
                "class_name": ic.name if ic else "?",
                "name": obis_name(entry.logical_name) or "",
                # readable/writable attributes, executable methods; "?" unknown
                "access": entry.rights.summary() if entry.rights else "?",
            }
        )
    _emit(args, rows)
    return 0


def cmd_clock(args) -> int:
    with build_client(args) as meter:
        clock = meter.get_clock()
    _emit(args, [{"clock": str(clock)}])
    return 0


def cmd_profile(args) -> int:
    from pydlms.apdu.xdlms import entry_descriptor

    with build_client(args) as meter:
        access = None
        if args.last:
            entries = meter.get(args.obis[0], 7, 7).value
            access = entry_descriptor(max(1, entries - args.last + 1), entries)
        buffer = meter.read_profile(
            args.obis[0], access, typed=args.typed or args.scalers, scalers=args.scalers
        )
    header = [f"{obis}/{attr}" for _, obis, attr, _ in buffer.columns]
    render = _typed_cell if args.typed or args.scalers else _cell
    rows = [dict(zip(header, (render(v) for v in row), strict=False)) for row in buffer.rows]
    _emit(args, rows)
    return 0


def _capture_objects(args):
    """The push_object_list for ``pydlms push``: from a file, or read from the meter."""
    if args.capture_objects:
        from pydlms.push import parse_capture_objects_text

        with open(args.capture_objects, encoding="utf-8") as handle:
            return parse_capture_objects_text(handle.read())
    if args.from_meter:
        # Connect with the same defaults as the other commands (public client),
        # read the list, close; then the caller listens on its own source.
        argv = ["list", args.from_meter, "--client", str(args.meter_client)]
        if args.meter_password:
            argv += ["--auth", "lls", "--password", args.meter_password]
        with build_client(build_parser().parse_args(argv)) as meter:
            return meter.push_decoder_from_meter(args.push_setup).capture_objects
    return None


def cmd_push(args) -> int:
    from pydlms.push import PushDecoder

    security = None
    if args.key:
        from pydlms.security.context import SecurityContext
        from pydlms.security.suites import SecurityPolicy

        # Without an authentication key nothing can be verified, so the
        # meter's pushes are held to encryption only; with one, every push
        # must be authenticated and encrypted.
        security = SecurityContext(
            _hex(args.key),
            _hex(args.auth_key),
            suite=args.suite,
            policy=SecurityPolicy.ENCRYPTED
            if args.auth_key is None
            else SecurityPolicy.AUTHENTICATED_ENCRYPTED,
            allow_unverified_auth=args.auth_key is None,
        )
    profile = None
    if args.profile:
        from pydlms.profiles import get_profile

        profile = get_profile(args.profile)
    capture = _capture_objects(args)
    decoder = PushDecoder(args.framing, security, profile, capture_objects=capture)

    def show(message):
        rows = [
            {"obis": str(r.obis) if r.obis else "-", "value": r.value, "unit": r.unit_symbol}
            for r in message.records
        ]
        if not args.json:
            print(f"--- push IC={message.invocation_counter} time={message.timestamp}")
        _emit(args, rows)
        sys.stdout.flush()

    if args.source == "-":
        for line in sys.stdin:
            line = line.strip()
            if line:
                for message in decoder.feed(_hex(line)):
                    show(message)
        return 0
    kind, params = parse_endpoint(args.source)
    if kind in ("tcp", "tcp+hdlc"):
        from pydlms.transports.tcp import TcpTransport

        transport = TcpTransport(params["host"], params["port"])
    else:
        from pydlms.transports.serial import SerialTransport

        transport = SerialTransport(
            params["port"], int(params.get("baud", args.baud)), parity=params.get("parity", "N")
        )
    with transport:
        while True:
            try:
                data = transport.recv(4096, timeout=args.timeout)
            except DlmsError:
                if args.once:
                    return 1
                continue
            for message in decoder.feed(data):
                show(message)
                if args.once:
                    return 0


def cmd_decode(args) -> int:
    from pydlms.explain import explain
    from pydlms.recording import load_recording, session_apdus

    records = load_recording(args.file) if args.file else []
    records += [(None, _hex(h)) for h in args.hex]
    if not records:
        raise SystemExit("nothing to decode: give hex arguments or --file")
    framing = args.framing
    if args.xml:
        from pydlms.apduxml import session_to_xml
        from pydlms.recording import deframe

        if args.apdus:
            apdus = session_apdus(records, framing, args.hdlc_modulo)
        else:
            apdus = deframe(
                records,
                framing,
                verify_checksums=not args.ignore_checksums,
                hdlc_modulus=args.hdlc_modulo,
            )
        sys.stdout.write(
            session_to_xml(
                apdus,
                _hex(args.key),
                _hex(args.auth_key),
                _hex(args.system_title),
                secrets=args.show_secrets,
                dialect=args.dialect,
            )
        )
        return 0
    if args.apdus:  # the plaintext APDU lines (or the APDUs inside the frames)
        buffers = [apdu for _, apdu in session_apdus(records, framing, args.hdlc_modulo)]
        framing = "apdu"
    else:
        buffers = [data for direction, data in records if direction in ("TX", "RX", None)]
    print(
        explain(
            buffers,
            _hex(args.key),
            _hex(args.auth_key),
            framing,
            verify_checksums=not args.ignore_checksums,
            system_title=_hex(args.system_title),
            hdlc_modulus=args.hdlc_modulo,
        )
    )
    return 0


def cmd_encode(args) -> int:
    from pydlms.apduxml import xml_to_session

    with open(args.file, encoding="utf-8") as handle:
        records = xml_to_session(handle.read())
    for direction, apdu in records:
        if args.recording:  # a --replay-able recording of plaintext APDUs
            print(f"{direction or 'TX'}-APDU {apdu.hex()}")
        else:
            print(apdu.hex())
    return 0


def cmd_image_transfer(args) -> int:
    from pydlms.image import transfer_image

    identifier = _hex(args.identifier)
    if not args.yes:
        print(
            "pydlms: image-transfer writes a firmware image to the meter; "
            "pass --yes to confirm (only on a meter you are authorised to update)",
            file=sys.stderr,
        )
        return 1
    with open(args.file, "rb") as handle:
        image = handle.read()

    def progress(sent: int, total: int) -> None:
        print(f"\rblock {sent}/{total}", end="", file=sys.stderr, flush=True)

    meter = build_client(args).connect()
    try:
        result = transfer_image(
            meter,
            image,
            identifier or b"",
            obis=args.obis,
            activate=args.activate,
            poll=args.poll,
            timeout=args.wait,
            progress=progress,
            max_rounds=args.max_rounds,
            check_info=not args.no_info_check,
        )
    except BaseException:
        print(file=sys.stderr)
        with contextlib.suppress(DlmsError):
            meter.close()
        raise
    print(file=sys.stderr)
    if result.activated and not result.activation_confirmed:
        # The meter restarted into the new image: the release cannot succeed.
        with contextlib.suppress(DlmsError):
            meter.close()
        print(
            "pydlms: association lost during activation; activation unconfirmed",
            file=sys.stderr,
        )
    else:
        meter.close()
    status = result.status
    _emit(
        args,
        [
            {
                "identifier": result.identifier.hex(),
                "size": result.image_size,
                "block_size": result.block_size,
                "blocks": result.blocks,
                "sent": result.sent,
                "rounds": result.rounds,
                "resumed": result.resumed,
                "status": getattr(status, "name", status),
                "activated": result.activated,
                "activation_confirmed": result.activation_confirmed,
            }
        ],
    )
    return 0


def cmd_discover_ic(args) -> int:
    from pydlms.ic_report import ic_report

    # The report is collected the way vendors expose the counter: through the
    # public client, without authentication or ciphering.
    if args.client != 16 or args.auth != "none" or args.password or args.key or args.auth_key:
        print(
            "pydlms: discover-ic always associates as the public client 16 without "
            "authentication or ciphering; client, auth and key options are ignored",
            file=sys.stderr,
        )
    args.client, args.auth = 16, "none"
    args.password = args.key = args.auth_key = None
    args.system_title = args.signing_key = args.server_key = None
    args.discover_ic = args.ic_retry = False
    args.ic_store = None
    with build_client(args) as meter:
        report = ic_report(meter)
    if args.report or args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    print(f"manufacturer {report['manufacturer'] or '?'}  firmware {report['firmware_id'] or '?'}")
    print(f"object list {report['object_list']}")
    for counter in report["invocation_counters"]:
        state = counter["type"] if counter["readable"] else "not readable"
        print(f"counter {counter['obis']} ({counter['found_by']}): {state}")
    for setup in report["security_setup"] or []:
        print(f"security setup {setup['obis']} class {setup['class_id']} v{setup['version']}")
    return 0


def cmd_redact(args) -> int:
    from pydlms.redact import redact_recording

    with open(args.file, encoding="utf-8") as handle:
        text = handle.read()
    also = [
        _hex(value[4:]) if value.startswith("hex:") else value.encode("utf-8")
        for value in args.also
    ]
    redacted, log = redact_recording(
        text, test_keys=args.test_keys, drop_raw_auth=args.drop_raw_auth, also=also
    )
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(redacted)
    else:
        sys.stdout.write(redacted)
    for line in log.lines():  # counts only, never the values
        print(f"pydlms redact: {line}", file=sys.stderr)
    return 0


def cmd_simulate(args) -> int:
    from pydlms.simulator import main as simulator_main

    argv = ["--host", args.host, "--port", str(args.port)]
    if args.hdlc:
        argv.append("--hdlc")
    if args.hdlc_window != 1:
        argv += ["--hdlc-window", str(args.hdlc_window)]
    if args.hdlc_modulo != 8:
        argv += ["--hdlc-modulo", str(args.hdlc_modulo)]
    for option in ("replay", "key", "auth_key"):
        if getattr(args, option):
            argv += ["--" + option.replace("_", "-"), getattr(args, option)]
    for spec in args.client:
        argv += ["--client", spec]
    simulator_main(argv)
    return 0


def _connection_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "endpoint",
        help="tcp://host:port, tcp+hdlc://, udp://, serial://, optical://, mbus://<device>?address=N, "
        "mbus+tcp://host:port?address=N or a device path",
    )
    parser.add_argument("--client", type=int, default=16, help="client SAP (default 16 public)")
    parser.add_argument("--server", type=int, default=1, help="server logical address")
    parser.add_argument("--physical", type=int, help="HDLC physical (lower) server address")
    parser.add_argument("--auth", choices=sorted(_AUTH), default="none")
    parser.add_argument("--password", help="LLS password or HLS secret (mechanisms 1-4, 6)")
    parser.add_argument("--signing-key", help="client ECDSA private key, PEM (--auth ecdsa)")
    parser.add_argument("--server-key", help="meter ECDSA public key, PEM (--auth ecdsa)")
    parser.add_argument("--key", help="global unicast encryption key (hex); enables ciphering")
    parser.add_argument("--auth-key", help="authentication key (hex)")
    parser.add_argument(
        "--system-title",
        "--client-title",
        dest="system_title",
        help="client system title, 8 octets hex (ciphering, sha256, ecdsa)",
    )
    parser.add_argument(
        "--invocation-counter",
        type=int,
        default=0,
        help="first outbound invocation counter (read 0.0.43.1.x.255 first)",
    )
    parser.add_argument(
        "--discover-ic",
        action="store_true",
        help="read the meter's invocation counters via the public client first",
    )
    parser.add_argument(
        "--ic-retry",
        "--invocation-counter-retry",
        dest="ic_retry",
        action="store_true",
        help="retry once from the counter the meter reports when ours is stale",
    )
    parser.add_argument("--ic-store", help="JSON file remembering the last invocation counter")
    parser.add_argument("--short-names", action="store_true", help="SN referencing")
    parser.add_argument(
        "--optical-wake-up",
        choices=("none", "normal", "fast"),
        default="none",
        help="optical:// only: IEC 62056-21 Annex B wake-up before the sign-on "
        "(normal: NULs 2.2 s + 1.6 s pause; fast: NUL strings until ACK, B1 on close)",
    )
    parser.add_argument(
        "--optical-break",
        action="store_true",
        help="optical:// only: send the break B0 before the sign-on",
    )
    parser.add_argument(
        "--optical-break-form",
        choices=("bcc", "crlf"),
        default="bcc",
        help="optical:// only: B0 with its BCC (default) or Gurux's SOH B0 ETX CR LF "
        "for meters that read lines without an inter-character timeout",
    )
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument(
        "--hdlc-window",
        type=int,
        choices=range(1, 128),
        metavar="N",
        help="HDLC transmit window to propose (1-7, 1-127 with --hdlc-modulo 128; "
        "default 1): up to N I-frames per acknowledgement, go-back-N on loss",
    )
    parser.add_argument(
        "--hdlc-modulo",
        type=int,
        choices=(8, 128),
        help="HDLC sequence numbering: 128 sets the link up with SNRME (two-octet "
        "control fields, outside IEC 62056-46), falling back to SNRM if refused; "
        "default 8 (SNRM)",
    )
    parser.add_argument(
        "--no-hdlc-modulo-fallback",
        action="store_true",
        help="with --hdlc-modulo 128: fail instead of falling back to SNRM",
    )
    parser.add_argument(
        "--address-size",
        type=int,
        choices=(1, 2, 4),
        help="HDLC only: server address length in octets (default: shortest that fits)",
    )
    parser.add_argument(
        "--physical-from-serial",
        metavar="SERIAL:VENDOR",
        help="HDLC only: physical address from the meter serial by vendor rule "
        f"({', '.join(sorted(SERIAL_ADDRESS_RULES))}); instead of --physical",
    )
    parser.add_argument(
        "--client-wport",
        type=int,
        metavar="N",
        help="wrapper only (tcp://, udp://): source wPort, 0-65535 (default: --client)",
    )
    parser.add_argument(
        "--max-pdu",
        type=int,
        metavar="N",
        help=f"client max-receive-pdu-size to propose, {_MIN_PDU}-65535 (default 65535)",
    )
    parser.add_argument(
        "--conformance",
        metavar="BITS",
        help="proposed conformance: hex (e.g. 007E1F) or a comma list of names "
        "(get,set,selective_access,...)",
    )
    parser.add_argument(
        "--protection",
        choices=_PROTECTIONS,
        help="envelope for protected services (needs --key; default glo)",
    )
    parser.add_argument(
        "--dedicated-key",
        action="store_true",
        help="propose a dedicated key and cipher services with it (needs --key)",
    )
    parser.add_argument(
        "--expect-server-title",
        metavar="HEX",
        help="refuse an AARE whose server system title is not these 8 octets",
    )
    parser.add_argument(
        "--gbt-window",
        type=int,
        metavar="N",
        help="general-block-transfer receive window to advertise, 1-63 (default 1)",
    )
    parser.add_argument(
        "--require-verified-release",
        action="store_true",
        help="fail when the RLRE to a ciphered RLRQ cannot be verified",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pydlms", description="DLMS/COSEM client")
    parser.add_argument("--version", action="version", version=f"pydlms {__version__}")
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="-v debug, -vv hexdump every buffer (TRACE)",
    )
    parser.add_argument(
        "--log-layers",
        help="comma list: transport,hdlc,wrapper,mbus,security,apdu,association,client,push",
    )
    parser.add_argument(
        "--record", help="write every TX/RX buffer and plaintext APDU as hex to this file"
    )
    parser.add_argument("--json", action="store_true", help="JSON output")
    sub = parser.add_subparsers(dest="command", required=True)

    read = sub.add_parser("read", help="GET attributes")
    _connection_options(read)
    read.add_argument("--obis", action="append", required=True)
    read.add_argument("--class", dest="class_id", type=int)
    read.add_argument("--attr", type=int, default=2)
    read.add_argument("--register", action="store_true", help="apply scaler/unit (attr 3)")
    read.set_defaults(func=cmd_read)

    lst = sub.add_parser("list", help="association view (object list)")
    _connection_options(lst)
    lst.set_defaults(func=cmd_list)

    clock = sub.add_parser("clock", help="read the clock")
    _connection_options(clock)
    clock.set_defaults(func=cmd_clock)

    profile = sub.add_parser("profile", help="read a profile generic buffer")
    _connection_options(profile)
    profile.add_argument("--obis", action="append", required=True)
    profile.add_argument("--last", type=int, help="only the last N entries (selective access)")
    profile.add_argument(
        "--typed", action="store_true", help="type the cells (date-times, enums, structures)"
    )
    profile.add_argument(
        "--scalers",
        action="store_true",
        help="apply each register's scaler and unit (reads scaler_unit once; implies --typed)",
    )
    profile.set_defaults(func=cmd_profile)

    push = sub.add_parser("push", help="listen for and decode pushes")
    push.add_argument("source", help="device, tcp://host:port, or - for hex lines on stdin")
    push.add_argument("--framing", choices=["hdlc", "mbus", "wrapper", "raw"], default="hdlc")
    push.add_argument("--baud", type=int, default=2400)
    push.add_argument("--key")
    push.add_argument("--auth-key")
    push.add_argument(
        "--suite",
        type=int,
        choices=[0, 1, 2],
        default=0,
        help="security suite id the meter puts in the SC byte (Kaifa MA309M: 1)",
    )
    push.add_argument("--profile", help="relabel compact payloads (see pydlms.profiles)")
    source = push.add_mutually_exclusive_group()
    source.add_argument(
        "--capture-objects",
        metavar="FILE",
        help="push_object_list for positional decoding: text lines 'class_id obis attribute "
        "[data_index]' (# comments) or a JSON array (see pydlms.push.parse_capture_objects_text)",
    )
    source.add_argument(
        "--from-meter",
        metavar="URL",
        help="read the push_object_list from the meter's push setup at this endpoint first",
    )
    push.add_argument(
        "--push-setup", default="0.0.25.9.0.255", help="push setup OBIS (--from-meter)"
    )
    push.add_argument("--meter-client", type=int, default=16, help="client SAP for --from-meter")
    push.add_argument("--meter-password", help="LLS password for --from-meter (default: none)")
    push.add_argument("--once", action="store_true", help="exit after the first push")
    push.add_argument("--timeout", type=float, default=30.0)
    push.set_defaults(func=cmd_push)

    decode = sub.add_parser("decode", help="explain captured bytes layer by layer")
    decode.add_argument("hex", nargs="*", help="hex buffers (frames or APDUs)")
    decode.add_argument("--file", help="file of hex lines (e.g. from --record)")
    decode.add_argument("--key")
    decode.add_argument("--auth-key")
    decode.add_argument("--system-title", help="sender system title for glo-/ded- APDUs")
    decode.add_argument(
        "--hdlc-modulo",
        type=int,
        choices=(8, 128),
        default=8,
        help="HDLC numbering the frames start in (default 8); an SNRME or SNRM "
        "answered by UA in the data switches it",
    )
    decode.add_argument(
        "--framing", choices=["auto", "hdlc", "mbus", "wrapper", "apdu"], default="auto"
    )
    decode.add_argument(
        "--ignore-checksums",
        action="store_true",
        help="accept HDLC frames with bad HCS/FCS (analysis only)",
    )
    decode.add_argument(
        "--apdus",
        action="store_true",
        help="decode the recording's plaintext TX-APDU/RX-APDU lines instead of the frames",
    )
    decode.add_argument(
        "--xml", action="store_true", help="write the APDUs as XML (pydlms.apduxml)"
    )
    decode.add_argument(
        "--dialect",
        choices=("pydlms", "gurux"),
        default="pydlms",
        help="with --xml: pydlms's own format or the Gurux translator dialect",
    )
    decode.add_argument(
        "--show-secrets",
        action="store_true",
        help="with --xml: keep LLS passwords, HLS challenges and dedicated keys",
    )
    decode.set_defaults(func=cmd_decode)

    encode = sub.add_parser("encode", help="turn decode --xml output back into APDUs")
    encode.add_argument(
        "file",
        help="XML file: one APDU element, a pydlms-session, or Gurux translator XML",
    )
    encode.add_argument(
        "--recording",
        action="store_true",
        help="print TX-APDU/RX-APDU lines that simulate --replay accepts",
    )
    encode.set_defaults(func=cmd_encode)

    image = sub.add_parser(
        "image-transfer", help="send a firmware image (Image transfer, IC 18); writes!"
    )
    _connection_options(image)
    image.add_argument("file", help="the image file")
    image.add_argument("--identifier", required=True, help="image_identifier (hex)")
    image.add_argument("--obis", default="0.0.44.0.0.255", help="image transfer object")
    image.add_argument("--activate", action="store_true", help="activate after verification")
    image.add_argument("--poll", type=float, default=1.0, help="seconds between status reads")
    image.add_argument(
        "--wait", type=float, default=300.0, help="seconds to wait for verify/activate"
    )
    image.add_argument("--max-rounds", type=int, default=3, help="rounds of block resends")
    image.add_argument(
        "--no-info-check",
        action="store_true",
        help="do not require image_to_activate_info to list the image",
    )
    image.add_argument("--yes", action="store_true", help="confirm writing to the meter (required)")
    image.set_defaults(func=cmd_image_transfer)

    discover = sub.add_parser(
        "discover-ic",
        help="where the meter keeps its invocation counters (public client, no values shown)",
    )
    _connection_options(discover)
    discover.add_argument(
        "--report",
        action="store_true",
        help="print the redacted JSON report for a device-compat issue",
    )
    discover.set_defaults(func=cmd_discover_ic)

    redact = sub.add_parser(
        "redact", help="replace serials, system titles and secrets in a --record file"
    )
    redact.add_argument("file", help="recording written by --record")
    redact.add_argument("-o", "--output", help="write here instead of stdout")
    redact.add_argument(
        "--test-keys",
        action="store_true",
        help="the session used publishable test keys: keep raw AARQ/AARE and ciphered "
        "frames (their titles and authentication values still replaced)",
    )
    redact.add_argument(
        "--drop-raw-auth",
        action="store_true",
        help="drop raw AARQ/AARE, HLS pass 3/4 and ciphered frames even with --test-keys",
    )
    redact.add_argument(
        "--also",
        action="append",
        default=[],
        metavar="VALUE",
        help="another value to replace wherever it appears (text, or hex:...); repeatable",
    )
    redact.set_defaults(func=cmd_redact)

    simulate = sub.add_parser("simulate", help="run the built-in meter simulator")
    simulate.add_argument("--host", default="127.0.0.1")
    simulate.add_argument("--port", type=int, default=4059)
    simulate.add_argument("--hdlc", action="store_true")
    simulate.add_argument(
        "--hdlc-window",
        type=int,
        default=1,
        metavar="N",
        help="HDLC receive window to offer, 1-7 or 1-127 with --hdlc-modulo 128 "
        "(default 1; needs --hdlc)",
    )
    simulate.add_argument(
        "--hdlc-modulo",
        type=int,
        choices=(8, 128),
        default=8,
        help="128: also take SNRME (modulo-128 numbering); default 8 answers it with DM",
    )
    simulate.add_argument("--replay", help="answer from a --record file instead")
    simulate.add_argument("--key", help="encryption key (hex) for ciphered clients")
    simulate.add_argument("--auth-key")
    simulate.add_argument(
        "--client",
        action="append",
        default=[],
        metavar="SAP:MECHANISM[:SECRET]",
        help="accept a client SAP, e.g. 1:5 (HLS-GMAC); repeatable",
    )
    simulate.set_defaults(func=cmd_simulate)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args._recorder = None
    if args.verbose:
        level = TRACE if args.verbose >= 2 else "DEBUG"
        layers = args.log_layers.split(",") if args.log_layers else None
        enable_debug(level, layers)
    try:
        return args.func(args)
    except DlmsError as exc:
        print(f"pydlms: {type(exc).__name__}: {exc}", file=sys.stderr)
        if not args.verbose:
            print(
                "pydlms: rerun with -v (or -vv for hexdumps) to see the exchange", file=sys.stderr
            )
        return 2
    finally:
        if args._recorder is not None:
            with open(args.record, "w", encoding="utf-8") as handle:
                handle.write(args._recorder.dump() + "\n")


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
