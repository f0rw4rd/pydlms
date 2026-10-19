"""High-level DLMS/COSEM client.

::

    from pydlms import DlmsClient

    with DlmsClient.tcp("192.0.2.10", 4059) as meter:
        print(meter.get_register("1.0.1.8.0.255"))

Builders pick the framing: :meth:`DlmsClient.tcp` (wrapper, or HDLC over TCP
with ``hdlc=True``), :meth:`DlmsClient.udp`, :meth:`DlmsClient.serial` (HDLC)
and :meth:`DlmsClient.optical` (IEC 62056-21 mode E, then HDLC).

Services: :meth:`get` (with block transfer), :meth:`get_many` (with-list),
:meth:`set` (with block transfer), :meth:`action`, plus the convenience
readers :meth:`get_register`, :meth:`get_clock`, :meth:`get_association_view`
and :meth:`read_profile`. Short-Name meters use the same calls; the object
list read during association maps ``(class_id, obis, attribute)`` onto base
names.
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any

from pydlms.apdu import sn, xdlms
from pydlms.association import Association, AssociationSettings, AssociationState
from pydlms.cosem.access import AccessRights, decode_access_rights
from pydlms.cosem.compact_data import (
    CompactData,
    decode_compact_buffer,
    decode_template_description,
)
from pydlms.cosem.data import DlmsData, decode_data, encode_data
from pydlms.cosem.delta import resolve_deltas as _resolve_deltas
from pydlms.cosem.enums import ActionResult, DataAccessResult, DataType, Unit, result_name
from pydlms.cosem.interface_classes import ClassId, attribute_index
from pydlms.cosem.profile import register_scaler, scaled_registers, typed_rows
from pydlms.cosem.scaler import RegisterValue, apply_scaler, scaler_unit
from pydlms.cosem.time import CosemDateTime
from pydlms.debug import get_logger
from pydlms.exceptions import DecodeError, DlmsError, KeyMissingError, ProtocolError, ServiceError
from pydlms.link import ApduLink
from pydlms.obis import ObisCode
from pydlms.security.hls import Mechanism

if TYPE_CHECKING:
    from pydlms.hdlc.connection import HdlcParameters
    from pydlms.security.keywrap import KeyId

__all__ = [
    "DlmsClient",
    "AccessGet",
    "AccessSet",
    "AccessAction",
    "AccessOutcome",
    "RegisterValue",
    "ObjectListEntry",
    "ProfileBuffer",
    "apply_scaler",
    "scaler_unit",
]

log = get_logger("client")


def _obis(value: ObisCode | str | bytes) -> ObisCode:
    if isinstance(value, ObisCode):
        return value
    if isinstance(value, bytes):
        return ObisCode.from_bytes(value)
    return ObisCode.parse(value)


@dataclass(frozen=True)
class ObjectListEntry:
    class_id: int
    version: int
    logical_name: ObisCode
    base_name: int | None = None  # SN only
    access_rights: DlmsData | None = None  # LN only, as received
    #: ``access_rights`` decoded with the view's Association LN version;
    #: ``None`` for SN views and when the meter's field is malformed.
    rights: AccessRights | None = None

    def __str__(self) -> str:
        bn = f" sn=0x{self.base_name:04X}" if self.base_name is not None else ""
        return f"{self.logical_name} class={self.class_id} v{self.version}{bn}"


@dataclass
class ProfileBuffer:
    """Profile generic buffer with its column descriptions.

    ``rows`` holds one Python value per column: plain values by default,
    typed ones (:mod:`pydlms.cosem.profile`) from a typed read. ``cells``
    keeps the received ``Data`` of every cell, untouched.
    """

    columns: list[tuple[int, ObisCode, int, int]]
    rows: list[list[Any]]
    cells: list[list[DlmsData]] = field(default_factory=list, repr=False)


# --- ACCESS operations ------------------------------------------------------------------


@dataclass(frozen=True)
class AccessGet:
    """Read one attribute in an ACCESS request (:meth:`DlmsClient.access`);
    ``access`` makes it a get-with-selection."""

    obis: ObisCode | str
    class_id: int = ClassId.DATA
    attribute: int | str = 2
    access: xdlms.SelectiveAccess | None = None


@dataclass(frozen=True)
class AccessSet:
    """Write one attribute in an ACCESS request; ``access`` makes it a
    set-with-selection."""

    obis: ObisCode | str
    class_id: int
    attribute: int | str
    value: DlmsData
    access: xdlms.SelectiveAccess | None = None


@dataclass(frozen=True)
class AccessAction:
    """Invoke one method in an ACCESS request (null-data parameters when
    ``parameters`` is None)."""

    obis: ObisCode | str
    class_id: int
    method: int | str
    parameters: DlmsData | None = None


AccessOperation = AccessGet | AccessSet | AccessAction


@dataclass(frozen=True)
class AccessOutcome:
    """The answer to one operation of :meth:`DlmsClient.access`.

    ``result`` is a :class:`DataAccessResult` (get, set) or
    :class:`ActionResult` (action), or the bare code when the meter sent an
    undefined one. ``data`` is what the meter returned for the operation:
    the value read, the action's return parameters, or null-data.
    """

    operation: AccessOperation
    result: DataAccessResult | ActionResult | int
    data: DlmsData

    @property
    def ok(self) -> bool:
        return int(self.result) == 0


def _access_spec(op: AccessOperation) -> tuple[xdlms.AccessRequestSpecification, DlmsData]:
    """The Access-Request-Specification and list-of-data entry of ``op``."""
    from pydlms.cosem.interface_classes import lookup

    if not isinstance(op, (AccessGet, AccessSet, AccessAction)):
        raise TypeError(f"{type(op).__name__} is not an AccessGet, AccessSet or AccessAction")
    obis = _obis(op.obis)
    if isinstance(op, AccessAction):
        method = op.method
        if isinstance(method, str):
            ic = lookup(op.class_id)
            if ic is None:
                raise KeyError(f"unknown interface class {op.class_id}")
            method = ic.method_index(method)
        descriptor = xdlms.MethodDescriptor(int(op.class_id), obis, method)
        params = op.parameters if op.parameters is not None else DlmsData.null()
        return xdlms.AccessRequestAction(descriptor), params
    attribute = op.attribute
    if isinstance(attribute, str):
        attribute = attribute_index(op.class_id, attribute)
    att = xdlms.AttributeDescriptor(int(op.class_id), obis, attribute)
    if isinstance(op, AccessGet):
        if op.access is None:
            return xdlms.AccessRequestGet(att), DlmsData.null()
        return xdlms.AccessRequestGetWithSelection(att, op.access), DlmsData.null()
    if op.access is None:
        return xdlms.AccessRequestSet(att), op.value
    return xdlms.AccessRequestSetWithSelection(att, op.access), op.value


#: Access-Response-Specification expected for each request specification kind.
_ACCESS_RESULT_FOR = {
    xdlms.AccessKind.GET: xdlms.AccessResponseGet,
    xdlms.AccessKind.GET_WITH_SELECTION: xdlms.AccessResponseGet,
    xdlms.AccessKind.SET: xdlms.AccessResponseSet,
    xdlms.AccessKind.SET_WITH_SELECTION: xdlms.AccessResponseSet,
    xdlms.AccessKind.ACTION: xdlms.AccessResponseAction,
}


#: Inter-octet time-out (seconds) :meth:`DlmsClient.serial` and
#: :meth:`DlmsClient.optical` give their HDLC frame reader. *Unverified*: a
#: conservative library choice, not a standard value. The time-out of
#: IEC 62056-46 is far shorter (cB-Sigma defaults to 100 ms), but USB serial
#: adapters and OS buffering delay octets, and a too-short value would drop
#: good frames; one second still clears a frame cut off by line noise or a
#: meter reset before the next answer. TCP gets none.
SERIAL_INTER_OCTET_TIMEOUT = 1.0

#: Logical name of the IEC HDLC setup object (IC 23) of the current channel
#: (Blue Book OBIS 0-b:22.0.0.255 with b = 0, clause not checked; also
#: cB-Sigma ``obis/cosem_test.go``).
HDLC_SETUP_OBIS = "0.0.22.0.0.255"

_UNSIGNED_TAGS = frozenset(
    {DataType.UNSIGNED, DataType.LONG_UNSIGNED, DataType.DOUBLE_LONG_UNSIGNED}
)


def _hdlc_server_address(
    logical: int,
    physical: int | None,
    address_size: int | None,
    physical_from_serial: tuple[int | str, str] | None,
):
    """The HDLC server address of the HDLC constructors; raises ValueError
    for an invalid size, a value the size cannot carry, or conflicting
    physical-address options, before any transport is created."""
    from pydlms.hdlc.address import SERIAL_ADDRESS_RULES, HdlcAddress, physical_address_from_serial

    if physical_from_serial is not None:
        if physical is not None:
            raise ValueError("give server_physical or physical_from_serial, not both")
        try:
            serial, vendor = physical_from_serial
        except (TypeError, ValueError):
            raise ValueError("physical_from_serial must be a (serial, vendor) pair") from None
        try:
            physical = physical_address_from_serial(serial, vendor)
        except KeyError:
            known = ", ".join(sorted(SERIAL_ADDRESS_RULES))
            raise ValueError(
                f"no serial address rule for vendor {vendor!r} (known: {known})"
            ) from None
    if address_size is not None:
        if isinstance(address_size, bool) or address_size not in (1, 2, 4):
            raise ValueError(f"address_size must be 1, 2 or 4, got {address_size!r}")
        if address_size > 1 and physical is None:
            raise ValueError(f"a {address_size}-octet server address needs a physical address")
    return HdlcAddress.server(logical, physical, address_size)


def _wrapper_wport(client_sap: int, client_wport: int | None) -> int:
    """The client wPort of a wrapper link: ``client_sap`` unless overridden."""
    if client_wport is None:
        return client_sap
    if isinstance(client_wport, bool) or not isinstance(client_wport, int):
        raise ValueError(f"client_wport must be an integer, got {client_wport!r}")
    if not 0 <= client_wport <= 0xFFFF:
        raise ValueError(f"client_wport {client_wport} outside the 16-bit range 0..65535")
    return client_wport


class DlmsClient:
    """A connected DLMS client. Use as a context manager or call
    :meth:`connect` / :meth:`close`."""

    def __init__(
        self,
        link: ApduLink,
        settings: AssociationSettings | None = None,
        auto_associate: bool = True,
        discover_invocation_counter: bool = False,
        public_client_sap: int = 16,
        manufacturer: str | None = None,
        counter_store=None,
    ) -> None:
        self.link = link
        self.association = Association(link, settings)
        self.auto_associate = auto_associate
        self._sn_map: dict[tuple[int, ObisCode], int] | None = None
        self._sn_versions: dict[tuple[int, ObisCode], int] = {}
        #: ``(class_id, obis) -> (scaler, unit)`` read by ``read_profile``;
        #: ``None`` marks a register whose scaler_unit could not be read.
        self._scaler_cache: dict[tuple[int, ObisCode], tuple[int, Unit | int | None] | None] = {}
        #: Read the meter's invocation counters through the public client
        #: before a ciphered association (see :mod:`pydlms.counters`).
        self.discover_invocation_counter = discover_invocation_counter
        self.public_client_sap = public_client_sap
        self.manufacturer = manufacturer
        #: :class:`pydlms.counters.CounterStore` persisting the outbound IC.
        self.counter_store = counter_store

    # -- builders --------------------------------------------------------------
    @staticmethod
    def _settings(
        mechanism=Mechanism.NONE,
        password: bytes | str | None = None,
        security=None,
        logical_names: bool = True,
        **kw,
    ) -> AssociationSettings:
        if isinstance(password, str):
            password = password.encode("ascii")
        return AssociationSettings(
            mechanism=Mechanism(mechanism),
            secret=password,
            security=security,
            logical_names=logical_names,
            **kw,
        )

    _CLIENT_OPTIONS = (
        "discover_invocation_counter",
        "public_client_sap",
        "manufacturer",
        "counter_store",
        "auto_associate",
    )

    @classmethod
    def _build(cls, link: ApduLink, settings: dict) -> DlmsClient:
        options = {k: settings.pop(k) for k in cls._CLIENT_OPTIONS if k in settings}
        return cls(link, cls._settings(**settings), **options)

    @classmethod
    def tcp(
        cls,
        host: str,
        port: int = 4059,
        client_sap: int = 16,
        server_logical: int = 1,
        server_physical: int | None = None,
        hdlc: bool = False,
        timeout: float = 10.0,
        hdlc_parameters: HdlcParameters | None = None,
        address_size: int | None = None,
        physical_from_serial: tuple[int | str, str] | None = None,
        client_wport: int | None = None,
        hdlc_modulus: int = 8,
        hdlc_modulus_fallback: bool = True,
        **settings: Any,
    ) -> DlmsClient:
        """TCP with the IEC 62056-47 wrapper (default) or HDLC over TCP.

        HDLC only: ``hdlc_parameters`` are proposed in the SNRM, e.g.
        ``HdlcParameters(window_tx=3)`` for a transmit window of 3;
        ``address_size`` (1, 2 or 4) fixes the server address length
        instead of picking the shortest that fits; ``physical_from_serial``
        ``(serial, vendor)`` derives the physical address from the meter
        serial (:func:`~pydlms.hdlc.address.physical_address_from_serial`),
        in place of ``server_physical``; ``hdlc_modulus=128`` sets the link
        up with SNRME for modulo-128 numbering (opt-in, outside IEC
        62056-46; windows up to 127), falling back to SNRM unless
        ``hdlc_modulus_fallback`` is False (see
        :class:`~pydlms.hdlc.connection.HdlcLink`).

        Wrapper only: ``client_wport`` sends from that wPort instead of
        ``client_sap``.

        Every other keyword goes to the client (``discover_invocation_counter``,
        ``public_client_sap``, ``manufacturer``, ``counter_store``,
        ``auto_associate``) or to :class:`~pydlms.association.AssociationSettings`
        (``mechanism``, ``password`` for its ``secret``, ``security``, and any
        other field such as ``max_receive_pdu_size`` or ``gbt_window``).
        Invalid addressing raises ValueError before any I/O."""
        from pydlms.transports.tcp import TcpTransport

        if hdlc:
            if client_wport is not None:
                raise ValueError("client_wport is a wrapper option; HDLC has no wPorts")
            from pydlms.hdlc.connection import HdlcLink

            address = _hdlc_server_address(
                server_logical, server_physical, address_size, physical_from_serial
            )
            link: ApduLink = HdlcLink(
                TcpTransport(host, port, timeout=timeout),
                client_sap,
                address,
                parameters=hdlc_parameters,
                timeout=timeout,
                modulus=hdlc_modulus,
                modulus_fallback=hdlc_modulus_fallback,
            )
        else:
            for name, value in (
                ("hdlc_parameters", hdlc_parameters),
                ("address_size", address_size),
                ("physical_from_serial", physical_from_serial),
                ("hdlc_modulus", None if hdlc_modulus == 8 else hdlc_modulus),
            ):
                if value is not None:
                    raise ValueError(f"{name} requires hdlc=True")
            from pydlms.wrapper import WrapperLink

            link = WrapperLink(
                TcpTransport(host, port, timeout=timeout),
                _wrapper_wport(client_sap, client_wport),
                server_logical,
                timeout=timeout,
            )
        return cls._build(link, settings)

    @classmethod
    def udp(
        cls,
        host: str,
        port: int = 4059,
        client_sap: int = 16,
        server_logical: int = 1,
        timeout: float = 10.0,
        client_wport: int | None = None,
        **settings: Any,
    ) -> DlmsClient:
        """The IEC 62056-47 wrapper over UDP; ``client_wport`` and
        ``**settings`` as for :meth:`tcp`."""
        from pydlms.transports.tcp import UdpTransport
        from pydlms.wrapper import WrapperLink

        wport = _wrapper_wport(client_sap, client_wport)
        link = WrapperLink(UdpTransport(host, port, timeout), wport, server_logical, timeout)
        return cls._build(link, settings)

    @classmethod
    def serial(
        cls,
        port: str,
        baudrate: int = 9600,
        client_sap: int = 16,
        server_logical: int = 1,
        server_physical: int | None = None,
        timeout: float = 5.0,
        inter_octet_timeout: float | None = SERIAL_INTER_OCTET_TIMEOUT,
        inactivity_timeout: float | None = None,
        hdlc_parameters: HdlcParameters | None = None,
        address_size: int | None = None,
        physical_from_serial: tuple[int | str, str] | None = None,
        hdlc_modulus: int = 8,
        hdlc_modulus_fallback: bool = True,
        **settings: Any,
    ) -> DlmsClient:
        """HDLC over a serial line (RS-485, P1/CII ports) or a pyserial URL.

        ``inter_octet_timeout``, ``inactivity_timeout``, ``hdlc_parameters``
        and ``hdlc_modulus`` / ``hdlc_modulus_fallback`` (as ``modulus`` /
        ``modulus_fallback``) go to :class:`~pydlms.hdlc.connection.HdlcLink`; see
        :data:`SERIAL_INTER_OCTET_TIMEOUT` and
        :meth:`read_hdlc_inactivity_timeout`. ``address_size``,
        ``physical_from_serial`` and ``**settings`` as for :meth:`tcp`."""
        from pydlms.hdlc.connection import HdlcLink
        from pydlms.transports.serial import SerialTransport

        address = _hdlc_server_address(
            server_logical, server_physical, address_size, physical_from_serial
        )
        link = HdlcLink(
            SerialTransport(port, baudrate, timeout),
            client_sap,
            address,
            parameters=hdlc_parameters,
            timeout=timeout,
            inter_octet_timeout=inter_octet_timeout,
            inactivity_timeout=inactivity_timeout,
            modulus=hdlc_modulus,
            modulus_fallback=hdlc_modulus_fallback,
        )
        return cls._build(link, settings)

    @classmethod
    def optical(
        cls,
        port: str,
        client_sap: int = 16,
        server_logical: int = 1,
        server_physical: int | None = None,
        max_baud: int = 19200,
        timeout: float = 5.0,
        inter_octet_timeout: float | None = SERIAL_INTER_OCTET_TIMEOUT,
        inactivity_timeout: float | None = None,
        hdlc_parameters: HdlcParameters | None = None,
        wake_up: str = "none",
        break_before_sign_on: bool = False,
        break_form: str = "bcc",
        address_size: int | None = None,
        physical_from_serial: tuple[int | str, str] | None = None,
        hdlc_modulus: int = 8,
        hdlc_modulus_fallback: bool = True,
        **settings: Any,
    ) -> DlmsClient:
        """Optical probe: IEC 62056-21 mode E sign-on, then HDLC (time-outs,
        ``hdlc_modulus``, ``address_size``, ``physical_from_serial`` and
        ``**settings`` as for :meth:`serial`).

        ``wake_up`` (``"none"``, ``"normal"``, ``"fast"``),
        ``break_before_sign_on`` and ``break_form`` (``"bcc"``, ``"crlf"``) go
        to :class:`~pydlms.transports.serial.OpticalTransport`: the Annex B
        wake-up of battery-powered meters, and a break B0 before the
        sign-on."""
        from pydlms.hdlc.connection import HdlcLink
        from pydlms.transports.serial import OpticalTransport

        address = _hdlc_server_address(
            server_logical, server_physical, address_size, physical_from_serial
        )
        link = HdlcLink(
            OpticalTransport(
                port,
                timeout,
                max_baud,
                break_before_sign_on=break_before_sign_on,
                wake_up=wake_up,
                break_form=break_form,
            ),
            client_sap,
            address,
            parameters=hdlc_parameters,
            timeout=timeout,
            inter_octet_timeout=inter_octet_timeout,
            inactivity_timeout=inactivity_timeout,
            modulus=hdlc_modulus,
            modulus_fallback=hdlc_modulus_fallback,
        )
        return cls._build(link, settings)

    @classmethod
    def mbus(
        cls,
        port_or_url: str,
        primary_address: int = 0,
        client_sap: int = 16,
        server_logical: int = 1,
        baudrate: int = 2400,
        parity: str = "E",
        timeout: float = 10.0,
        reply_timeout: float | None = None,
        retries: int = 2,
        secondary_address: str | bytes | None = None,
        max_segment: int = 250,
        **settings: Any,
    ) -> DlmsClient:
        """DLMS over a wired M-Bus (IEC 62056-7-3), the client being the
        M-Bus master (:class:`~pydlms.mbus_link.MbusLink`).

        ``port_or_url`` is a serial device or pyserial URL (``baudrate``,
        8 data bits, ``parity``; M-Bus lines usually run 2400 8E1), or
        ``tcp://host:port`` for an M-Bus gateway that passes the bus through.
        ``primary_address`` is the meter's M-Bus address (0..250, or 254
        point to point); ``secondary_address`` (16 hex digits
        ``IIIIIIIIMMMMVVDD`` or 8 octets) selects the meter instead.
        ``client_sap`` / ``server_logical`` are the STSAP / DTSAP.
        ``reply_timeout``, ``retries`` and ``max_segment`` go to the link.

        ``max_receive_pdu_size`` defaults to 16 segments of ``max_segment``
        octets (4000; the sequence rolls over after 15, so this is a
        library choice, not a protocol limit); ``**settings`` otherwise as
        for :meth:`tcp`."""
        from pydlms.mbus_link import MAX_SEGMENTS, MbusLink

        transport: Any
        if port_or_url.lower().startswith("tcp://"):
            from urllib.parse import urlparse

            from pydlms.transports.tcp import TcpTransport

            url = urlparse(port_or_url)
            if not url.hostname or url.port is None:
                raise ValueError(f"M-Bus gateway URL {port_or_url!r} needs a host and a port")
            transport = TcpTransport(url.hostname, url.port, timeout=timeout)
        else:
            from pydlms.transports.serial import SerialTransport

            transport = SerialTransport(port_or_url, baudrate, timeout, bytesize=8, parity=parity)
        link = MbusLink(
            transport,
            primary_address,
            client_sap=client_sap,
            server_sap=server_logical,
            timeout=timeout,
            reply_timeout=reply_timeout,
            retries=retries,
            secondary_address=secondary_address,
            max_segment=max_segment,
        )
        settings.setdefault("max_receive_pdu_size", MAX_SEGMENTS * max_segment)
        return cls._build(link, settings)

    # -- lifecycle -------------------------------------------------------------------
    def connect(self) -> DlmsClient:
        security = self.association.security
        if security is not None and self.counter_store is not None:
            stored = self.counter_store.get(self._store_key())
            if stored is not None and stored > security.invocation_counter:
                log.info("continuing from stored invocation counter %d", stored)
                security.set_invocation_counter(stored)
        if security is not None and self.discover_invocation_counter:
            self.discover_counter()
        self.link.connect()
        if self.auto_associate:
            self.associate()
        return self

    def _store_key(self) -> str:
        from pydlms.counters import CounterStore
        from pydlms.security.provider import is_raw_key, resolve

        description = getattr(getattr(self.link, "transport", None), "description", "link")
        security = self.association.security
        key = security.encryption_key if security else None
        if key is not None and not is_raw_key(key):
            # A handle: the provider names the key (a stable, non-secret
            # fingerprint), or the store cannot tell keys apart and refuses.
            key = resolve(getattr(security, "provider", None)).key_fingerprint(key)
        return CounterStore.make_key(description, self.link.client_sap, key)

    def discover_counter(self, extra_locations=None) -> dict[str, int]:
        """Read the meter's invocation counters via the public client.

        Opens and releases a separate public association on the same link,
        then moves the security context's outbound counter past the highest
        value found. Returns ``{location: value}``.
        """
        from pydlms.counters import read_invocation_counters

        security = self.association.security
        target_sap = self.link.client_sap
        self.link.client_sap = self.public_client_sap
        public = DlmsClient(
            self.link, AssociationSettings(logical_names=self.association.settings.logical_names)
        )
        try:
            public.connect()
            manufacturer = self.manufacturer
            if manufacturer is None:
                try:
                    name = public.get("0.0.42.0.0.255").value
                    text = name.decode("ascii", "replace") if isinstance(name, bytes) else name
                    manufacturer = text[:3] if text[:3].isalpha() else None
                except DlmsError:
                    manufacturer = None
            found = read_invocation_counters(public, manufacturer, extra_locations)
        finally:
            public.close()
            self.link.client_sap = target_sap
        if found and security is not None:
            highest = max(found.values())
            if highest + 1 > security.invocation_counter:
                security.set_invocation_counter(highest + 1)
            log.info(
                "invocation counter set to %d from %s",
                security.invocation_counter,
                max(found, key=found.get),
            )
        elif not found:
            log.warning("meter exposes no readable invocation counter to the public client")
        return found

    def associate(self) -> None:
        self.association.associate()
        if not self.association.settings.logical_names:
            self._load_sn_map()

    def close(self) -> None:
        try:
            if self.association.state != AssociationState.IDLE:
                self.association.release()
        finally:
            self.link.disconnect()
            security = self.association.security
            if security is not None and self.counter_store is not None:
                self.counter_store.put(self._store_key(), security.invocation_counter)

    def __enter__(self) -> DlmsClient:
        return self.connect()

    def __exit__(self, *exc) -> None:
        self.close()

    @property
    def conformance(self) -> xdlms.Conformance:
        return self.association.negotiated_conformance

    # -- GET -----------------------------------------------------------------------
    def _fits(self, request) -> bool:
        """Whether ``request`` can go as one APDU: it fits the server's max
        PDU once protected, or general-block-transfer carries it (then GBT
        is preferred to the service-specific blocks)."""
        if self.association.uses_gbt:
            return True
        return len(request.to_bytes()) <= self.association.max_plain_request()

    def _chunk_size(self, first_block_request) -> int:
        """Data octets per block so that the first (largest-header) block
        request fits the server's max PDU once protected. The header is
        measured with an empty chunk; 2 more octets cover the A-XDR length
        of a full chunk growing from 1 to 3 octets."""
        header = len(first_block_request.to_bytes()) + 2
        size = self.association.max_plain_request() - header
        if size < 1:
            raise ProtocolError(
                f"server max PDU {self.association.max_request_size} leaves no room for block data"
            )
        return size

    def _split_list(self, items: list, build) -> list[list]:
        """Cut ``items`` greedily, in order, into groups whose with-list
        request ``build(group)`` fits the server's max PDU once protected.
        A single item that does not fit stays a group of its own. With
        general-block-transfer in use the list stays whole."""
        if self.association.uses_gbt:
            return [list(items)]
        limit = self.association.max_plain_request()
        groups: list[list] = []
        chunk: list = []
        for item in items:
            if chunk and len(build([*chunk, item]).to_bytes()) > limit:
                groups.append(chunk)
                chunk = []
            chunk.append(item)
        groups.append(chunk)
        return groups

    def _send_blocks(self, what: str, invoke: int, first, encoded: bytes, action: bool):
        """Send ``encoded`` in numbered blocks and return the reply to the last.

        ``first(last, raw)`` builds block 1 (the request that names the
        attributes or methods); the others are Set-Request-With-Datablock or
        Action-Request-With-Pblock. Every non-final block must be
        acknowledged (Set-Response-Datablock / Action-Response-Next-Pblock)
        with its own number; an error result instead raises
        :class:`ServiceError`, anything else :class:`ProtocolError`.
        """
        limit = self._chunk_size(first(False, b""))
        chunks = [encoded[i : i + limit] for i in range(0, len(encoded), limit)] or [b""]
        ack = xdlms.ActionResponseNextPblock if action else xdlms.SetResponseDatablock
        log.debug("%s in %d blocks", what, len(chunks))
        for number, chunk in enumerate(chunks, start=1):
            last = number == len(chunks)
            if number == 1:
                request = first(last, chunk)
            elif action:
                request = xdlms.ActionRequestWithPblock(invoke, last, number, chunk)
            else:
                request = xdlms.SetRequestWithDatablock(invoke, last, number, chunk)
            response = xdlms.decode_apdu(self.association.request(request.to_bytes()))
            if last:
                if (
                    isinstance(response, xdlms.SetResponseLastDatablockWithList)
                    and response.block_number != number
                ):
                    raise ProtocolError(
                        f"{what}: last block {number} answered as block {response.block_number}"
                    )
                return response
            if not isinstance(response, ack):
                _raise_early_reply(what, number, response)
            if response.block_number != number:
                raise ProtocolError(
                    f"{what} block {number} acknowledged as block {response.block_number}"
                )
        raise AssertionError("unreachable")  # pragma: no cover

    def get(
        self,
        obis: ObisCode | str,
        class_id: int = ClassId.DATA,
        attribute: int | str = 2,
        access: xdlms.SelectiveAccess | None = None,
    ) -> DlmsData:
        """Read one attribute; follows GET-with-datablock transfers."""
        obis = _obis(obis)
        if isinstance(attribute, str):
            attribute = attribute_index(class_id, attribute)
        if not self.association.settings.logical_names:
            return self._sn_read(class_id, obis, attribute, access)
        descriptor = xdlms.AttributeDescriptor(int(class_id), obis, attribute)
        invoke = self.association.next_invoke_id()
        response = xdlms.decode_apdu(
            self.association.request(xdlms.GetRequestNormal(invoke, descriptor, access).to_bytes())
        )
        if isinstance(response, xdlms.GetResponseNormal):
            return self._data_or_raise(response.result, descriptor)
        if isinstance(response, xdlms.GetResponseWithDatablock):
            return self._collect_blocks(invoke, response, descriptor)
        raise ProtocolError(f"unexpected GET response {type(response).__name__}")

    @staticmethod
    def _data_or_raise(result: xdlms.GetDataResult, what) -> DlmsData:
        if not result.ok:
            raise ServiceError(f"GET {what} failed: {result_name(result.error)}", result.error)
        assert result.data is not None
        log.debug("GET %s -> %s", what, result.data.tag.name)
        return result.data

    def _collect_blocks(self, invoke: int, first, descriptor) -> DlmsData:
        buffer = self._collect_raw_blocks(invoke, first, descriptor)
        value, end = decode_data(buffer)
        if end != len(buffer):
            raise DecodeError(f"{len(buffer) - end} trailing octets after block-transferred data")
        return value

    def _collect_raw_blocks(self, invoke: int, first, descriptor) -> bytes:
        buffer = bytearray()
        block = first
        expected = 1
        while True:
            if block.error is not None:
                raise ServiceError(
                    f"GET {descriptor} block {block.block_number} failed: {result_name(block.error)}",
                    block.error,
                )
            if block.block_number != expected:
                raise ProtocolError(
                    f"GET block {block.block_number} out of sequence (expected {expected})"
                )
            buffer += block.raw_data or b""
            self.association._check_transfer_size(len(buffer))
            log.debug(
                "GET %s block %d (%d octets, last=%s)",
                descriptor,
                block.block_number,
                len(block.raw_data or b""),
                block.last_block,
            )
            if block.last_block:
                break
            response = xdlms.decode_apdu(
                self.association.request(
                    xdlms.GetRequestNext(invoke, block.block_number).to_bytes()
                )
            )
            if not isinstance(response, xdlms.GetResponseWithDatablock):
                raise ProtocolError(f"expected a data block, got {type(response).__name__}")
            block = response
            expected += 1
        return bytes(buffer)

    def get_many(
        self, items: list[tuple[ObisCode | str, int, int]]
    ) -> list[DlmsData | DataAccessResult]:
        """GET-with-list; falls back to single GETs if multiple references are
        not negotiated. Failed items come back as :class:`DataAccessResult`.

        A list whose request would exceed the server's max PDU is sent as
        several GET-with-list requests; results keep the order of ``items``.
        """
        if not items:
            return []
        if not (self.conformance & xdlms.Conformance.MULTIPLE_REFERENCES) or not (
            self.association.settings.logical_names
        ):
            out: list[DlmsData | DataAccessResult] = []
            for obis, cid, attr in items:
                try:
                    out.append(self.get(obis, cid, attr))
                except ServiceError as exc:
                    out.append(exc.result)  # type: ignore[arg-type]
            return out
        descriptors = [
            (xdlms.AttributeDescriptor(int(cid), _obis(obis), attr), None)
            for obis, cid, attr in items
        ]
        # Each request must fit the server's max PDU: send as many
        # descriptors per GET-Request-With-List as fit, in order.
        out: list[DlmsData | DataAccessResult] = []
        for group in self._split_list(descriptors, lambda g: xdlms.GetRequestWithList(0, g)):
            out.extend(self._get_with_list(group))
        return out

    def _get_with_list(self, descriptors: list) -> list[DlmsData | DataAccessResult]:
        if len(descriptors) > 1:
            log.debug("GET with-list of %d items", len(descriptors))
        invoke = self.association.next_invoke_id()
        response = xdlms.decode_apdu(
            self.association.request(xdlms.GetRequestWithList(invoke, descriptors).to_bytes())
        )
        if isinstance(response, xdlms.GetResponseWithDatablock):
            # The blocks carry the encoded SEQUENCE OF Get-Data-Result.
            raw = self._collect_raw_blocks(invoke, response, "with-list")
            results = xdlms.decode_get_data_results(raw)
        elif isinstance(response, xdlms.GetResponseWithList):
            results = response.results
        else:
            raise ProtocolError(f"expected GET-Response-With-List, got {type(response).__name__}")
        if len(results) != len(descriptors):
            raise ProtocolError(
                f"GET-with-list asked for {len(descriptors)} items, got {len(results)}"
            )
        return [r.data if r.ok else r.error for r in results]  # type: ignore[misc]

    # -- SET -------------------------------------------------------------------------
    def set(
        self,
        obis: ObisCode | str,
        class_id: int,
        attribute: int | str,
        value: DlmsData,
        access: xdlms.SelectiveAccess | None = None,
    ) -> None:
        obis = _obis(obis)
        if isinstance(attribute, str):
            attribute = attribute_index(class_id, attribute)
        if not self.association.settings.logical_names:
            self._sn_write(class_id, obis, attribute, value)
            return
        descriptor = xdlms.AttributeDescriptor(int(class_id), obis, attribute)
        encoded = encode_data(value)
        invoke = self.association.next_invoke_id()
        normal = xdlms.SetRequestNormal(invoke, descriptor, value, access)
        if self._fits(normal):
            response = xdlms.decode_apdu(self.association.request(normal.to_bytes()))
        else:
            response = self._send_blocks(
                f"SET {descriptor}",
                invoke,
                lambda last, raw: xdlms.SetRequestWithFirstDatablock(
                    invoke, descriptor, last, 1, raw, access
                ),
                encoded,
                action=False,
            )
        result = getattr(response, "result", None)
        if result is None:
            raise ProtocolError(f"unexpected SET response {type(response).__name__}")
        if result != DataAccessResult.SUCCESS:
            raise ServiceError(f"SET {descriptor} failed: {result_name(result)}", result)
        log.debug("SET %s ok", descriptor)

    def set_many(
        self,
        items: list[tuple[ObisCode | str, int, int, DlmsData]],
        *,
        split_lists: bool = True,
    ) -> list[DataAccessResult]:
        """SET-with-list: write several attributes in one request.

        Returns one :class:`DataAccessResult` per item, in the order of
        ``items`` (failures are not raised, like :meth:`get_many`). Falls
        back to single SETs when multiple references are not negotiated or
        SN referencing is in use.

        A list whose request would exceed the server's max PDU is sent as
        several SET-with-list requests (``split_lists``, the default); one
        that still does not fit (a single long value, or the whole list with
        ``split_lists=False``) goes as Set-Request-With-List-And-First-Datablock
        when block transfer with SET is negotiated, else :class:`ProtocolError`
        is raised before it is sent. A block refused during the transfer
        raises :class:`ServiceError`.
        """
        if not items:
            return []
        if not (self.conformance & xdlms.Conformance.MULTIPLE_REFERENCES) or not (
            self.association.settings.logical_names
        ):
            out: list[DataAccessResult] = []
            for obis, cid, attr, value in items:
                try:
                    self.set(obis, cid, attr, value)
                    out.append(DataAccessResult.SUCCESS)
                except ServiceError as exc:
                    out.append(exc.result)  # type: ignore[arg-type]
            return out
        entries = [
            (xdlms.AttributeDescriptor(int(cid), _obis(obis), attr), None, value)
            for obis, cid, attr, value in items
        ]
        groups = (
            self._split_list(entries, lambda g: xdlms.SetRequestWithList(0, g))
            if split_lists
            else [entries]
        )
        results: list[DataAccessResult] = []
        for group in groups:
            results.extend(self._set_with_list(group))
        log.debug("SET with-list: %s", [result_name(r) for r in results])
        return results

    def _set_with_list(self, entries: list) -> list[DataAccessResult]:
        invoke = self.association.next_invoke_id()
        request = xdlms.SetRequestWithList(invoke, entries)
        if self._fits(request):
            response = xdlms.decode_apdu(self.association.request(request.to_bytes()))
            if not isinstance(response, xdlms.SetResponseWithList):
                raise ProtocolError(
                    f"expected SET-Response-With-List, got {type(response).__name__}"
                )
        else:
            self._need_block_transfer(
                "SET-with-list", request, xdlms.Conformance.BLOCK_TRANSFER_WITH_SET_OR_WRITE
            )
            descriptors = [(attribute, access) for attribute, access, _ in entries]
            response = self._send_blocks(
                "SET-with-list",
                invoke,
                lambda last, raw: xdlms.SetRequestWithListAndFirstDatablock(
                    invoke, descriptors, last, 1, raw
                ),
                xdlms.encode_data_list([value for _, _, value in entries]),
                action=False,
            )
            if not isinstance(response, xdlms.SetResponseLastDatablockWithList):
                _raise_early_reply("SET-with-list", None, response)
        if len(response.results) != len(entries):
            raise ProtocolError(
                f"SET-with-list sent {len(entries)} items, got {len(response.results)} results"
            )
        return list(response.results)

    def _need_block_transfer(self, what: str, request, bit: xdlms.Conformance) -> None:
        if not self.conformance & bit:
            raise ProtocolError(
                f"{what} of {len(request.to_bytes())} octets exceeds the negotiated PDU size "
                f"and {bit.name} was not negotiated; split the list or use single requests"
            )

    # -- ACTION ------------------------------------------------------------------------
    def action(
        self,
        obis: ObisCode | str,
        class_id: int,
        method: int | str,
        parameters: DlmsData | None = None,
    ) -> DlmsData | None:
        from pydlms.cosem.interface_classes import lookup

        obis = _obis(obis)
        if isinstance(method, str):
            ic = lookup(class_id)
            if ic is None:
                raise KeyError(f"unknown interface class {class_id}")
            method = ic.method_index(method)
        descriptor = xdlms.MethodDescriptor(int(class_id), obis, method)
        if not self.association.settings.logical_names:
            address = self._sn_method_address(class_id, obis, method)
            return self.association.sn_action_raw(address, parameters or DlmsData.null())
        encoded = encode_data(parameters) if parameters is not None else b""
        # Invoke-id 0 only sizes the request; the real one is taken on sending.
        if self._fits(xdlms.ActionRequestNormal(0, descriptor, parameters)):
            result = self.association.action_raw(descriptor, parameters)
        else:
            result = self._action_blocks(descriptor, encoded)
        log.debug("ACTION %s ok", descriptor)
        return result

    # -- ACCESS ------------------------------------------------------------------------
    def access(
        self,
        operations: Iterable[AccessOperation],
        *,
        break_on_error: bool = False,
        date_time: CosemDateTime | _dt.datetime | bytes | None = None,
    ) -> list[AccessOutcome]:
        """Run several get / set / action operations in one ACCESS request.

        ``operations`` are :class:`AccessGet`, :class:`AccessSet` and
        :class:`AccessAction`; the answer is one :class:`AccessOutcome` per
        operation, in order (failures are results, not exceptions, like
        :meth:`get_many`). ``break_on_error`` asks the meter to stop at the
        first failing operation; ``date_time`` is the optional request
        date-time.

        ACCESS must have been negotiated (``propose_access=True`` and a meter
        that grants conformance bit 17), else :class:`ProtocolError` is
        raised before anything is sent. In a ciphered association it is sent
        with general-glo / general-ded (or the configured general
        envelope). A request longer than the meter's PDU goes in
        general-block-transfer when that was negotiated, else it raises
        :class:`ProtocolError`. A response whose results do not match the
        operations in number and kind raises :class:`ProtocolError`.
        """
        ops = list(operations)
        if not ops:
            return []
        if not self.association.settings.logical_names:
            raise ProtocolError("ACCESS is a Logical-Name service; this association uses SN")
        if not self.association.access_negotiated:
            raise ProtocolError(
                "the ACCESS service was not negotiated (propose it with propose_access=True)"
            )
        pairs = [_access_spec(op) for op in ops]
        if isinstance(date_time, _dt.datetime):
            date_time = CosemDateTime.from_datetime(date_time)
        if isinstance(date_time, CosemDateTime):
            date_time = date_time.to_bytes()
        invoke = self.association.next_long_invoke_id(break_on_error=break_on_error)
        request = xdlms.AccessRequest(
            invoke, date_time, [spec for spec, _ in pairs], [value for _, value in pairs]
        )
        response = xdlms.decode_apdu(self.association.request(request.to_bytes()))
        if not isinstance(response, xdlms.AccessResponse):
            raise ProtocolError(f"expected an ACCESS response, got {type(response).__name__}")
        if len(response.results) != len(ops):
            raise ProtocolError(
                f"ACCESS sent {len(ops)} operations, got {len(response.results)} results"
            )
        if (
            response.specifications is not None
            and response.specifications != request.specifications
        ):
            raise ProtocolError("the ACCESS response echoes other specifications than were sent")
        out = []
        for index, (op, (spec, _), result, data) in enumerate(
            zip(ops, pairs, response.results, response.data, strict=True)
        ):
            expected = _ACCESS_RESULT_FOR[spec.kind]
            if not isinstance(result, expected):
                raise ProtocolError(
                    f"ACCESS operation {index} ({spec}) answered with a "
                    f"{result.kind.name.lower()} result"
                )
            out.append(AccessOutcome(op, result.result, data))
        log.debug("ACCESS: %s", [result_name(o.result) for o in out])
        return out

    # -- broadcast ---------------------------------------------------------------------
    def broadcast_set(
        self,
        obis: ObisCode | str,
        class_id: int,
        attribute: int | str,
        value: DlmsData,
    ) -> None:
        """SET an attribute on every server of the link at once, ciphered with
        the global broadcast key (:meth:`Association.send_broadcast`).

        An unconfirmed set-request-normal (SN: an UnconfirmedWriteRequest) in
        one APDU: no block transfer, no answer, so no result either.
        """
        obis = _obis(obis)
        if isinstance(attribute, str):
            attribute = attribute_index(class_id, attribute)
        if not self.association.settings.logical_names:
            address = sn.attribute_address(self._base_name(class_id, obis), attribute)
            request = sn.UnconfirmedWriteRequest([sn.VariableName(address)], [value])
            self.association.send_broadcast(request.to_bytes())
            return
        descriptor = xdlms.AttributeDescriptor(int(class_id), obis, attribute)
        invoke = xdlms.invoke_id_byte(self.association.next_invoke_id() & 0x0F, confirmed=False)
        self.association.send_broadcast(
            xdlms.SetRequestNormal(invoke, descriptor, value).to_bytes()
        )
        log.debug("broadcast SET %s sent", descriptor)

    def broadcast_action(
        self,
        obis: ObisCode | str,
        class_id: int,
        method: int | str,
        parameters: DlmsData | None = None,
    ) -> None:
        """Invoke a method on every server of the link at once, ciphered with
        the global broadcast key (:meth:`Association.send_broadcast`).

        An unconfirmed action-request-normal in one APDU; no return data. LN
        only: SN methods are invoked here with a ReadRequest, which is
        confirmed, so a short-name association raises :class:`ProtocolError`.
        """
        from pydlms.cosem.interface_classes import lookup

        obis = _obis(obis)
        if isinstance(method, str):
            ic = lookup(class_id)
            if ic is None:
                raise KeyError(f"unknown interface class {class_id}")
            method = ic.method_index(method)
        if not self.association.settings.logical_names:
            raise ProtocolError("no unconfirmed form of a short-name method invocation")
        descriptor = xdlms.MethodDescriptor(int(class_id), obis, method)
        invoke = xdlms.invoke_id_byte(self.association.next_invoke_id() & 0x0F, confirmed=False)
        self.association.send_broadcast(
            xdlms.ActionRequestNormal(invoke, descriptor, parameters).to_bytes()
        )
        log.debug("broadcast ACTION %s sent", descriptor)

    def action_many(
        self,
        items: list[tuple[ObisCode | str, int, int | str, DlmsData | None]],
        *,
        split_lists: bool = True,
    ) -> list[DlmsData | None | ActionResult | DataAccessResult]:
        """ACTION-with-list: invoke several methods in one request.

        Each entry is the method's return data (or None); a failed method
        comes back as its :class:`ActionResult`, a failed return value as
        its :class:`DataAccessResult`. Falls back to single ACTIONs when
        multiple references are not negotiated or SN referencing is in use.

        Lists too long for the server's max PDU are split and sent in
        pblocks exactly as in :meth:`set_many` (Action-Request-With-List-
        And-First-Pblock needs block transfer with ACTION).
        """
        from pydlms.cosem.interface_classes import lookup

        if not items:
            return []
        out: list[DlmsData | None | ActionResult | DataAccessResult] = []
        if not (self.conformance & xdlms.Conformance.MULTIPLE_REFERENCES) or not (
            self.association.settings.logical_names
        ):
            for obis, cid, method, params in items:
                try:
                    out.append(self.action(obis, cid, method, params))
                except ServiceError as exc:
                    out.append(exc.result)  # type: ignore[arg-type]
            return out
        methods = []
        for obis, cid, method, params in items:
            if isinstance(method, str):
                ic = lookup(cid)
                if ic is None:
                    raise KeyError(f"unknown interface class {cid}")
                method = ic.method_index(method)
            methods.append((xdlms.MethodDescriptor(int(cid), _obis(obis), method), params))
        groups = (
            self._split_list(methods, lambda g: xdlms.ActionRequestWithList(0, g))
            if split_lists
            else [methods]
        )
        for group in groups:
            for result, data in self._action_with_list(group):
                if result != ActionResult.SUCCESS:
                    out.append(result)
                elif data is None:
                    out.append(None)
                else:
                    out.append(data.data if data.ok else data.error)
        return out

    def _action_with_list(self, methods: list) -> list:
        invoke = self.association.next_invoke_id()
        request = xdlms.ActionRequestWithList(invoke, methods)
        if self._fits(request):
            response = xdlms.decode_apdu(self.association.request(request.to_bytes()))
        else:
            self._need_block_transfer(
                "ACTION-with-list", request, xdlms.Conformance.BLOCK_TRANSFER_WITH_ACTION
            )
            descriptors = [method for method, _ in methods]
            response = self._send_blocks(
                "ACTION-with-list",
                invoke,
                lambda last, raw: xdlms.ActionRequestWithListAndFirstPblock(
                    invoke, descriptors, last, 1, raw
                ),
                xdlms.encode_data_list(
                    [params if params is not None else DlmsData.null() for _, params in methods]
                ),
                action=True,
            )
        if not isinstance(response, xdlms.ActionResponseWithList):
            _raise_early_reply("ACTION-with-list", None, response)
        if len(response.results) != len(methods):
            raise ProtocolError(
                f"ACTION-with-list sent {len(methods)} methods, got {len(response.results)} results"
            )
        return response.results

    def _action_blocks(self, descriptor, encoded: bytes):
        invoke = self.association.next_invoke_id()
        response = self._send_blocks(
            f"ACTION {descriptor}",
            invoke,
            lambda last, raw: xdlms.ActionRequestWithFirstPblock(invoke, descriptor, last, 1, raw),
            encoded,
            action=True,
        )
        return self.association.action_result(invoke, response, descriptor)

    # -- key management ----------------------------------------------------------------
    def transfer_keys(
        self, keys: dict[int, bytes], security_setup: ObisCode | str = "0.0.43.0.0.255"
    ) -> None:
        """Install new global keys with Security Setup ``key_transfer``
        (IC 64 method 2): each key is AES-key-wrapped (RFC 3394) under the
        master key (KEK) of this association's :class:`SecurityContext`.

        ``keys`` maps :class:`~pydlms.security.keywrap.KeyId` to the new key.
        The meter applies them after answering; reconnect with a context
        holding the new keys. Key bytes are never logged.
        """
        from pydlms.security.keywrap import KeyId, key_transfer_data
        from pydlms.security.suites import key_length

        security = self.association.security
        if security is None or security.master_key is None:
            raise KeyMissingError("key_transfer needs SecurityContext.master_key (the KEK)")
        if not keys:
            raise ValueError("no keys to transfer")
        # The context checked a raw master key against the suite; a provider
        # handle has the suite's length by the same contract.
        expected = key_length(security.suite)
        for key_id, key in keys.items():
            KeyId(key_id)  # raises ValueError on an unknown key id
            if len(key) != expected:
                raise ValueError(
                    f"{KeyId(key_id).name} key is {len(key)} octets; the suite's keys are "
                    f"{expected}"
                )
        parameter = key_transfer_data(
            security.master_key,
            {KeyId(k): v for k, v in keys.items()},
            provider=getattr(security, "provider", None),
        )
        self.action(security_setup, ClassId.SECURITY_SETUP, 2, parameter)
        log.info("key_transfer: installed %s", ", ".join(KeyId(k).name for k in keys))

    def agree_keys(
        self, key_ids: Iterable[int], security_setup: ObisCode | str = "0.0.43.0.0.255"
    ) -> dict[KeyId, bytes]:
        """Agree new global keys with Security Setup ``key_agreement``
        (IC 64 method 3, suites 1/2, IEC 62056-5-3:2023 annex I.1).

        Sends a signed ephemeral key per key id, checks the meter's signed
        answer under ``peer_signing_key`` and derives each key with the KDF
        (:mod:`pydlms.security.keyagreement`). Needs ``signing_key``,
        ``peer_signing_key`` and both system titles in the association's
        :class:`SecurityContext`. Key ids 0, 1 and 2 only.

        Returns ``{KeyId: key}``. The context is **not** changed: the meter
        switches to the new keys after answering, so reconnect with a
        context holding them. Keys are registered for log redaction.
        """
        from pydlms.security import keyagreement

        security = self.association.security
        if security is None:
            raise KeyMissingError("key_agreement needs a SecurityContext")
        if security.signing_key is None or security.peer_signing_key is None:
            raise KeyMissingError("key_agreement needs signing_key and peer_signing_key")
        if not security.own_title_known or security.server_system_title is None:
            raise KeyMissingError("key_agreement needs the client and server system titles")
        suite = security.suite
        ephemeral, offers = keyagreement.offers_for(
            security.signing_key, suite, key_ids, provider=getattr(security, "provider", None)
        )
        answer = self.action(
            security_setup,
            ClassId.SECURITY_SETUP,
            3,
            keyagreement.key_agreement_data(offers),
        )
        keys = keyagreement.agree(
            suite,
            ephemeral,
            security.peer_signing_key,
            answer,
            security.client_system_title,
            security.server_system_title,
        )
        log.info("key_agreement: agreed %s", ", ".join(k.name for k in keys))
        return keys

    def security_activate(
        self,
        policy: int,
        *,
        version: int | None = None,
        security_setup: ObisCode | str = "0.0.43.0.0.255",
        refuse_weakening: bool = False,
    ) -> None:
        """Raise the meter's security policy with Security Setup
        ``security_activate`` (IC 64 method 1).

        Version 0 takes an enum (:class:`~pydlms.security.suites.SecurityPolicyV0`),
        version 1 a bit field (:class:`~pydlms.security.suites.SecurityPolicyBits`);
        the same number means different things, so ``version`` is taken from
        the association view when not given and never guessed (no view entry
        raises :class:`ServiceError`). With ``refuse_weakening`` the current
        policy (attribute 2) is read first and a policy dropping any of its
        protections raises :class:`SecurityError` before anything is sent.
        A new policy may lock this session out; reconnect with matching
        protection afterwards.
        """
        from pydlms.exceptions import SecurityError
        from pydlms.security.suites import security_policy_value, security_policy_weakens

        obis = _obis(security_setup)
        if version is None:
            entry = self._view_index().get(obis)
            if entry is None or entry.class_id != ClassId.SECURITY_SETUP:
                raise ServiceError(
                    f"{obis} is not a Security Setup in the association view; pass version="
                )
            version = entry.version
        value = security_policy_value(policy, version)
        if refuse_weakening:
            current = self.get(obis, ClassId.SECURITY_SETUP, 2)
            if current.tag != DataType.ENUM:
                raise DecodeError(f"security_policy of {obis} is {current.tag.name}, not an enum")
            if security_policy_weakens(current.value, value, version):
                raise SecurityError(
                    f"security_activate 0x{value:02X} would weaken the current policy "
                    f"0x{current.value:02X} of {obis} (version {version})"
                )
        self.action(obis, ClassId.SECURITY_SETUP, 1, DlmsData.enum(value))
        log.info("security_activate: %s policy 0x%02X (version %d)", obis, value, version)

    def generate_key_pair(
        self, key_type: int, security_setup: ObisCode | str = "0.0.43.0.0.255"
    ) -> None:
        """Have the meter generate a new key pair (IC 64 method 4).

        ``key_type`` is :class:`~pydlms.cosem.model.KeyType` (0 signing,
        1 key agreement, 2 TLS). The old key pair is gone afterwards.
        """
        from pydlms.cosem.model import KeyType

        key_type = KeyType(key_type)
        self.action(security_setup, ClassId.SECURITY_SETUP, 4, DlmsData.enum(key_type))
        log.info("generate_key_pair: %s", key_type.name)

    def certificate_request(
        self,
        key_type: int,
        security_setup: ObisCode | str = "0.0.43.0.0.255",
        suite: int | None = None,
    ):
        """Ask the meter for a PKCS #10 request for one of its key pairs
        (IC 64 method 5) and check it with
        :func:`~pydlms.security.certificates.load_certificate_request`
        (curve, ECDSA hash and self-signature for the suite).

        The suite is ``suite``, else the security context's (1/2), else
        attribute 3 of the Security Setup. Returns the
        ``cryptography.x509.CertificateSigningRequest``.
        """
        from pydlms.cosem.model import KeyType
        from pydlms.security.certificates import load_certificate_request

        key_type = KeyType(key_type)
        resolved = self._certificate_suite(security_setup, suite)
        answer = self.action(security_setup, ClassId.SECURITY_SETUP, 5, DlmsData.enum(key_type))
        return load_certificate_request(_octets(answer, "certificate request"), resolved)

    def import_certificate(
        self, certificate: Any, security_setup: ObisCode | str = "0.0.43.0.0.255"
    ) -> None:
        """Give the meter an X.509 certificate (IC 64 method 6).

        ``certificate`` is a :class:`~pydlms.security.certificates.DlmsCertificate`,
        a ``cryptography`` certificate, or PEM/DER; it is parsed before
        sending and sent as DER.
        """
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding

        from pydlms.security.certificates import DlmsCertificate

        if isinstance(certificate, DlmsCertificate):
            certificate = certificate.certificate
        if not hasattr(certificate, "public_bytes"):
            raw = certificate.encode("ascii") if isinstance(certificate, str) else certificate
            raw = bytes(raw)
            try:
                if raw.lstrip().startswith(b"-----BEGIN"):
                    certificate = x509.load_pem_x509_certificate(raw)
                else:
                    certificate = x509.load_der_x509_certificate(raw)
            except ValueError as exc:
                raise DecodeError(f"not a PEM or DER X.509 certificate: {exc}") from None
        der = certificate.public_bytes(Encoding.DER)
        self.action(security_setup, ClassId.SECURITY_SETUP, 6, DlmsData.octet_string(der))
        log.info("import_certificate: serial %x", certificate.serial_number)

    def export_certificate(
        self,
        selector,
        security_setup: ObisCode | str = "0.0.43.0.0.255",
        suite: int | None = None,
    ):
        """Read a certificate the meter holds (IC 64 method 7).

        ``selector`` is a :class:`~pydlms.security.certificates.CertificateSelector`.
        Returns a :class:`~pydlms.security.certificates.DlmsCertificate`
        (so the certificate needs a system-title CommonName; a CA
        certificate raises :class:`DecodeError`). Selected by entity, the
        certificate must carry the requested system title and key usage,
        else :class:`SecurityError`.

        The result is **not** trusted and is never installed as the
        context's ``peer_certificate``: pydlms does no chain validation.
        Validate it against your CA before passing it to a
        :class:`SecurityContext`.
        """
        from pydlms.exceptions import SecurityError
        from pydlms.security.certificates import CertificateType, load_certificate

        resolved = self._certificate_suite(security_setup, suite)
        answer = self.action(security_setup, ClassId.SECURITY_SETUP, 7, selector.to_data())
        cert = load_certificate(_octets(answer, "certificate"), resolved)
        if not selector.by_serial:
            if cert.system_title != selector.system_title:
                raise SecurityError(
                    f"exported certificate is for {cert.system_title.hex()}, "
                    f"not the requested {bytes(selector.system_title or b'').hex()}"
                )
            usage = {
                CertificateType.DIGITAL_SIGNATURE: cert.can_sign,
                CertificateType.KEY_AGREEMENT: cert.can_agree,
            }.get(selector.certificate_type, True)
            if not usage:
                raise SecurityError(
                    f"exported certificate's KeyUsage does not allow {selector.certificate_type}"
                )
        return cert

    def remove_certificate(
        self, selector, security_setup: ObisCode | str = "0.0.43.0.0.255"
    ) -> None:
        """Remove a certificate from the meter (IC 64 method 8)."""
        self.action(security_setup, ClassId.SECURITY_SETUP, 8, selector.to_data())
        log.info("remove_certificate: done")

    def _certificate_suite(self, security_setup: ObisCode | str, suite: int | None) -> int:
        from pydlms.exceptions import SecurityError
        from pydlms.security.suites import SecuritySuite

        if suite is None:
            security = self.association.security
            if security is not None and security.suite != SecuritySuite.AES_GCM_128:
                suite = int(security.suite)
            else:
                value = self.get(security_setup, ClassId.SECURITY_SETUP, 3)
                if value.tag != DataType.ENUM:
                    raise DecodeError(f"security_suite is {value.tag.name}, not an enum")
                suite = value.value
        if suite not in (1, 2):
            raise SecurityError(f"security suite {suite} does not use certificates")
        return int(suite)

    # -- conveniences ----------------------------------------------------------------
    def get_register(self, obis: ObisCode | str, class_id: int = ClassId.REGISTER) -> RegisterValue:
        """Read a Register / Extended register: value (attr 2) scaled by attr 3."""
        value = self.get(obis, class_id, 2)
        scaler, unit = scaler_unit(self.get(obis, class_id, 3))
        return RegisterValue(value.to_python(), scaler, unit)

    def read_hdlc_inactivity_timeout(
        self, obis: ObisCode | str = HDLC_SETUP_OBIS, apply: bool = True
    ) -> int:
        """Read ``inactivity_time_out`` (attribute 8, seconds) of the IEC HDLC
        setup object (IC 23) and return it.

        With ``apply`` and an HDLC link, the link tracks it from now on
        (``HdlcLink.inactivity_timeout``; 0, "not operational", turns the
        tracking off). A value that is not an unsigned integer raises
        :class:`~pydlms.exceptions.DecodeError` and changes nothing.
        """
        value = self.get(obis, ClassId.IEC_HDLC_SETUP, 8)
        if value.tag not in _UNSIGNED_TAGS or not isinstance(value.value, int):
            raise DecodeError(f"HDLC inactivity_time_out is {value.tag.name}, not an unsigned")
        seconds = value.value
        if apply and hasattr(self.link, "inactivity_timeout"):
            self.link.inactivity_timeout = seconds or None
            log.info("HDLC inactivity time-out from the meter: %ds", seconds)
        return seconds

    def get_clock(self, obis: ObisCode | str = "0.0.1.0.0.255") -> CosemDateTime:
        value = self.get(obis, ClassId.CLOCK, 2)
        return CosemDateTime.from_bytes(bytes(value.value))

    def set_clock(self, when: _dt.datetime, obis: ObisCode | str = "0.0.1.0.0.255") -> None:
        raw = CosemDateTime.from_datetime(when).to_bytes()
        self.set(obis, ClassId.CLOCK, 2, DlmsData.octet_string(raw))

    def object(self, obis: ObisCode | str, class_id: int | None = None, version: int = 0):
        """A :class:`~pydlms.objects.CosemObject` with typed attributes/methods.

        Without ``class_id`` the class and version come from the association
        view (read once and cached).
        """
        from pydlms.objects import CosemObject

        obis = _obis(obis)
        if class_id is None:
            entry = self._view_index().get(obis)
            if entry is None:
                raise ServiceError(f"{obis} is not in the association view; pass class_id")
            class_id, version = entry.class_id, entry.version
        return CosemObject(self, class_id, obis, version)

    def objects(self) -> list:
        """Every object of the association view, bound and typed."""
        from pydlms.objects import CosemObject

        return [
            CosemObject(self, e.class_id, e.logical_name, e.version)
            for e in self._view_index().values()
        ]

    def _view_index(self) -> dict[ObisCode, ObjectListEntry]:
        if getattr(self, "_view_cache", None) is None:
            self._view_cache = {e.logical_name: e for e in self.get_association_view()}
        return self._view_cache

    def get_association_view(self) -> list[ObjectListEntry]:
        """Read the current association's object_list.

        LN entries carry their decoded access rights in ``rights`` (see
        :mod:`pydlms.cosem.access`); a malformed ``access_rights`` field
        leaves ``rights`` at ``None`` with a warning, the entry itself stays.
        """
        if self.association.settings.logical_names:
            data = self.get(_ASSOCIATION_LN, ClassId.ASSOCIATION_LN, 2)
            return _with_rights([_ln_entry(item) for item in _array(data, "object_list")])
        data = self._sn_read_address(0xFA00 + 8)
        return [_sn_entry(item) for item in _array(data, "object_list")]

    def can_read(
        self,
        obis: ObisCode | str,
        class_id: int | None = None,
        attribute: int | str = 2,
    ) -> bool | None:
        """Whether the association view grants read access to an attribute.

        ``None`` means unknown: the object or attribute is not in the view,
        ``class_id`` differs from the view's, the view is Short-Name or its
        rights did not decode, or the mode is one the class version does not
        define. Meters often list only the attributes they support, so an
        unlisted attribute is not taken as denied. Advisory only:
        :meth:`get` never refuses in advance. Reads the view once (cached).
        """
        entry = self._view_index().get(_obis(obis))
        if entry is None or entry.rights is None:
            return None
        if class_id is not None and int(class_id) != entry.class_id:
            return None
        if isinstance(attribute, str):
            attribute = attribute_index(entry.class_id, attribute)
        return entry.rights.can_read(attribute)

    def read_profile(
        self,
        obis: ObisCode | str,
        access: xdlms.SelectiveAccess | None = None,
        *,
        typed: bool = False,
        scalers: bool | Mapping[ObisCode | str, tuple[int, Unit | int | None]] = False,
        fill_timestamps: bool = False,
        fill_values: bool = False,
        resolve_deltas: bool = False,
    ) -> ProfileBuffer:
        """Read a Profile generic buffer (attr 2) and its capture objects (attr 3).

        With selective access that narrows the columns (entry descriptor
        ``from/to_selected_value``, or a non-empty range descriptor
        ``selected_values``) the meter returns only those columns, so
        ``columns`` lists only them. Every row must have one cell per column,
        otherwise :class:`DecodeError` is raised.

        ``typed=True`` types the cells (:func:`pydlms.cosem.profile.typed_rows`):
        date-times become :class:`CosemDateTime`, and with ``scalers`` register
        values become :class:`RegisterValue`. ``scalers=True`` reads the
        ``scaler_unit`` of every captured register once (GET-with-list, cached
        on this client); a mapping ``{logical name: (scaler, unit)}`` supplies
        them instead. ``fill_timestamps`` (reads attributes 4 and 5) and
        ``fill_values`` reconstruct null-data cells of a compressed buffer.
        Any of ``scalers`` / ``fill_*`` implies ``typed``.

        ``resolve_deltas=True`` (PROVISIONAL, :mod:`pydlms.cosem.delta`) turns
        delta-typed cells into absolute values before ``rows`` are built: each
        column accumulates from the previous row's absolute value. A delta
        with no base or one overflowing its base type raises
        :class:`DecodeError`. ``cells`` always holds the received ``Data``,
        deltas included.
        """
        capture = self.get(obis, ClassId.PROFILE_GENERIC, 3)
        columns = [_capture_object(item) for item in _array(capture, "capture_objects")]
        columns = _selected_columns(columns, access)
        buffer = self.get(obis, ClassId.PROFILE_GENERIC, 2, access)
        cells = []
        for number, row in enumerate(_array(buffer, "profile buffer"), 1):
            values = row.value if row.tag == DataType.STRUCTURE else None
            if values is None or len(values) != len(columns):
                found = f"{len(values)} cells" if values is not None else row.tag.name
                raise DecodeError(
                    f"profile {obis} row {number} has {found} for {len(columns)} columns"
                )
            cells.append(values)
        source = cells
        if resolve_deltas:
            resolved = _resolve_deltas(DlmsData.array([DlmsData.structure(r) for r in cells]))
            source = [row.value for row in resolved.value]
        if not (typed or scalers or fill_timestamps or fill_values):
            return ProfileBuffer(columns, [[c.to_python() for c in row] for row in source], cells)
        period = sort = None
        if fill_timestamps:
            period, sort = self._profile_order(obis)
        rows = typed_rows(
            columns,
            source,
            scalers=self._scalers_for(columns, scalers),
            fill_timestamps=fill_timestamps,
            capture_period=period,
            sort_method=sort,
            fill_values=fill_values,
        )
        return ProfileBuffer(columns, rows, cells)

    def _profile_order(self, obis: ObisCode | str) -> tuple[int | None, int | None]:
        """``capture_period`` (attr 4) and ``sort_method`` (attr 5); None if unread."""
        out: list[int | None] = []
        items = [(obis, ClassId.PROFILE_GENERIC, 4), (obis, ClassId.PROFILE_GENERIC, 5)]
        for (_, _, attribute), result in zip(items, self.get_many(items), strict=True):
            value = result.value if isinstance(result, DlmsData) else None
            if not isinstance(value, int) or isinstance(value, bool):
                log.warning(
                    "profile %s attribute %d unusable for filling: %s", obis, attribute, result
                )
                value = None
            out.append(value)
        return out[0], out[1]

    def _scalers_for(
        self, columns: list, scalers: bool | Mapping
    ) -> dict[ObisCode, tuple[int, Unit | int | None]]:
        """The ``(scaler, unit)`` of each register in ``columns``.

        ``scalers=True`` reads every register not yet cached in one
        GET-with-list; a register whose scaler_unit fails to read or decode is
        cached as unknown (warning) and its values stay unscaled.
        """
        if isinstance(scalers, Mapping):
            return {_obis(k): v for k, v in scalers.items()}
        if not scalers:
            return {}
        cache = self._scaler_cache
        wanted = [r for r in scaled_registers(columns) if (r[0], r[1]) not in cache]
        results = self.get_many([(obis, cid, attr) for cid, obis, attr in wanted])
        for (cid, obis, attr), result in zip(wanted, results, strict=True):
            try:
                if not isinstance(result, DlmsData):
                    raise ServiceError(f"read failed: {result_name(result)}", result)
                cache[(cid, obis)] = register_scaler(result)
            except DlmsError as exc:
                log.warning(
                    "scaler_unit of %s (class %d attr %d) unknown: %s", obis, cid, attr, exc
                )
                cache[(cid, obis)] = None
        return {
            obis: cache[(cid, obis)]
            for cid, obis, _ in scaled_registers(columns)
            if cache.get((cid, obis)) is not None
        }

    def read_compact_data(
        self,
        obis: ObisCode | str,
        *,
        typed: bool = False,
        scalers: bool | Mapping[ObisCode | str, tuple[int, Unit | int | None]] = False,
        resolve_deltas: bool = False,
    ) -> CompactData:
        """Read a Compact data object (IC 62) and decode its buffer.

        Reads capture_objects, template_id, template_description and
        capture_method (attributes 3 to 6, one GET-with-list) first, then
        compact_buffer (attribute 2). The template must be a structure with
        one member per capture object, else :class:`DecodeError`; an
        unreadable capture_method (class version 0, access) is ``None``.
        ``typed`` and ``scalers`` work as in :meth:`read_profile`. An empty
        buffer (nothing captured yet) gives empty ``cells``. The template_id
        is in the buffer only when it is a capture object, as in the Blue
        Book examples (see :mod:`pydlms.cosem.compact_data`).

        ``resolve_deltas=True`` (PROVISIONAL, :mod:`pydlms.cosem.delta`)
        resolves deltas in ``values``; ``cells`` keep the received ``Data``.
        One capture is a structure, not an array, so only deltas inside an
        array member can resolve; a delta capture object itself has no base
        and raises :class:`DecodeError`.
        """
        cid = ClassId.COMPACT_DATA
        names = ("capture_objects", "template_id", "template_description")
        results = self.get_many([(obis, cid, attribute) for attribute in (3, 4, 5, 6)])
        for name, result in zip(names, results, strict=False):
            if not isinstance(result, DlmsData):
                raise ServiceError(f"GET {obis} {name} failed: {result_name(result)}", result)
        capture, template_id, template, method = results
        columns = [_capture_object(item) for item in _array(capture, "capture_objects")]
        template_id = _int_field(template_id, "template_id")
        desc = decode_template_description(_octets(template, "template_description"))
        if desc.tag != DataType.STRUCTURE:
            raise DecodeError(f"template_description is {desc.tag.name}, not a structure")
        if len(desc.members) != len(columns):
            raise DecodeError(
                f"template_description has {len(desc.members)} members "
                f"for {len(columns)} capture objects"
            )
        capture_method = None
        if isinstance(method, DlmsData) and isinstance(method.value, int):
            capture_method = method.value
        buffer = _octets(self.get(obis, cid, 2), "compact_buffer")
        cells = decode_compact_buffer(desc, buffer) if buffer else []
        source = cells
        if resolve_deltas and cells:
            source = _resolve_deltas(DlmsData.structure(cells)).value
        if source and (typed or scalers):
            values = typed_rows(columns, [source], scalers=self._scalers_for(columns, scalers))[0]
        else:
            values = [cell.to_python() for cell in source]
        return CompactData(columns, template_id, desc, capture_method, cells, values)

    # -- push ----------------------------------------------------------------------------
    def read_push(self, timeout: float | None = None, profile=None):
        """Wait for the next DataNotification on this link and decode it.

        Uses the association's security context (if any) to decipher. Works on
        an associated link and on a bare push port (``auto_associate=False``).
        A push that arrived during a request was queued there and is returned
        first, exactly once.
        """
        from pydlms.push import PushDecoder

        decoder = PushDecoder("raw", security=self.association.security, profile=profile)
        while True:
            # Pushes the association queued during a request come first,
            # already deciphered and checked.
            message = decoder.decode_queued(self.link.receive_queued_push(timeout))
            if message is not None:  # None while general-block-transfer is in progress
                return message

    def push_decoder_from_meter(
        self, push_setup: ObisCode | str = "0.0.25.9.0.255", **decoder_kwargs: Any
    ):
        """Read a Push setup's ``push_object_list`` and build a positional decoder.

        GETs attribute 2 of the Push setup (IC 40) at ``push_setup`` and returns
        ``PushDecoder(capture_objects=<that list>, **decoder_kwargs)``, so pushes
        without inline OBIS labels (IDIS, compact lists) decode by position.
        The list is meter data: anything but an array of ``{class_id,
        logical_name (6 octets), attribute_index, data_index}`` structures, or
        an empty array, raises :class:`DecodeError`.
        """
        from pydlms.push import PushDecoder, parse_capture_objects

        obis = _obis(push_setup)
        objects = self.get(obis, ClassId.PUSH_SETUP, 2)
        if objects.tag != DataType.ARRAY:
            raise DecodeError(f"push setup {obis} push_object_list is {objects.tag.name}")
        for number, entry in enumerate(objects.value, 1):
            fields = entry.value if entry.tag == DataType.STRUCTURE else None
            if fields is None or len(fields) != 4:
                raise DecodeError(
                    f"push setup {obis} push_object_list entry {number} is not "
                    "{class_id, logical_name, attribute_index, data_index}"
                )
        capture = parse_capture_objects(objects)
        if not capture:
            raise DecodeError(f"push setup {obis} push_object_list is empty")
        return PushDecoder(capture_objects=capture, **decoder_kwargs)

    # -- short-name support ------------------------------------------------------------
    def _load_sn_map(self) -> None:
        entries = self.get_association_view()
        self._sn_map = {
            (e.class_id, e.logical_name): e.base_name for e in entries if e.base_name is not None
        }
        self._sn_versions = {(e.class_id, e.logical_name): e.version for e in entries}
        log.debug("loaded %d short names", len(self._sn_map))

    def _base_name(self, class_id: int, obis: ObisCode) -> int:
        if self._sn_map is None:
            self._load_sn_map()
        assert self._sn_map is not None
        try:
            return self._sn_map[(int(class_id), obis)]
        except KeyError:
            raise ServiceError(f"{obis} class {class_id} is not in the SN object list") from None

    def _sn_method_address(self, class_id: int, obis: ObisCode, method: int) -> int:
        from pydlms.sn_methods import method_address

        base = self._base_name(class_id, obis)
        version = self._sn_versions.get((int(class_id), obis))
        return method_address(base, class_id, method, version)

    def _sn_read_address(self, address: int, access: xdlms.SelectiveAccess | None = None):
        spec: Any = (
            sn.VariableName(address)
            if access is None
            else sn.ParameterizedAccess(address, access.selector, access.parameters)
        )
        response = sn.decode_sn_apdu(self.association.request(sn.ReadRequest([spec]).to_bytes()))
        return self.association.sn_read_value(response, f"READ 0x{address:04X}")

    def _sn_read(self, class_id, obis, attribute, access=None):
        if class_id == ClassId.ASSOCIATION_SN and obis == ObisCode(0, 0, 40, 0, 0, 255):
            base = 0xFA00
        else:
            base = self._base_name(class_id, obis)
        return self._sn_read_address(sn.attribute_address(base, attribute), access)

    def _sn_write(self, class_id, obis, attribute, value: DlmsData) -> None:
        """WriteRequest on the attribute's address; a value too long for the
        server's PDU goes in write-data-block-access blocks."""
        address = sn.attribute_address(self._base_name(class_id, obis), attribute)
        request = sn.WriteRequest([sn.VariableName(address)], [value])
        response = self.association.sn_request(request)
        if not isinstance(response, sn.WriteResponse) or len(response.results) != 1:
            raise ProtocolError(f"WRITE 0x{address:04X}: expected a one-item WriteResponse")
        result = response.results[0]
        if isinstance(result, sn.WriteBlockNumber):
            # sn_request turns the acknowledged last block into SUCCESS, so
            # a block number here answers a request sent in one piece.
            raise ProtocolError(
                f"WRITE 0x{address:04X} answered with block-number {result.block_number}, "
                "but the value was not sent in blocks"
            )
        if result != DataAccessResult.SUCCESS:
            raise ServiceError(f"WRITE 0x{address:04X} failed: {result_name(result)}", result)


def _raise_early_reply(what: str, number: int | None, response) -> None:
    """Raise for a reply that is not the expected acknowledgement or final
    response: :class:`ServiceError` when it carries an error result (the
    server ended the transfer), else :class:`ProtocolError`."""
    where = f"{what} block {number}" if number is not None else what
    results = getattr(response, "results", None)
    if results is None:
        result = getattr(response, "result", None)
        results = [] if result is None else [result]
    for result in results:
        code = result[0] if isinstance(result, tuple) else result
        if int(code) != 0:
            raise ServiceError(f"{where} refused: {result_name(code)}", code)
    raise ProtocolError(f"{where}: unexpected reply {type(response).__name__}")


def _selected_columns(
    columns: list[tuple[int, ObisCode, int, int]], access: xdlms.SelectiveAccess | None
) -> list[tuple[int, ObisCode, int, int]]:
    """The capture objects a Profile generic ``buffer`` read returns.

    Blue Book, Profile generic (IC 7) ``buffer`` selective access: an
    entry_descriptor returns the columns ``from_selected_value`` to
    ``to_selected_value`` (1-based, 0 = the last one); a range_descriptor
    with a non-empty ``selected_values`` returns those capture objects in
    that order, an empty one all columns.
    """
    if access is None or access.parameters.tag != DataType.STRUCTURE:
        return columns
    params = access.parameters.value
    if access.selector == 2 and len(params) == 4:
        first, last = params[2].value, params[3].value
        if not isinstance(first, int) or not isinstance(last, int) or first < 1:
            raise ValueError(f"entry descriptor columns {first}..{last} are invalid")
        return columns[first - 1 : last or None]
    if access.selector == 1 and len(params) == 4 and params[3].value:
        return [_capture_object(item) for item in params[3].value]
    return columns


def _octets(data: DlmsData | None, what: str) -> bytes:
    if data is None or data.tag != DataType.OCTET_STRING:
        raise DecodeError(f"the meter returned no octet string for the {what}")
    return bytes(data.value)


def _fields(item: DlmsData, minimum: int, what: str) -> list[DlmsData]:
    """The elements of a meter structure, checked for shape before use."""
    if item.tag != DataType.STRUCTURE or len(item.value) < minimum:
        found = f"{len(item.value)} elements" if item.tag == DataType.STRUCTURE else item.tag.name
        raise DecodeError(f"{what} is not a structure of {minimum} elements ({found})")
    return item.value


def _int_field(item: DlmsData, what: str) -> int:
    if not isinstance(item.value, int) or isinstance(item.value, bool):
        raise DecodeError(f"{what} is {item.tag.name}, not an integer")
    return item.value


def _obis_field(item: DlmsData, what: str) -> ObisCode:
    if item.tag != DataType.OCTET_STRING or len(item.value) != 6:
        raise DecodeError(f"{what} is not a 6-octet logical name")
    return ObisCode.from_bytes(bytes(item.value))


def _capture_object(item: DlmsData) -> tuple[int, ObisCode, int, int]:
    """``{class_id, logical_name, attribute_index, data_index}``."""
    v = _fields(item, 4, "capture object definition")
    what = "capture object"
    return (
        _int_field(v[0], f"{what} class_id"),
        _obis_field(v[1], f"{what} logical_name"),
        _int_field(v[2], f"{what} attribute_index"),
        _int_field(v[3], f"{what} data_index"),
    )


def _octets(data: DlmsData, what: str) -> bytes:
    if data.tag != DataType.OCTET_STRING:
        raise DecodeError(f"{what} is {data.tag.name}, not an octet-string")
    return bytes(data.value)


def _array(data: DlmsData, what: str) -> list[DlmsData]:
    if data.tag != DataType.ARRAY:
        raise DecodeError(f"{what} is {data.tag.name}, not an array")
    return data.value


def _ln_entry(item: DlmsData) -> ObjectListEntry:
    values = _fields(item, 3, "object_list entry")
    return ObjectListEntry(
        class_id=_int_field(values[0], "object_list class_id"),
        version=_int_field(values[1], "object_list version"),
        logical_name=_obis_field(values[2], "object_list logical_name"),
        access_rights=values[3] if len(values) > 3 else None,
    )


_ASSOCIATION_LN = ObisCode(0, 0, 40, 0, 0, 255)


def _with_rights(entries: list[ObjectListEntry]) -> list[ObjectListEntry]:
    """Decode every entry's access rights with the Association LN class
    version of the view's own entry, or inferred per entry without one."""
    version = next(
        (
            e.version
            for e in entries
            if e.class_id == ClassId.ASSOCIATION_LN and e.logical_name == _ASSOCIATION_LN
        ),
        None,
    )
    out = []
    for entry in entries:
        if entry.access_rights is not None:
            try:
                entry = replace(entry, rights=decode_access_rights(entry.access_rights, version))
            except DecodeError as exc:
                log.warning("object_list %s: access_rights not decoded: %s", entry, exc)
        out.append(entry)
    return out


def _sn_entry(item: DlmsData) -> ObjectListEntry:
    values = _fields(item, 4, "SN object_list entry")
    return ObjectListEntry(
        _int_field(values[1], "object_list class_id"),
        _int_field(values[2], "object_list version"),
        _obis_field(values[3], "object_list logical_name"),
        _int_field(values[0], "object_list base_name") & 0xFFFF,
    )
