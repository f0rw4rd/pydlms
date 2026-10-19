"""Invocation-counter (frame counter) discovery and persistence.

A ciphered association only succeeds when the client's outbound invocation
counter (IC) is above the last value the meter accepted for that key. Three
complementary mechanisms, used by :class:`~pydlms.client.DlmsClient`:

1. **Discovery** (:func:`read_invocation_counters`): through a short public
   association, read every IC object the meter exposes - the standard
   ``0.0.43.1.e.255`` Data objects found in the public object list, plus the
   vendor locations registered in :data:`VENDOR_LOCATIONS` for the meter's
   manufacturer - and continue from the **highest** value. Taking the maximum
   is always safe: the IC only has to exceed what the meter last saw, so a
   counter belonging to another client SAP can only overshoot, never undershoot.
2. **Retry** (``AssociationSettings.invocation_counter_retry``): a meter that
   refuses the AARQ with ``ExceptionResponse invocation-counter-error`` reports
   the counter it expects; one retry continues from there. Opt-in, logged.
   The hint is not authenticated, so one at or above
   :data:`pydlms.association.IC_HINT_LIMIT` (``0xFFFFFFF0``) is refused
   instead of followed: it would exhaust the counter, and the store below
   would carry that into every later session with the key.
3. **Persistence** (:class:`CounterStore`): the last used IC per endpoint,
   client SAP and key fingerprint (never the key), so a restarted client never
   reuses an IV.

Vendor locations are data. Each entry must cite a checkable source (capture,
vendor or DSO documentation) and say whether it was seen on one meter only;
entries copied from GPL/BSL implementations are not accepted. Register more
with :func:`register_location` or the ``extra_locations`` argument.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path

from pydlms.cosem.data import DlmsData
from pydlms.cosem.enums import DataType
from pydlms.debug import get_logger
from pydlms.exceptions import DlmsError
from pydlms.obis import ObisCode

__all__ = [
    "CounterLocation",
    "VENDOR_LOCATIONS",
    "register_location",
    "read_invocation_counters",
    "CounterStore",
    "key_fingerprint",
    "is_counter_obis",
    "BLIND_CANDIDATES",
]

log = get_logger("client")


def is_counter_obis(obis: ObisCode) -> bool:
    """Whether ``obis`` is in the invocation-counter range ``0.0-64.43.1.0-127.255``.

    Confirmed by four sources.
    """
    a, b, c, d, e, f = obis.groups
    return a == 0 and b <= 64 and c == 43 and d == 1 and e <= 127 and f == 255


#: Tried blindly when the public object list cannot be read: E = 0..9 covers
#: the per-client counters seen in the field,
#: plus the Italian offline-management counter (B = 1).
BLIND_CANDIDATES = [ObisCode(0, 0, 43, 1, e, 255) for e in range(10)] + [
    ObisCode(0, 1, 43, 1, 1, 255)
]


@dataclass(frozen=True)
class CounterLocation:
    """Where a meter exposes an invocation counter."""

    obis: ObisCode
    class_id: int = 1
    attribute: int = 2
    source: str = ""
    #: "confirmed by N" / "single source".
    confidence: str = "single source"

    def __str__(self) -> str:
        return f"{self.class_id}/{self.obis}/{self.attribute}"


def _loc(obis: str, source: str, confidence: str = "single source") -> CounterLocation:
    return CounterLocation(ObisCode.parse(obis), 1, 2, source, confidence)


#: manufacturer FLAG id (3 letters, from the system title, the logical device
#: name or the optical identification) -> counter locations to try first.
#: Every entry cites its source. Kaifa (KFM), Sagemcom,
#: ZIV, Holley, Hexing, Inhemeter, Honeywell/Elster and Itron are absent on
#: purpose: no public source names their counter objects.
VENDOR_LOCATIONS: dict[str, list[CounterLocation]] = {
    "ISK": [
        _loc(
            "0.0.43.1.0.255",
            "Iskraemeco AM550: dlms-cosem docs; gurux.fi/node/6263",
            "confirmed by 2",
        )
    ],
    "LGZ": [
        _loc(f"0.0.43.1.{e}.255", "L+G E570 association view, tomter123/dlms_client@a643d67")
        for e in range(4)
    ],
    "EDM": [
        _loc(f"0.0.43.1.{e}.255", "EDMI Mk7Mi clients 103/104/105/80: VegaSCADA@4f94dc1")
        for e in (6, 7, 8, 9)
    ],
    "WSE": [
        _loc(
            "0.0.43.1.0.255",
            "Wasion ameter300 (not readable by the public client): gurux.fi/node/35220",
        )
    ],
    "MCS": [
        _loc(
            "0.0.43.1.0.255",
            "MetCom MCS301/MCS501 management client 1: gurux.fi/node/13858; "
            "Gurux.DLMS.DeviceProfiles@137f6ad (CC0) MetCom/*/HDLC/Management.gxc",
            "confirmed by 2",
        )
    ],
}


def register_location(manufacturer: str, location: CounterLocation) -> None:
    """Add a vendor-specific counter location (keep ``source`` filled in)."""
    VENDOR_LOCATIONS.setdefault(manufacturer.upper(), []).append(location)


def _as_counter(value: DlmsData) -> int | None:
    if value.tag in (
        DataType.DOUBLE_LONG_UNSIGNED,
        DataType.LONG64_UNSIGNED,
        DataType.LONG_UNSIGNED,
        DataType.DOUBLE_LONG,
    ) and isinstance(value.value, int):
        return value.value
    return None


def read_invocation_counters(
    client,
    manufacturer: str | None = None,
    extra_locations: list[CounterLocation] | None = None,
) -> dict[str, int]:
    """Read every reachable IC on an associated (public) client.

    Returns ``{location: value}``; empty when the meter exposes none.
    """
    locations: list[CounterLocation] = list(extra_locations or [])
    if manufacturer:
        locations += VENDOR_LOCATIONS.get(manufacturer.upper(), [])
    try:
        for entry in client.get_association_view():
            if is_counter_obis(entry.logical_name):
                locations.append(
                    CounterLocation(entry.logical_name, entry.class_id, 2, "object list")
                )
    except DlmsError as exc:
        log.debug("object list not readable (%s); trying the standard objects blindly", exc)
        locations += [CounterLocation(obis, source="blind") for obis in BLIND_CANDIDATES]
    found: dict[str, int] = {}
    seen = set()
    for location in locations:
        if location in seen:
            continue
        seen.add(location)
        try:
            value = _as_counter(client.get(location.obis, location.class_id, location.attribute))
        except DlmsError as exc:
            log.debug("no invocation counter at %s: %s", location, exc)
            continue
        if value is not None:
            found[str(location)] = value
            log.info("invocation counter at %s = %d", location, value)
    return found


def key_fingerprint(key: bytes | None) -> str:
    """Stable, non-reversible identifier of a key for the counter store."""
    if not key:
        return "none"
    return hashlib.sha256(b"pydlms-ic-store" + key).hexdigest()[:16]


class CounterStore:
    """JSON file remembering the last used outbound IC per association.

    The key is ``"<endpoint>|<client SAP>|<key fingerprint>"``. Writes are
    atomic (temp file + rename).
    """

    def __init__(self, path: str | os.PathLike) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    @staticmethod
    def make_key(endpoint: str, client_sap: int, encryption_key: bytes | None) -> str:
        return f"{endpoint}|{client_sap}|{key_fingerprint(encryption_key)}"

    def _load(self) -> dict[str, int]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            raise DlmsError(f"invocation-counter store {self.path} is unreadable: {exc}") from exc
        return {k: int(v) for k, v in data.items()}

    def get(self, key: str) -> int | None:
        with self._lock:
            return self._load().get(key)

    def put(self, key: str, next_counter: int) -> None:
        """Remember ``next_counter`` (never lowers a stored value)."""
        with self._lock:
            data = self._load()
            data[key] = max(next_counter, data.get(key, 0))
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
            os.replace(tmp, self.path)
