"""Companion profiles: data that relabels push payloads, not protocol code.

A :class:`Profile` post-processes the :class:`~pydlms.push.PushRecord` list
of a decoded push:

* :class:`CompactProfile` assigns OBIS codes (and scaler/unit) by position to
  payloads that carry none ("compact" pushes such as Wiener Netze or the
  Kaifa HAN lists).
* :class:`LengthProfile` picks one of several positional layouts by the
  number of values (the Kaifa list 1/2/3 and 1-phase/3-phase lists).
* :class:`LabelProfile` names the unlabelled leading/trailing values of a
  flat payload (e.g. the trailing meter number of the Austrian Netz NÖ P1
  push).

:data:`PROFILES` lists the built-in ones by name; :func:`get_profile` looks
one up (the CLI's ``--profile`` option uses it).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pydlms.cosem.enums import Unit
from pydlms.debug import get_logger
from pydlms.obis import ObisCode
from pydlms.push import PushRecord

__all__ = [
    "Profile",
    "CompactProfile",
    "LengthProfile",
    "LabelProfile",
    "PROFILES",
    "get_profile",
    "register_profile",
]

log = get_logger("profiles")


class Profile:
    """Base class; subclasses define ``name`` and ``description``."""

    def apply(self, records: list[PushRecord]) -> list[PushRecord]:
        return records


@dataclass
class CompactProfile(Profile):
    """Map positional values to ``(obis, scaler, unit)`` entries.

    ``fields`` entries may be ``None`` to skip a position. Extra values beyond
    the template are kept unlabelled; a payload with fewer values than the
    template keeps what is there (meters send shorter lists at times).
    """

    name: str
    fields: list[tuple[str, int, Unit | None] | None]
    description: str = ""
    only_unlabelled: bool = True

    def apply(self, records: list[PushRecord]) -> list[PushRecord]:
        if self.only_unlabelled and any(r.obis is not None for r in records):
            return records
        out = []
        for index, record in enumerate(records):
            spec = self.fields[index] if index < len(self.fields) else None
            if spec is not None:
                obis, scaler, unit = spec
                record = PushRecord(ObisCode.parse(obis), record.data, scaler, unit)
            out.append(record)
        return out


@dataclass
class LengthProfile(Profile):
    """Positional layouts selected by the number of values.

    ``layouts`` maps a value count to a :class:`CompactProfile` field list.
    A payload whose count has no layout is left unlabelled (and logged):
    guessing a layout for an unknown list would mislabel values.
    """

    name: str
    layouts: dict[int, list[tuple[str, int, Unit | None] | None]]
    description: str = ""

    def apply(self, records: list[PushRecord]) -> list[PushRecord]:
        fields = self.layouts.get(len(records))
        if fields is None:
            if not any(r.obis is not None for r in records):
                log.info(
                    "profile %s has no layout for %d values; left unlabelled",
                    self.name,
                    len(records),
                )
            return records
        return CompactProfile(self.name, fields).apply(records)


@dataclass
class LabelProfile(Profile):
    """Name unlabelled values: ``leading``/``trailing`` OBIS strings in order."""

    name: str
    leading: list[str] = field(default_factory=list)
    trailing: list[str] = field(default_factory=list)
    description: str = ""

    def apply(self, records: list[PushRecord]) -> list[PushRecord]:
        out = list(records)
        for i, obis in enumerate(self.leading):
            if i < len(out) and out[i].obis is None:
                out[i] = PushRecord(ObisCode.parse(obis), out[i].data, out[i].scaler, out[i].unit)
        for i, obis in enumerate(self.trailing):
            j = len(out) - len(self.trailing) + i
            if 0 <= j < len(out) and out[j].obis is None:
                out[j] = PushRecord(ObisCode.parse(obis), out[j].data, out[j].scaler, out[j].unit)
        return out


PROFILES: dict[str, Profile] = {}


def register_profile(profile: Profile) -> Profile:
    PROFILES[profile.name] = profile
    return profile


def get_profile(name: str) -> Profile:
    try:
        return PROFILES[name]
    except KeyError:
        known = ", ".join(sorted(PROFILES))
        raise KeyError(f"unknown profile {name!r}; known: {known}") from None


# Register the built-in profiles.
from pydlms.profiles import austria, norway  # noqa: E402,F401
