"""Human-readable names for common OBIS codes.

The table in ``pydlms/data/obis_names.csv`` is hand-authored: each name
paraphrases the meaning given by the OBIS value groups (IEC 62056-6-1: A
medium, C quantity, D processing, E tariff) as used in the public DSMR 5.0.2
P1 and Austrian customer-interface descriptions. It is a convenience for
display only; nothing in the protocol depends on it.
"""

from __future__ import annotations

import csv
import functools
from importlib import resources

from pydlms.obis import ObisCode

__all__ = ["obis_name"]


@functools.lru_cache(maxsize=1)
def _table() -> dict[ObisCode, str]:
    text = resources.files("pydlms").joinpath("data/obis_names.csv").read_text(encoding="utf-8")
    return {ObisCode.parse(row["obis"]): row["name"] for row in csv.DictReader(text.splitlines())}


def obis_name(obis: ObisCode | str | None) -> str | None:
    """Name of ``obis`` if it is in the catalogue (wildcard-free lookup)."""
    if obis is None:
        return None
    key = ObisCode.parse(obis) if isinstance(obis, str) else obis
    return _table().get(key)
