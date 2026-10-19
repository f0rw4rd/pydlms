"""Delta-value resolution for COSEM ``Data`` (tags 28..33). PROVISIONAL.

The delta types ``delta-integer`` [28], ``delta-long`` [29],
``delta-double-long`` [30], ``delta-unsigned`` [31], ``delta-long-unsigned``
[32] and ``delta-double-long-unsigned`` [33] carry a difference to an earlier
value instead of the value itself. :mod:`pydlms.cosem.data` decodes them as
they are; :func:`resolve_deltas` turns them into absolute values, on request
only.

**Provisional.** The Green Book clause defining how deltas accumulate was not
read, and no reference implementation resolves them (Gurux and the Rust
``dlms_cosem`` crate decode the tags only), so the rule below is pydlms's
reading, not a verified one. The function is pure and opt-in; the received
values are never altered. pydlms does not propose the delta-value
conformance bit (bit 6) in its InitiateRequest.

The reading:

* Deltas exist only inside an ``array`` or ``compact-array``. Each delta
  element is the previous element's absolute value plus the delta, and the
  result takes the previous element's type (the *base* type): a
  ``delta-unsigned 5`` after ``double-long-unsigned 1000`` becomes
  ``double-long-unsigned 1005``. Resolved deltas chain: the next delta adds
  to 1005.
* An absolute integer element (``integer`` .. ``long64-unsigned``) is the
  new base. Any other element (``null-data``, strings, ``enum``,
  ``boolean``, floats, composites) leaves no base: a delta after it raises.
* In an array of structures every member position is its own column with
  its own base; structures nested in structures likewise, by member path.
  A nested array resolves on its own and never inherits the enclosing
  column's base.
* The unsigned deltas add a non-negative amount (``delta-unsigned 0xFF`` is
  +255, never -1); only the signed deltas can decrease a value.
* A delta with no base (first in its column, after a non-integer, or outside
  any array) and a sum outside the base type's range raise
  :class:`~pydlms.exceptions.DecodeError`; no value is clamped or wrapped.

A consequence worth knowing: a compact-array's type description fixes every
element's type, so a delta column there never holds an absolute value to
start from and resolving it always raises. That suggests the real rule may
treat the first delta of a compact-array column differently; until the clause
is read, pydlms refuses rather than guesses.

Partial public support: the DLMS UA white paper "Efficiency" (V1,
2018-11-01, dlms.com) describes delta-array compression as "used with
transferring data arrays", choosing "the shortest possible data type
depending on the change in the value": "a long-64-unsigned value that
requires 9 bytes ... may be replaced by a delta-unsigned value ... if the
change of the value is small". That matches the array-only scope, the
delta-to-the-previous-value reading and the base type taken from the
earlier value; the column and nesting rules above stay pydlms's reading.
"""

from __future__ import annotations

from pydlms.cosem.data import CompactArray, DlmsData
from pydlms.cosem.enums import DataType
from pydlms.exceptions import DecodeError

__all__ = ["DELTA_TYPES", "resolve_deltas"]

#: The delta tags, mapped to whether the delta is signed.
DELTA_TYPES: dict[DataType, bool] = {
    DataType.DELTA_INTEGER: True,
    DataType.DELTA_LONG: True,
    DataType.DELTA_DOUBLE_LONG: True,
    DataType.DELTA_UNSIGNED: False,
    DataType.DELTA_LONG_UNSIGNED: False,
    DataType.DELTA_DOUBLE_LONG_UNSIGNED: False,
}

#: Absolute integer types that can be a base, with their value range.
_RANGES: dict[DataType, tuple[int, int]] = {
    DataType.INTEGER: (-(1 << 7), (1 << 7) - 1),
    DataType.LONG: (-(1 << 15), (1 << 15) - 1),
    DataType.DOUBLE_LONG: (-(1 << 31), (1 << 31) - 1),
    DataType.LONG64: (-(1 << 63), (1 << 63) - 1),
    DataType.UNSIGNED: (0, (1 << 8) - 1),
    DataType.LONG_UNSIGNED: (0, (1 << 16) - 1),
    DataType.DOUBLE_LONG_UNSIGNED: (0, (1 << 32) - 1),
    DataType.LONG64_UNSIGNED: (0, (1 << 64) - 1),
}

_Key = tuple[int, ...]
#: Per array: member path -> ``(base type, absolute value)``, or None for
#: "the previous element at this path was no integer".
_State = dict[_Key, "tuple[DataType, int] | None"]


def resolve_deltas(value: DlmsData) -> DlmsData:
    """Return a copy of ``value`` with every delta element made absolute.

    PROVISIONAL; see the module docstring for the rule and what raises
    :class:`DecodeError`. ``value`` itself is not modified, so the received
    (unresolved) data stays available to the caller.
    """
    return _resolve(value, None, ())


def _resolve(item: DlmsData, state: _State | None, key: _Key) -> DlmsData:
    tag = DataType(item.tag)
    if tag in DELTA_TYPES:
        return _apply_delta(item, tag, state, key)
    if tag == DataType.STRUCTURE:
        return DlmsData(tag, [_resolve(m, state, (*key, i)) for i, m in enumerate(item.value)])
    if state is not None:
        state[key] = (tag, item.value) if tag in _RANGES else None
    if tag == DataType.ARRAY:
        inner: _State = {}
        return DlmsData(tag, [_resolve(e, inner, ()) for e in item.value])
    if tag == DataType.COMPACT_ARRAY:
        compact = item.value
        inner = {}
        items = [_resolve(e, inner, ()) for e in compact.items]
        return DlmsData(tag, CompactArray(compact.description, items))
    if isinstance(item.value, list):  # bit-string
        return DlmsData(tag, list(item.value))
    return DlmsData(tag, item.value)


def _apply_delta(item: DlmsData, tag: DataType, state: _State | None, key: _Key) -> DlmsData:
    if state is None:
        raise DecodeError(f"{tag.name} {item.value} outside an array has nothing to add to")
    base = state.get(key)
    if base is None:
        raise DecodeError(
            f"{tag.name} {item.value} has no base: no absolute integer precedes it in its column"
        )
    base_tag, base_value = base
    delta = int(item.value)
    if not DELTA_TYPES[tag] and delta < 0:
        raise DecodeError(f"{tag.name} {delta} is negative")
    result = base_value + delta
    low, high = _RANGES[base_tag]
    if not low <= result <= high:
        raise DecodeError(
            f"{tag.name} {delta} on {base_tag.name} {base_value} overflows "
            f"{base_tag.name} ({low}..{high})"
        )
    state[key] = (base_tag, result)
    return DlmsData(base_tag, result)
