"""COSEM objects bound to a client: typed attributes and callable methods.

::

    with DlmsClient.tcp(host) as meter:
        clock = meter.object("0.0.1.0.0.255")          # class looked up in the object list
        print(clock.time)                              # CosemDateTime
        clock.shift_time(-30)                          # method, typed parameter
        profile = meter.object("1.0.99.1.0.255")
        for column in profile.capture_objects:         # list[CaptureObject] dataclasses
            print(column.logical_name, column.attribute_index)
        script = meter.object("0.0.10.0.0.255")
        script.execute(1)

Attribute reads go through :meth:`CosemObject.get` (decoded with the type
from :mod:`pydlms.cosem.model`, ``DlmsData`` for unknown shapes); writes
through :meth:`CosemObject.set` (Python values are encoded with the same
type); methods through :meth:`CosemObject.call`. Attribute and method names
are also exposed as Python attributes; a name that is both (none in the Blue
Book) resolves to the attribute.
"""

from __future__ import annotations

from typing import Any

from pydlms.cosem.data import DlmsData
from pydlms.cosem.interface_classes import lookup
from pydlms.cosem.model import ClassSpec, spec_for
from pydlms.debug import get_logger
from pydlms.obis import ObisCode

__all__ = ["CosemObject"]

log = get_logger("client")


class CosemObject:
    """One COSEM object on a connected meter."""

    def __init__(
        self, client, class_id: int, logical_name: ObisCode | str, version: int = 0
    ) -> None:
        self._client = client
        self.class_id = int(class_id)
        self.logical_name = (
            ObisCode.parse(logical_name) if isinstance(logical_name, str) else logical_name
        )
        self.version = version
        self.spec: ClassSpec | None = spec_for(self.class_id)
        self._names = lookup(self.class_id, version)

    def __repr__(self) -> str:
        name = self.spec.name if self.spec else (self._names.name if self._names else "?")
        return f"<CosemObject {name} {self.logical_name} class={self.class_id} v{self.version}>"

    # -- attributes ------------------------------------------------------------------
    def _attribute(self, name_or_index: str | int):
        if self.spec is not None:
            return self.spec.attribute(name_or_index)
        from pydlms.cosem import types as T
        from pydlms.cosem.model import AttributeSpec

        if isinstance(name_or_index, str):
            if self._names is None:
                raise KeyError(f"class {self.class_id} attribute names are unknown")
            index = self._names.attribute_index(name_or_index)
        else:
            index = name_or_index
        return AttributeSpec(index, str(name_or_index), T.Any())

    def get(self, attribute: str | int, access=None, raw: bool = False) -> Any:
        """Read and decode an attribute (``raw=True`` returns the DlmsData)."""
        spec = self._attribute(attribute)
        data = self._client.get(self.logical_name, self.class_id, spec.index, access)
        if raw:
            return data
        return spec.type.decode(data, spec.name)

    def set(self, attribute: str | int, value: Any) -> None:
        """Encode ``value`` with the attribute's type and write it."""
        spec = self._attribute(attribute)
        data = value if isinstance(value, DlmsData) else spec.type.encode(value)
        self._client.set(self.logical_name, self.class_id, spec.index, data)

    # -- methods -------------------------------------------------------------------------
    def call(self, method: str | int, value: Any = None, raw: bool = False) -> Any:
        """Invoke a method. ``value`` is encoded with the method's parameter
        type; methods documented as ``data ::= integer(0)`` default to 0."""
        if self.spec is not None:
            spec = self.spec.method(method)
            index, params, returns = spec.index, spec.params, spec.returns
        else:
            if isinstance(method, str):
                if self._names is None:
                    raise KeyError(f"class {self.class_id} method names are unknown")
                index = self._names.method_index(method)
            else:
                index = method
            params = returns = None
        if isinstance(value, DlmsData):
            data = value
        elif params is None:
            data = None
        else:
            from pydlms.cosem import types as T

            if value is None and isinstance(params, T.Integer):
                value = 0
            data = params.encode(value)
        result = self._client.action(self.logical_name, self.class_id, index, data)
        if result is None or raw or returns is None:
            return result
        return returns.decode(result, f"{method} result")

    # -- name access ---------------------------------------------------------------------
    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        names = self._names
        if names is not None and name in names.attributes:
            return self.get(name)
        if names is not None and name in names.methods:
            return lambda value=None: self.call(name, value)
        raise AttributeError(f"{self!r} has no attribute or method {name!r}")

    def __setattr__(self, name: str, value: Any) -> None:
        if name.startswith("_") or name in ("class_id", "logical_name", "version", "spec"):
            object.__setattr__(self, name, value)
            return
        names = self.__dict__.get("_names")
        if names is not None and name in names.attributes:
            self.set(name, value)
            return
        object.__setattr__(self, name, value)

    def read_all(self, skip_unreadable: bool = True) -> dict[str, Any]:
        """Read every attribute; failed reads map to the exception.

        With ``skip_unreadable`` an attribute the association view marks as
        not readable is left out without a request. Attributes whose access
        is unknown (not listed, no decodable rights) are still read.
        """
        from pydlms.exceptions import DlmsError

        out: dict[str, Any] = {}
        names = self._names.attributes if self._names else ("logical_name",)
        check = skip_unreadable
        for name in names:
            if check:
                try:
                    index = self._attribute(name).index
                    readable = self._client.can_read(self.logical_name, self.class_id, index)
                except DlmsError as exc:  # no view: read everything
                    log.debug("read_all %s: access rights unavailable: %s", self, exc)
                    readable, check = None, False
                if readable is False:
                    log.debug("read_all %s: %s is not readable, skipped", self, name)
                    continue
            try:
                out[name] = self.get(name)
            except DlmsError as exc:
                out[name] = exc
        return out
