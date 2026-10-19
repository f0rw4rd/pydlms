"""Association presets: the client addressing and security a companion
standard prescribes for each of its associations.

A :class:`AssociationPreset` is data: client SAP, server logical device,
authentication mechanism, whether the context is ciphered, and the OBIS
codes of the Association LN and Security setup objects. It opens nothing
itself; :meth:`AssociationPreset.client_kwargs` gives the keywords for
:meth:`~pydlms.client.DlmsClient.tcp` (and the other builders). Keys, the
:class:`~pydlms.security.context.SecurityContext` and passwords stay with
the caller::

    preset = get_preset("dsmr-p3-management")
    meter = DlmsClient.tcp(host, security=context, **preset.client_kwargs())

Built-in presets: DSMR 4.2.2 P3 (:mod:`pydlms.profiles.dsmr_p3`) and IS
15959 (:mod:`pydlms.profiles.india`).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pydlms.security.hls import Mechanism
from pydlms.security.suites import SecurityPolicy

__all__ = ["AssociationPreset", "PRESETS", "get_preset", "register_preset"]


@dataclass(frozen=True)
class AssociationPreset:
    """One association of a companion standard.

    ``mechanism`` is ``None`` when the standard asks for HLS without naming
    a mechanism id (IS 15959); the caller then passes one, or
    ``default_mechanism`` (an HLS mechanism seen in field implementations,
    cited in ``source``) is used. ``pre_established``
    associations are not opened by the client (push destinations, broadcast
    clients); they are listed for their addressing. ``ciphered`` is ``None``
    when the standard does not say.
    """

    name: str
    client_sap: int
    mechanism: Mechanism | None
    ciphered: bool | None
    association_obis: str
    server_logical: int = 1
    security_setup_obis: str | None = None
    security_policy: SecurityPolicy | None = None
    security_suite: int | None = None
    pre_established: bool = False
    description: str = ""
    source: str = ""
    default_mechanism: Mechanism | None = None

    def __post_init__(self) -> None:
        if self.default_mechanism is not None and (
            self.mechanism is not None or not self.default_mechanism.is_hls
        ):
            raise ValueError(
                f"{self.name}: default_mechanism is only for an HLS association "
                "whose standard names no mechanism id"
            )

    def client_kwargs(self, mechanism: Mechanism | int | None = None) -> dict[str, Any]:
        """``client_sap``, ``server_logical`` and ``mechanism`` for a client
        builder. ``mechanism`` fills in an HLS mechanism the standard leaves
        open (``default_mechanism`` when not given); it may not contradict
        one the standard names."""
        if self.pre_established:
            raise ValueError(f"{self.name} is a pre-established association; nothing to open")
        chosen = None if mechanism is None else Mechanism(mechanism)
        if self.mechanism is not None:
            if chosen is not None and chosen != self.mechanism:
                raise ValueError(
                    f"{self.name} uses mechanism {self.mechanism.name}, not {chosen.name}"
                )
            chosen = self.mechanism
        elif chosen is None and self.default_mechanism is not None:
            chosen = self.default_mechanism
        elif chosen is None:
            raise ValueError(f"{self.name} names HLS without a mechanism id; pass mechanism=")
        elif not chosen.is_hls:
            raise ValueError(f"{self.name} requires HLS, not {chosen.name}")
        return {
            "client_sap": self.client_sap,
            "server_logical": self.server_logical,
            "mechanism": chosen,
        }


PRESETS: dict[str, AssociationPreset] = {}


def register_preset(preset: AssociationPreset) -> AssociationPreset:
    PRESETS[preset.name] = preset
    return preset


def get_preset(name: str) -> AssociationPreset:
    try:
        return PRESETS[name]
    except KeyError:
        known = ", ".join(sorted(PRESETS))
        raise KeyError(f"unknown association preset {name!r}; known: {known}") from None


# Register the built-in presets.
from pydlms.profiles import dsmr_p3, india  # noqa: E402,F401
