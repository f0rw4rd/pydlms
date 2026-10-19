"""DSMR P3: the Dutch head-end (central system) DLMS interface.

Not the P1 consumer port (:mod:`pydlms.profiles.dsmr`). Source for every
value: Netbeheer Nederland, "Dutch Smart Meter Requirements v4.2.2 Final
P3" companion standard, 2014-03-14 (public PDF on netbeheernederland.nl):

* 2.1: the management logical device has three associations, public client
  16 (test only, lowest level security), management client 1 (the central
  system) and pre-established client 102 (broadcast; no objects in 4.2.2);
* 3.2.2: the public client may only use no security; the management client
  uses HLS (3, 4 or 5 allowed, never LLS or HLS 2);
* 3.2.3.1: management data exchange is ciphered (application context 3,
  LN with ciphering), security suite 0, message encryption and
  authentication (security policy 3), global keys only; HLS uses
  mechanism_id(5);
* 5.1: Association LN ``0-0:40.0.0.255``, Security setup
  ``0-0:43.0.0.255``.

Server logical device 1 is the management logical device the standard names
(IEC 62056-6-2 reserves SAP 1 for it). OSGP (Apache-2.0) agrees on clients
16, 1, 102 and HLS 5 (second source). No public P3 document for DSMR 5.x was
found; these presets are pinned to 4.2.2.
"""

from __future__ import annotations

from pydlms.profiles.presets import AssociationPreset, register_preset
from pydlms.security.hls import Mechanism
from pydlms.security.suites import SecurityPolicy

_SOURCE = "DSMR 4.2.2 P3 companion standard (2014-03-14)"
_CURRENT_ASSOCIATION = "0.0.40.0.0.255"

DSMR_P3_PUBLIC = register_preset(
    AssociationPreset(
        name="dsmr-p3-public",
        client_sap=16,
        mechanism=Mechanism.NONE,
        ciphered=False,
        association_obis=_CURRENT_ASSOCIATION,
        description="DSMR P3 public client (test only, no metering data)",
        source=f"{_SOURCE} 2.1.1, 3.2.2",
    )
)

DSMR_P3_MANAGEMENT = register_preset(
    AssociationPreset(
        name="dsmr-p3-management",
        client_sap=1,
        mechanism=Mechanism.HLS_GMAC,
        ciphered=True,
        association_obis=_CURRENT_ASSOCIATION,
        security_setup_obis="0.0.43.0.0.255",
        security_policy=SecurityPolicy.AUTHENTICATED_ENCRYPTED,
        security_suite=0,
        description="DSMR P3 management client (central system): HLS 5, suite 0, policy 3",
        source=f"{_SOURCE} 2.1.3, 3.2.2, 3.2.3.1, 5.1",
    )
)

DSMR_P3_PRE_ESTABLISHED = register_preset(
    AssociationPreset(
        name="dsmr-p3-pre-established",
        client_sap=102,
        mechanism=None,
        ciphered=None,  # not stated in 4.2.2
        association_obis=_CURRENT_ASSOCIATION,
        pre_established=True,
        description="DSMR P3 pre-established client (broadcast; no objects in 4.2.2)",
        source=f"{_SOURCE} 2.1.2",
    )
)
