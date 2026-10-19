"""Austrian customer interface (Kundenschnittstelle) profiles.

Austrian DSOs push a DataNotification every few seconds over an M-Bus
(Netz NÖ, Salzburg, EWR/Kaifa) or HDLC (L+G E450 CII) port, enciphered with
a per-meter key (security suite 0, usually encryption only, SC 0x20/0x21).

The Netz NÖ P1 push is a flat payload: a leading date-time without OBIS, then
``obis, value, scaler_unit`` triples, and a trailing meter number without
OBIS. Source: the Netz NÖ capture in esphome-libs/dlms_parser
(``mbus_netz_noe_p1``), where the trailing octet string is the meter number
printed on the device; seen on one meter model only.

The L+G E450 customer interface (CII) push is the IDIS CII form (EN/IEC
62056-7-5 HDLC to client 103): a DataNotification without header date-time
whose body is one structure of a leading date-time without OBIS followed by
flat ``obis, value`` pairs (no scaler/unit). The leading value is the meter
clock ``0.0.1.0.0.255``. Sources: Netz Burgenland E450 interface spec
2023-04-26 (states the customer interface implements IDIS CII) and two captures in
esphome-libs/dlms_parser
(``hdlc_landis_gyr_e450``, ``hdlc_lgz_e450_2``) that have exactly this shape.
The self-descriptive E450 pushes from Cyprus (``hdlc_landis_gyr_e450_cyprus*``)
carry their own OBIS codes and do not need this profile.

The Wiener Netze customer interface (optical port, IEC 62056-21 head) pushes
the attribute-2 list of its push setup ``0-X:25.9.0.255`` without OBIS
codes. Source: Wiener Netze, "Smart Meter Kundenschnittstelle" (the DSO's
web page, read 2026-10-16): Landis+Gyr and Iskraemeco send the clock
(octet-string 12) and +A, -A, +R, -R, +P, -P, +Q, -Q (``1.8.0`` .. ``4.8.0``,
``1.7.0`` .. ``4.7.0``, unsigned32), 9 values; Siemens sends the serial
number ``0.0.96.1.1.255`` (octet-string 16) first, 10 values. The page gives
no scaler or unit. Scaler 0 with Wh (+A, -A), varh (+R, -R), W (+P, -P) and
var (+Q, -Q) is what two independent MIT-licensed decoders tested on Wiener
Netze meters apply (bernikr/esphome-wienernetze-smartmeter@0c8f3d6
``wienernetze.cpp``, tested on Siemens IM151/IM350/IM351, L+G E450 and
Iskraemeco AM550; tofuSCHNITZEL/wiener_netze_smartmeter@0c2ea2e
``meter_data.py``): both print the raw value / 1000 as kWh or kvarh and the
power values unscaled. No capture; the layout is chosen by length and other
lengths stay unlabelled.
"""

from __future__ import annotations

from pydlms.cosem.enums import Unit
from pydlms.profiles import LabelProfile, LengthProfile, register_profile

NETZ_NOE_P1 = register_profile(
    LabelProfile(
        name="netz-noe-p1",
        leading=["0.0.1.0.0.255"],
        trailing=["0.0.96.1.0.255"],
        description="Netz NÖ P1 (M-Bus, Kaifa/Sagemcom): leading clock, trailing meter number",
    )
)

LG_E450_CII = register_profile(
    LabelProfile(
        name="lg-e450-cii",
        leading=["0.0.1.0.0.255"],
        description="L+G E450 customer interface (IDIS CII push): leading clock without OBIS",
    )
)

# Scaler 0 and the units of the two community decoders (module docstring);
# Wiener Netze itself publishes neither.
_WN_REGISTERS = [
    ("1.0.1.8.0.255", 0, Unit.WATT_HOUR),  # +A
    ("1.0.2.8.0.255", 0, Unit.WATT_HOUR),  # -A
    ("1.0.3.8.0.255", 0, Unit.VAR_HOUR),  # +R
    ("1.0.4.8.0.255", 0, Unit.VAR_HOUR),  # -R
    ("1.0.1.7.0.255", 0, Unit.WATT),  # +P
    ("1.0.2.7.0.255", 0, Unit.WATT),  # -P
    ("1.0.3.7.0.255", 0, Unit.VAR),  # +Q
    ("1.0.4.7.0.255", 0, Unit.VAR),  # -Q
]
_WN_LIST = [("0.0.1.0.0.255", 0, None), *_WN_REGISTERS]

WIENER_NETZE = register_profile(
    LengthProfile(
        name="wiener-netze",
        layouts={
            len(_WN_LIST): _WN_LIST,  # Landis+Gyr, Iskraemeco
            len(_WN_LIST) + 1: [("0.0.96.1.1.255", 0, None), *_WN_LIST],  # Siemens
        },
        description="Wiener Netze customer interface (compact, by length; Wh/varh/W/var)",
    )
)
