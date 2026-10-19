"""Norwegian HAN (NVE) push lists.

Kaifa MA105H2E / MA304 meters push their lists without OBIS codes (compact
form). Source for every position, OBIS code, unit and scaler below: Kaifa,
"Norwegian HAN spesification - OBIS Codes", list version identifier
``KFM_001``, list version date 09.11.2018 (published by NEK,
``nek.no/wp-content/uploads/2018/11/Kaifa-KFM_001.pdf``), pages 2 and 3:

* list 1 (every 2 s): active power+ alone;
* list 2 (every 10 s): list version identifier, meter id, meter type, P+,
  P-, Q+, Q-, IL1, IL2, IL3, ULN1, ULN2, ULN3;
* list 3 (hourly): list 2, then the clock and the cumulative A+, A-, R+, R-
  energies;
* MA105H2E (1x230 V): IL2, IL3, ULN2 and ULN3 are "NA" (page 3), so its
  lists are 9 and 14 values. The document marks them NA without saying they
  are omitted; the 9/14 counts are also what the amshan decoder
  (toreamun/amshan ``han/kaifa.py``) uses.

Scalers: power W/var (0), current mA (-3), voltage dV (-1), energy Wh/varh
(0). The layout is chosen by the number of values; other counts stay
unlabelled.

Verification status: the 13-value 3-phase list 2 matches the one capture
available (``hdlc_kaifa_ma304h3e`` in esphome-libs/dlms_parser: "KFM_001",
meter id, "MA304H3E", U ~ 238.5 V). Lists 1 and 3 and the single-phase
lists are from the document only; no capture. Aidon and Kamstrup lists carry
OBIS codes and need no profile.
"""

from __future__ import annotations

from pydlms.cosem.enums import Unit
from pydlms.profiles import LengthProfile, register_profile

_HEAD = [
    ("1.1.0.2.129.255", 0, None),  # OBIS list version identifier
    ("0.0.96.1.0.255", 0, None),  # meter id (GIAI GS1)
    ("0.0.96.1.7.255", 0, None),  # meter type
    ("1.0.1.7.0.255", 0, Unit.WATT),
    ("1.0.2.7.0.255", 0, Unit.WATT),
    ("1.0.3.7.0.255", 0, Unit.VAR),
    ("1.0.4.7.0.255", 0, Unit.VAR),
]
_I1 = ("1.0.31.7.0.255", -3, Unit.AMPERE)
_I2_I3 = [("1.0.51.7.0.255", -3, Unit.AMPERE), ("1.0.71.7.0.255", -3, Unit.AMPERE)]
_U1 = ("1.0.32.7.0.255", -1, Unit.VOLT)
_U2_U3 = [("1.0.52.7.0.255", -1, Unit.VOLT), ("1.0.72.7.0.255", -1, Unit.VOLT)]
_HOURLY = [
    ("0.0.1.0.0.255", 0, None),  # clock, local time of Norway
    ("1.0.1.8.0.255", 0, Unit.WATT_HOUR),
    ("1.0.2.8.0.255", 0, Unit.WATT_HOUR),
    ("1.0.3.8.0.255", 0, Unit.VAR_HOUR),
    ("1.0.4.8.0.255", 0, Unit.VAR_HOUR),
]

KAIFA_LIST_1 = [("1.0.1.7.0.255", 0, Unit.WATT)]
#: 3-phase list 2 (MA304*); the only layout with a capture.
KAIFA_LIST = [*_HEAD, _I1, *_I2_I3, _U1, *_U2_U3]
KAIFA_LIST_1PH = [*_HEAD, _I1, _U1]

KAIFA_HAN = register_profile(
    LengthProfile(
        name="kaifa-han-no",
        layouts={
            1: KAIFA_LIST_1,
            len(KAIFA_LIST_1PH): KAIFA_LIST_1PH,  # 9: MA105H2E list 2
            len(KAIFA_LIST_1PH) + len(_HOURLY): KAIFA_LIST_1PH + _HOURLY,  # 14: MA105H2E list 3
            len(KAIFA_LIST): KAIFA_LIST,  # 13: MA304 list 2
            len(KAIFA_LIST) + len(_HOURLY): KAIFA_LIST + _HOURLY,  # 18: MA304 list 3
        },
        description="Kaifa KFM_001 Norwegian HAN lists 1/2/3, 1- and 3-phase (compact, no OBIS)",
    )
)
