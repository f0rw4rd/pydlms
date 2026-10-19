#!/usr/bin/env python3
"""Read a load profile (Profile generic, IC 7) with typed timestamps and scaled values."""

import os

from _meter import connect

PROFILE = os.environ.get("DLMS_PROFILE", "1.0.99.1.0.255")

with connect() as meter:
    profile = meter.read_profile(
        PROFILE,
        typed=True,  # date-time cells become CosemDateTime
        scalers=True,  # register cells become RegisterValue (scaler_unit read once)
        fill_timestamps=True,  # rebuild null (compressed) timestamps
    )
    print("columns:", [str(obis) for _, obis, *_ in profile.columns])
    print(f"{len(profile.rows)} rows, last five:")
    for stamp, *values in profile.rows[-5:]:
        print(f"  {stamp.to_datetime()}  {', '.join(str(v) for v in values)}")
