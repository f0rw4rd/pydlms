#!/usr/bin/env python3
"""Read the meter's identity, clock and a few registers (public client, no security)."""

from _meter import connect

from pydlms.catalog import obis_name

REGISTERS = ["1.0.1.8.0.255", "1.0.2.8.0.255", "1.0.1.7.0.255", "1.0.32.7.0.255"]

with connect() as meter:
    print(f"logical device name: {meter.get('0.0.42.0.0.255').value!r}")
    print(f"clock:               {meter.get_clock().to_datetime()}\n")

    for obis in REGISTERS:
        register = meter.get_register(obis)  # value with scaler and unit applied
        print(f"{obis:16} {str(register):>14}  {obis_name(obis) or ''}")
