#!/usr/bin/env python3
"""Read several attributes in one request, then write the clock.

The write changes the meter: run it only against the simulator or a meter you
own. With DLMS_HOST set it asks before writing.
"""

import datetime as dt

from _meter import HOST, connect

from pydlms.cosem.enums import DataAccessResult

with connect() as meter:
    # GET-Request-With-List: one round trip; a failed item is a result, not an exception
    values = meter.get_many(
        [("1.0.1.8.0.255", 3, 2), ("1.0.2.8.0.255", 3, 2), ("9.9.9.9.9.9", 3, 2)]
    )
    for value in values:
        if isinstance(value, DataAccessResult):
            print(f"failed: {value.name}")
        else:
            print(f"value:  {value.value}")

    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    if HOST and input(f"\nset the meter clock to {now}? [y/N] ").lower() != "y":
        raise SystemExit
    meter.set_clock(now)
    print(f"\nclock now: {meter.get_clock().to_datetime()}")
