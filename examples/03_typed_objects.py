#!/usr/bin/env python3
"""Work with typed COSEM objects: attributes by name, nested structures, methods."""

from _meter import connect

with connect() as meter:
    clock = meter.object("0.0.1.0.0.255")  # class taken from the association view
    print(f"clock.time:        {clock.time}")
    print(f"clock.time_zone:   {clock.time_zone} min\n")

    profile = meter.object("1.0.99.1.0.255")
    print(f"capture period:    {profile.capture_period} s")
    print("capture objects:")
    for column in profile.capture_objects:  # list[CaptureObject]
        print(
            f"  class {column.class_id:3} {column.logical_name} attribute {column.attribute_index}"
        )

    disconnect = meter.object("0.0.96.3.10.255")
    print(f"\ndisconnect control output_state: {disconnect.output_state}")
