#!/usr/bin/env python3
"""List the objects of the association view with their access rights."""

from _meter import connect

from pydlms.catalog import obis_name

with connect() as meter:
    view = meter.get_association_view()
    print(f"{len(view)} objects\n")
    for entry in view:
        readable = meter.can_read(entry.logical_name, entry.class_id, 2)
        print(f"{entry!s:40} attr 2 readable={readable!s:5}  {obis_name(entry.logical_name) or ''}")
