"""Run a server image and sweep it with pydlms (phase 3 of interop-plan.md)."""

from __future__ import annotations

import contextlib
import subprocess
import time

import pytest

from tests.docker_ready import listening
from tests.interop.model import data_json


def _docker(*args: str, timeout: int = 120) -> str:
    return subprocess.run(  # noqa: S603,S607 - fixed docker argv, test-only
        ["docker", *args], check=True, capture_output=True, text=True, timeout=timeout
    ).stdout.strip()


@contextlib.contextmanager
def running(image: str, *args: str, port: int = 4059, ready: str | None = None, env=None):
    """Start ``image`` (``args`` as its command) and yield ``("127.0.0.1", host_port)``.

    Ready when ``ready`` appears in the container log (if given) and the port
    accepts a TCP connection.
    """
    argv = ["run", "-d", "--rm", "-p", f"127.0.0.1::{port}"]
    for key, value in (env or {}).items():
        argv += ["-e", f"{key}={value}"]
    cid = _docker(*argv, image, *args)
    try:
        host_port = int(_docker("port", cid, str(port)).splitlines()[0].rsplit(":", 1)[1])
        deadline = time.monotonic() + 120
        while True:
            logs = subprocess.run(  # noqa: S603,S607
                ["docker", "logs", cid], capture_output=True, text=True, timeout=30
            )
            if ready is None or ready in logs.stdout + logs.stderr:
                # Docker's proxy accepts before the server listens; wait for
                # a connection that stays open (tests/docker_ready.py).
                if listening(host_port):
                    break
            if time.monotonic() > deadline:
                pytest.fail(f"{image} did not come up:\n{(logs.stdout + logs.stderr)[-2000:]}")
            time.sleep(0.5)
        yield "127.0.0.1", host_port
    finally:
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True, timeout=60)  # noqa: S603,S607


def sweep(client, max_attributes: int = 32) -> dict:
    """Read the object list, then every attribute of every object.

    Returns ``{"objects": n, "read": n, "errors": {"obis/class/attr": "msg"},
    "values": {"obis/class/attr": data tree}}``. Attribute counts come from
    pydlms's class registry; unknown classes are probed up to the first
    failure past attribute 2.
    """
    from pydlms.cosem.interface_classes import lookup
    from pydlms.exceptions import DlmsError

    report: dict = {"objects": 0, "read": 0, "errors": {}, "values": {}}
    try:
        entries = client.get_association_view()
    except DlmsError as exc:
        # A server whose object list does not decode still gets a report.
        report["errors"]["object_list"] = f"{type(exc).__name__}: {exc}"
        return report
    report["objects"] = len(entries)
    for entry in entries:
        ic = lookup(entry.class_id, entry.version)
        count = len(ic.attributes) if ic else max_attributes
        for attribute in range(1, count + 1):
            key = f"{entry.logical_name}/{entry.class_id}/{attribute}"
            try:
                value = client.get(entry.logical_name, entry.class_id, attribute)
            except DlmsError as exc:
                report["errors"][key] = f"{type(exc).__name__}: {exc}"
                if ic is None and attribute > 2:
                    break
                continue
            report["read"] += 1
            report["values"][key] = data_json(value) if hasattr(value, "tag") else repr(value)
    return report
