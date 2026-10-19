"""Integration-test fixtures (run with ``pytest -m integration``).

They need external tools (socat, docker, a Gurux simulator) and are
deselected by default. When a tool is missing the test is skipped with the
reason; a failure of a present tool is a failure, never a skip.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time

import pytest


@pytest.fixture
def pty_pair():
    """Two connected pseudo-terminals from socat: ``(meter_side, client_side)``."""
    if shutil.which("socat") is None:
        pytest.skip("socat not installed")
    proc = subprocess.Popen(  # noqa: S603 - fixed argv, test-only helper
        ["socat", "-d", "-d", "pty,raw,echo=0", "pty,raw,echo=0"],
        stderr=subprocess.PIPE,
        text=True,
    )
    paths: list[str] = []
    deadline = time.monotonic() + 5
    while len(paths) < 2 and time.monotonic() < deadline:
        line = proc.stderr.readline()
        match = re.search(r"PTY is (\S+)", line)
        if match:
            paths.append(match.group(1))
    if len(paths) < 2:
        proc.kill()
        pytest.fail("socat did not report two PTYs")
    for path in paths:
        while not os.path.exists(path):
            time.sleep(0.01)
    yield paths[0], paths[1]
    proc.terminate()
    proc.wait(5)
