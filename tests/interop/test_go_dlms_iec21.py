"""IEC 62056-21 against cB-Sigma/dlms's meter (``iec6205621/meter``, Go,
Apache-2.0) over a real tty.

The go-dlms image's ``iec21`` mode (``tests/interop/go-dlms/adapter/iec21.go``)
serves the library's meter on TCP as a transparent converter would, with 7E1
emulated in bit 7; ``socat`` bridges a PTY to it, so ``OpticalTransport`` runs
its termios settings, 300 -> 9600 baud switch, wake-ups and B1 on a tty.
The meter logs its records (option selects, commands, NULs before each
request, acknowledged fast wake-ups) as ``iec21 state`` lines.

Image: ``docker build -t pydlms-interop-go-dlms tests/interop/go-dlms``;
``PYDLMS_GO_DLMS_IMAGE`` selects another tag.
"""

from __future__ import annotations

import contextlib
import logging
import os
import shutil
import subprocess
import time

import pytest

from pydlms.exceptions import DlmsTimeoutError
from tests.interop.oracle import require_image

pytestmark = pytest.mark.integration
pytest.importorskip("serial")

IMAGE = os.environ.get("PYDLMS_GO_DLMS_IMAGE", "pydlms-interop-go-dlms")


def _docker(*args: str) -> str:
    return subprocess.run(  # noqa: S603,S607 - fixed argv, test-only
        ["docker", *args], capture_output=True, text=True, check=True, timeout=60
    ).stdout.strip()


def _logs(cid: str) -> str:
    out = subprocess.run(  # noqa: S603,S607
        ["docker", "logs", cid], capture_output=True, text=True, timeout=30
    )
    return out.stdout + out.stderr


@contextlib.contextmanager
def meter_tty(tmp_path, wake: str):
    """Run the meter with ``-wake wake``; yield ``(tty_path, state)`` where
    ``state()`` returns the meter's last ``iec21 state`` line."""
    require_image(IMAGE, "tests/interop/go-dlms")
    if shutil.which("socat") is None:
        pytest.skip("socat not installed")
    cid = _docker("run", "-d", "--rm", "-p", "127.0.0.1::4059", IMAGE, "iec21", "-wake", wake)
    socat = None
    try:
        deadline = time.monotonic() + 60
        while "godlms iec21 listening" not in (logs := _logs(cid)):
            if "unknown command" in logs:
                pytest.skip(f"{IMAGE} has no iec21 mode: rebuild tests/interop/go-dlms")
            if time.monotonic() > deadline:
                pytest.fail(f"iec21 meter did not come up:\n{logs[-2000:]}")
            time.sleep(0.2)
        port = _docker("port", cid, "4059").splitlines()[0].rsplit(":", 1)[1]
        tty = str(tmp_path / "tty")
        socat = subprocess.Popen(  # noqa: S603,S607 - fixed argv, test-only
            ["socat", f"pty,raw,echo=0,link={tty}", f"tcp:127.0.0.1:{port}"]
        )
        while not os.path.exists(tty):
            time.sleep(0.01)

        def state() -> str:
            time.sleep(0.2)  # the meter logs changes every 50 ms
            lines = [line for line in _logs(cid).splitlines() if "iec21 state" in line]
            return lines[-1] if lines else ""

        yield tty, state
    finally:
        if socat is not None:
            socat.terminate()
            socat.wait(5)
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True, timeout=60)  # noqa: S603,S607


def _optical(tty, **kw):
    from pydlms.transports.serial import OpticalTransport

    return OpticalTransport(tty, timeout=3, **kw)


@pytest.mark.parametrize("wake", ["none", "normal", "fast"])
def test_mode_c_readout_after_wake_up(tmp_path, wake):
    with meter_tty(tmp_path, wake) as (tty, state):
        transport = _optical(tty, wake_up=wake)
        try:
            readout = transport.read_mode_c()
        finally:
            transport.close()
        assert readout.identification.manufacturer == "GOD"
        assert readout.get("1.8.0").value == "001234.5" and readout.get("1.8.0").unit == "kWh"
        meter = state()
    assert 'options=["0 5 0"]' in meter
    if wake == "normal":
        assert "wakeNULs=[66]" in meter  # 2.2 s of NULs at 300 baud
    if wake == "fast":
        assert "fastWakes=1" in meter
        assert 'commands=["B1 "]' in meter  # sign-off after the readout, ACKed


def test_sleeping_meter_does_not_hear_the_request_without_wake_up(tmp_path):
    with meter_tty(tmp_path, "normal") as (tty, state):
        transport = _optical(tty)
        with pytest.raises(DlmsTimeoutError):
            transport.read_mode_c()
        transport.close()
        assert "sessions=0" in state()


@pytest.mark.parametrize("wake", ["none", "fast"])
def test_mode_e_hdlc_after_wake_up(tmp_path, wake, caplog):
    """Mode E at the spec's 300 baud 7E1 on a PTY (which refuses the
    in-place switch to 8N1, so the port is reopened), then HDLC."""
    from pydlms.client import DlmsClient

    with meter_tty(tmp_path, wake) as (tty, state):
        with caplog.at_level(logging.WARNING, logger="pydlms.transport"):
            with DlmsClient.optical(tty, timeout=3, wake_up=wake) as meter:
                assert meter.get_register("1.0.1.8.0.255").value == 12345678
        assert 'options=["2 5 2"]' in state()
    if wake == "fast":
        # cB-Sigma's meter hands the line to its HDLC server for good and
        # never reads the B1 that close() sends; close() logs and goes on.
        assert "sign-off B1 on close failed" in caplog.text


@pytest.mark.xfail(
    strict=True,
    raises=DlmsTimeoutError,
    reason="cB-Sigma's idle meter has no inter-character timeout and joins B0 "
    "and the request into one line, so it drops the request; Gurux sends "
    "'SOH B0 ETX CR LF' (no BCC), which ends that line",
)
def test_break_before_sign_on(tmp_path):
    with meter_tty(tmp_path, "none") as (tty, _):
        transport = _optical(tty, break_before_sign_on=True)
        try:
            assert len(transport.read_mode_c().data_sets) == 2
        finally:
            transport.close()


def test_break_crlf_before_sign_on(tmp_path):
    # The opt-in Gurux form ends the line, so cB-Sigma's line reader drops
    # B0 and answers the request (the BCC form above stays an xfail).
    with meter_tty(tmp_path, "none") as (tty, _):
        transport = _optical(tty, break_before_sign_on=True, break_form="crlf")
        try:
            assert len(transport.read_mode_c().data_sets) == 2
        finally:
            transport.close()
