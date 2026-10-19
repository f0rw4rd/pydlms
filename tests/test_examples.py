"""Every script in ``examples/`` runs against the built-in simulator."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = sorted((ROOT / "examples").glob("[0-9][0-9]_*.py"))

#: Optional dependency each example needs beyond construct.
NEEDS = {
    "04_secured_hls_gmac.py": "cryptography",
    "06_decode_push.py": "cryptography",
    "09_serial_hdlc.py": "serial",
}


@pytest.mark.skipif(not EXAMPLES, reason="examples/ not present")
@pytest.mark.parametrize("script", EXAMPLES, ids=lambda p: p.name)
def test_example_runs(script: Path) -> None:
    module = NEEDS.get(script.name)
    if module and importlib.util.find_spec(module) is None:
        pytest.skip(f"needs {module}")
    env = {k: v for k, v in os.environ.items() if not k.startswith("DLMS_")}
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(ROOT), env.get("PYTHONPATH")]))
    result = subprocess.run(  # noqa: S603 - fixed interpreter and repo-local script
        [sys.executable, str(script)],
        cwd=script.parent,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip()
