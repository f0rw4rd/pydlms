"""Run an oracle image (PROTOCOL.md) as one long-lived process."""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest


class Oracle:
    def __init__(self, image: str, *args: str) -> None:
        self.image = image
        self.proc = subprocess.Popen(  # noqa: S603,S607 - fixed argv, test-only
            ["docker", "run", "--rm", "-i", "--network", "none", image, *args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        self.hello = self.ask("hello")

    def ask(self, line: str) -> dict:
        assert self.proc.stdin and self.proc.stdout
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()
        reply = self.proc.stdout.readline()
        if not reply:
            raise RuntimeError(f"{self.image} closed its output after {line[:60]!r}")
        return json.loads(reply)

    def supports(self, op: str) -> bool:
        return op in self.hello.get("ops", [])

    def close(self) -> None:
        if self.proc.stdin:
            self.proc.stdin.close()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def require_image(image: str, build_dir: str | None = None) -> None:
    """Skip unless docker and the image exist (build hint in the skip message)."""
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    found = subprocess.run(  # noqa: S603,S607
        ["docker", "image", "inspect", image], capture_output=True, check=False
    )
    if found.returncode:
        build_dir = build_dir or f"tests/interop/{image.removeprefix('pydlms-interop-')}"
        pytest.skip(f"image {image} missing: docker build -t {image} {build_dir}")
