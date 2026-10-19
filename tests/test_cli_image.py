"""``pydlms image-transfer`` against the simulator's image transfer object."""

from __future__ import annotations

import json

import pytest

from pydlms.cli import main
from pydlms.simulator import ImageTransferTarget, example_meter, serve

IMAGE = bytes(range(256)) * 3


@pytest.fixture
def meter():
    sim = example_meter()
    servers = []

    def start(target: ImageTransferTarget) -> str:
        target.install(sim)
        server = serve(sim)
        servers.append(server)
        host, port = server.server_address
        return f"tcp://{host}:{port}"

    sim.start = start
    yield sim
    for server in servers:
        server.shutdown()
        server.server_close()


@pytest.fixture
def firmware(tmp_path):
    path = tmp_path / "fw.bin"
    path.write_bytes(IMAGE)
    return str(path)


def test_refuses_without_yes(meter, firmware, capsys):
    target = ImageTransferTarget()
    endpoint = meter.start(target)
    assert main(["image-transfer", endpoint, firmware, "--identifier", "4657"]) == 1
    assert "--yes" in capsys.readouterr().err
    assert target.identifier is None
    assert meter.requests == []  # never connected


def test_transfers_verifies_and_activates(meter, firmware, capsys):
    target = ImageTransferTarget(drop_blocks=[2], verify_steps=1, activate_steps=1)
    endpoint = meter.start(target)
    code = main(
        [
            "--json",
            "image-transfer",
            endpoint,
            firmware,
            "--identifier",
            "4657322E30",
            "--activate",
            "--poll",
            "0",
            "--yes",
        ]
    )
    out = capsys.readouterr()
    assert code == 0
    assert target.image() == IMAGE and target.identifier == b"FW2.0" and target.activated
    row = json.loads(out.out)[0]
    assert row["blocks"] == 12 and row["rounds"] == 2 and row["activation_confirmed"] is True
    assert row["status"] == "ACTIVATION_SUCCESSFUL"
    assert "12/12" in out.err  # progress on stderr


def test_association_drop_on_activate_is_not_an_error(meter, firmware, capsys):
    target = ImageTransferTarget(drop_on_activate=True)
    endpoint = meter.start(target)
    code = main(["image-transfer", endpoint, firmware, "--identifier", "01", "--activate", "--yes"])
    out = capsys.readouterr()
    assert code == 0 and target.activated
    assert "unconfirmed" in out.out + out.err


def test_failure_exits_2(meter, firmware, capsys):
    target = ImageTransferTarget(enabled=False)
    endpoint = meter.start(target)
    assert main(["image-transfer", endpoint, firmware, "--identifier", "01", "--yes"]) == 2
    assert "not enabled" in capsys.readouterr().err


def test_bad_identifier_is_rejected(meter, firmware):
    endpoint = meter.start(ImageTransferTarget())
    with pytest.raises(SystemExit):
        main(["image-transfer", endpoint, firmware, "--identifier", "zz", "--yes"])
