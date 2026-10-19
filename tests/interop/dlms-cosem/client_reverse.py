"""dlms-cosem's blocking TCP client against a DLMS server (phase 4 of interop-plan.md).

python client_reverse.py HOST PORT [none | gmac EK AK [METER_IC]]

Associates (no security as client 16, or HLS-GMAC with general-glo-ciphering
as client 1), reads a register, the clock and a load profile (range selective
access, then the whole buffer by block transfer), releases, and prints one
JSON object per step on stdout:
``{"step": ..., "ok": bool, "raw": hex, "value": data tree, "error": ...}``.
Values are decoded with dlms-cosem's own parser and mapped by adapter.tree.
"""

from __future__ import annotations

import datetime as dt
import json
import sys
import traceback

sys.path.insert(0, "/opt/oracle")

from adapter import parse_one, tree  # noqa: E402
from dlms_cosem import cosem, enumerations  # noqa: E402
from dlms_cosem.clients.dlms_client import DlmsClient  # noqa: E402
from dlms_cosem.cosem import selective_access  # noqa: E402

CI = enumerations.CosemInterface


def emit(step: str, **kw) -> None:
    sys.stdout.write(json.dumps({"step": step, **kw}) + "\n")
    sys.stdout.flush()


def attempt(step: str, fn):
    try:
        out = fn()
    except Exception as exc:  # noqa: BLE001 - every failure is a result here
        traceback.print_exc(file=sys.stderr)
        emit(step, ok=False, error=f"{type(exc).__name__}: {exc}")
        return None
    return out


def read(client, step: str, interface, obis: str, attribute: int, access=None) -> None:
    def go():
        raw = client.get(
            cosem.CosemAttribute(
                interface=interface, instance=cosem.Obis.from_string(obis), attribute=attribute
            ),
            access_descriptor=access,
        )
        try:
            value = tree(parse_one(raw)[0])
        except Exception as exc:  # noqa: BLE001
            value = f"unmapped: {type(exc).__name__}: {exc}"
        emit(step, ok=True, raw=raw.hex(), value=value)

    attempt(step, go)


def main() -> int:
    host, port, mode = sys.argv[1], int(sys.argv[2]), (sys.argv[3] if len(sys.argv) > 3 else "none")
    kw: dict = {"client_logical_address": 16, "server_logical_address": 1, "timeout": 10}
    if mode == "gmac":
        kw.update(
            client_logical_address=1,
            authentication_method=enumerations.AuthenticationMechanism.HLS_GMAC,
            encryption_key=bytes.fromhex(sys.argv[4]),
            authentication_key=bytes.fromhex(sys.argv[5]),
            client_system_title=b"DLMSCOSM",
        )
        if len(sys.argv) > 6:
            # dlms-cosem requires every server IC to exceed this "last seen" value,
            # so with the default 0 it refuses a server whose first IC is 0.
            kw["meter_initial_invocation_counter"] = int(sys.argv[6])
    client = DlmsClient.with_tcp_transport(host=host, port=port, **kw)
    if attempt("connect", lambda: client.connect() or True) is None:
        return 1

    def associate():
        aare = client.associate()
        emit(
            "associate",
            ok=True,
            result=int(aare.result),
            diagnostic=int(aare.result_source_diagnostics),
            mechanism=None if aare.authentication is None else int(aare.authentication),
            server_system_title=(aare.system_title or b"").hex(),
        )
        return aare

    if attempt("associate", associate) is None:
        attempt("disconnect", client.disconnect)
        return 1
    read(client, "register-value", CI.REGISTER, "1.0.1.8.0.255", 2)
    read(client, "register-scaler-unit", CI.REGISTER, "1.0.1.8.0.255", 3)
    read(client, "clock", CI.CLOCK, "0.0.1.0.0.255", 2)
    utc = dt.timezone.utc
    rng = selective_access.RangeDescriptor(
        restricting_object=selective_access.CaptureObject(
            cosem_attribute=cosem.CosemAttribute(
                interface=CI.CLOCK,
                instance=cosem.Obis.from_string("0.0.1.0.0.255"),
                attribute=2,
            ),
            data_index=0,
        ),
        from_value=dt.datetime(2024, 5, 1, 0, 0, tzinfo=utc),
        to_value=dt.datetime(2024, 5, 1, 1, 0, tzinfo=utc),
    )
    read(client, "profile-range", CI.PROFILE_GENERIC, "1.0.99.1.0.255", 2, rng)
    # The whole buffer (96 rows) needs GET-with-datablock.
    read(client, "profile-all", CI.PROFILE_GENERIC, "1.0.99.1.0.255", 2)

    def release():
        rlre = client.release_association()
        emit("release", ok=True, reason=None if rlre.reason is None else int(rlre.reason))

    attempt("release", release)
    attempt("disconnect", client.disconnect)
    return 0


if __name__ == "__main__":
    sys.exit(main())
