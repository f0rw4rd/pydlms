"""Simulator method handlers that answer an ACTION with a non-success result.

Handlers raise :class:`pydlms.simulator.ActionFailure`; the meter answers
with that Action-Result (LN) or the data-access-result of the same code
(SN READ on the method address). Image transfer (IC 18) and the security
setup methods need this to model a meter that refuses or defers a method.
"""

from __future__ import annotations

import pytest

from pydlms.client import DlmsClient
from pydlms.cosem.enums import ActionResult, DataAccessResult
from pydlms.cosem.interface_classes import ClassId
from pydlms.exceptions import ServiceError
from pydlms.simulator import ActionFailure, example_meter, serve


@pytest.fixture
def meter():
    sim = example_meter()
    server = serve(sim)
    sim.address = server.server_address
    yield sim
    server.shutdown()
    server.server_close()


def _refuse(result):
    def handler(meter, params):
        raise ActionFailure(result)

    return handler


@pytest.mark.parametrize(
    "result", [ActionResult.TEMPORARY_FAILURE, ActionResult.READ_WRITE_DENIED]
)
def test_ln_action_returns_the_handler_result(meter, result):
    meter.add_method(ClassId.DISCONNECT_CONTROL, "0.0.96.3.10.255", 2, _refuse(result))
    with DlmsClient.tcp(*meter.address, timeout=3) as client:
        with pytest.raises(ServiceError) as err:
            client.action("0.0.96.3.10.255", ClassId.DISCONNECT_CONTROL, 2)
    assert err.value.result == result


def test_sn_action_maps_the_result_to_the_same_code(meter):
    meter.add_method(
        ClassId.DISCONNECT_CONTROL,
        "0.0.96.3.10.255",
        2,
        _refuse(ActionResult.TEMPORARY_FAILURE),
    )
    with DlmsClient.tcp(*meter.address, timeout=3, logical_names=False) as client:
        with pytest.raises(ServiceError) as err:
            client.action("0.0.96.3.10.255", ClassId.DISCONNECT_CONTROL, 2)
    assert err.value.result == DataAccessResult.TEMPORARY_FAILURE


def test_action_result_without_a_data_access_twin_is_other_reason(meter):
    meter.add_method(
        ClassId.DISCONNECT_CONTROL,
        "0.0.96.3.10.255",
        2,
        _refuse(ActionResult.LONG_ACTION_ABORTED),
    )
    with DlmsClient.tcp(*meter.address, timeout=3, logical_names=False) as client:
        with pytest.raises(ServiceError) as err:
            client.action("0.0.96.3.10.255", ClassId.DISCONNECT_CONTROL, 2)
    assert err.value.result == DataAccessResult.OTHER_REASON


def test_action_failure_rejects_success():
    with pytest.raises(ValueError):
        ActionFailure(ActionResult.SUCCESS)
