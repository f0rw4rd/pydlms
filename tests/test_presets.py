"""Association presets: the DSMR 4.2.2 P3 head-end associations.

Source: Netbeheer Nederland, "Dutch Smart Meter Requirements v4.2.2 Final
P3" companion standard, 2014-03-14 (public PDF): 2.1 clients 16, 1 and 102;
3.2.2 access security; 3.2.3.1 ciphered context, suite 0, security policy
3, HLS mechanism_id(5); 5.1 Association LN 0-0:40.0.0.255 and Security
setup 0-0:43.0.0.255. OSGP (Apache-2.0) agrees on 16/1/102 and HLS 5.
"""

from __future__ import annotations

import pytest

from pydlms.profiles.presets import PRESETS, AssociationPreset, get_preset
from pydlms.security.hls import Mechanism
from pydlms.security.suites import SecurityPolicy


def test_dsmr_p3_management_client():
    preset = get_preset("dsmr-p3-management")
    assert preset.client_sap == 1 and preset.server_logical == 1
    assert preset.mechanism is Mechanism.HLS_GMAC
    assert preset.ciphered and preset.security_suite == 0
    assert preset.security_policy is SecurityPolicy.AUTHENTICATED_ENCRYPTED
    assert preset.association_obis == "0.0.40.0.0.255"
    assert preset.security_setup_obis == "0.0.43.0.0.255"
    assert preset.client_kwargs() == {
        "client_sap": 1,
        "server_logical": 1,
        "mechanism": Mechanism.HLS_GMAC,
    }


def test_dsmr_p3_public_client_is_unciphered_lowest_level():
    preset = get_preset("dsmr-p3-public")
    assert (preset.client_sap, preset.mechanism, preset.ciphered) == (16, Mechanism.NONE, False)
    assert preset.security_policy is None and preset.security_setup_obis is None


def test_dsmr_p3_pre_established_client_cannot_be_opened():
    preset = get_preset("dsmr-p3-pre-established")
    assert preset.client_sap == 102 and preset.pre_established
    with pytest.raises(ValueError, match="pre-established"):
        preset.client_kwargs()


def test_mechanism_override_must_not_contradict_the_preset():
    preset = get_preset("dsmr-p3-management")
    assert preset.client_kwargs(Mechanism.HLS_GMAC)["mechanism"] is Mechanism.HLS_GMAC
    with pytest.raises(ValueError, match="mechanism"):
        preset.client_kwargs(Mechanism.LLS)


def test_unnamed_hls_needs_an_hls_mechanism_from_the_caller():
    preset = AssociationPreset(
        name="example",
        client_sap=48,
        mechanism=None,
        ciphered=True,
        association_obis="0.0.40.0.3.255",
    )
    with pytest.raises(ValueError, match="mechanism"):
        preset.client_kwargs()
    with pytest.raises(ValueError, match="HLS"):
        preset.client_kwargs(Mechanism.LLS)
    assert preset.client_kwargs(5)["mechanism"] is Mechanism.HLS_GMAC


def test_default_mechanism_fills_in_and_yields_to_the_caller():
    preset = AssociationPreset(
        name="example",
        client_sap=48,
        mechanism=None,
        ciphered=True,
        association_obis="0.0.40.0.3.255",
        default_mechanism=Mechanism.HLS,
    )
    assert preset.client_kwargs()["mechanism"] is Mechanism.HLS
    assert preset.client_kwargs(Mechanism.HLS_GMAC)["mechanism"] is Mechanism.HLS_GMAC
    with pytest.raises(ValueError, match="HLS"):
        preset.client_kwargs(Mechanism.LLS)


def test_default_mechanism_must_be_hls_and_only_without_a_named_one():
    with pytest.raises(ValueError, match="default_mechanism"):
        AssociationPreset("x", 48, None, True, "0.0.40.0.3.255", default_mechanism=Mechanism.LLS)
    with pytest.raises(ValueError, match="default_mechanism"):
        AssociationPreset(
            "x", 1, Mechanism.HLS_GMAC, True, "0.0.40.0.0.255", default_mechanism=Mechanism.HLS
        )


def test_unknown_preset_lists_the_known_ones():
    with pytest.raises(KeyError, match="dsmr-p3-management"):
        get_preset("nope")
    assert all(PRESETS[name].name == name for name in PRESETS)


def test_preset_kwargs_build_a_client():
    from pydlms.client import DlmsClient

    kwargs = get_preset("dsmr-p3-public").client_kwargs()
    client = DlmsClient.tcp("192.0.2.1", auto_associate=False, **kwargs)
    assert client.link.client_sap == 16
    assert client.association.settings.mechanism is Mechanism.NONE
