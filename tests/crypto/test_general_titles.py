"""general-ciphering must be addressed to us and come from the expected peer.

The recipient and originator system titles travel in the general-ciphering
header (IEC 62056-5-3 general-ciphering APDU). With an identified key and
AAD ``SC || AK`` the recipient is not authenticated and the originator only
through the IV, so an APDU meant for another party, or produced by another
party holding the same global key, used to be accepted.
"""

from __future__ import annotations

import pytest

from pydlms.exceptions import AuthenticationError
from pydlms.security.ciphering import unwrap
from pydlms.security.context import SecurityContext
from pydlms.security.general import KeyInfo, wrap_general_ciphering
from tests.crypto.vectors import GB_PLAINTEXT

EK, AK = bytes(range(16)), bytes(range(16, 32))
CLIENT, SERVER, OTHER = b"CLIENT01", b"SERVER01", b"OTHER001"


def sender(title: bytes = SERVER) -> SecurityContext:
    return SecurityContext(EK, AK, client_system_title=title)


def receiver(**kw) -> SecurityContext:
    return SecurityContext(EK, AK, client_system_title=CLIENT, **kw)


def test_addressed_to_us_from_the_meter_is_accepted():
    apdu = wrap_general_ciphering(sender(), GB_PLAINTEXT, CLIENT, KeyInfo("identified"))
    assert unwrap(receiver(server_system_title=SERVER), apdu).plaintext == GB_PLAINTEXT


def test_addressed_to_someone_else_is_refused():
    apdu = wrap_general_ciphering(sender(), GB_PLAINTEXT, OTHER, KeyInfo("identified"))
    rx = receiver(server_system_title=SERVER)
    with pytest.raises(AuthenticationError, match="recipient"):
        unwrap(rx, apdu)
    assert rx.last_inbound_counter(SERVER) is None


def test_from_another_originator_is_refused():
    apdu = wrap_general_ciphering(sender(OTHER), GB_PLAINTEXT, CLIENT, KeyInfo("identified"))
    with pytest.raises(AuthenticationError, match="originator"):
        unwrap(receiver(server_system_title=SERVER), apdu)


def test_unknown_peer_or_own_title_is_not_checked():
    """A push decoder knows neither title; nothing to compare against."""
    apdu = wrap_general_ciphering(sender(OTHER), GB_PLAINTEXT, OTHER, KeyInfo("identified"))
    assert unwrap(SecurityContext(EK, AK), apdu).plaintext == GB_PLAINTEXT


def test_analysis_path_shows_it_anyway():
    apdu = wrap_general_ciphering(sender(OTHER), GB_PLAINTEXT, OTHER, KeyInfo("identified"))
    rx = receiver(server_system_title=SERVER)
    assert unwrap(rx, apdu, strict=False).plaintext == GB_PLAINTEXT
