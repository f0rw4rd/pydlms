"""The crypto suite needs ``cryptography``; without it the suite is SKIPPED
(reported as skipped, never silently passed). CI always installs it."""

import pytest

pytest.importorskip("cryptography", reason="crypto extra not installed")


class CryptoKeys:
    """A provider and how to turn a raw test key into its key reference."""

    def __init__(self, kind: str) -> None:
        from pydlms.security.provider import SoftwareProvider
        from tests.crypto.handle_provider import HandleProvider

        self.kind = kind
        self.provider = SoftwareProvider() if kind == "software" else HandleProvider()

    def ref(self, key):
        """``key`` itself for software, a fresh integer handle otherwise."""
        return key if self.kind == "software" else self.provider.add(key)


@pytest.fixture(params=["software", "handle"])
def crypto(request) -> CryptoKeys:
    """The provider matrix the known-answer and tamper suites run over."""
    return CryptoKeys(request.param)
