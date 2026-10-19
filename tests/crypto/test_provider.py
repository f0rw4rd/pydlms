"""Pluggable crypto provider (pydlms.security.provider).

* The default SoftwareProvider and a HandleProvider (keys behind integer
  handles) give identical bytes on every envelope and key-info kind; the
  known-answer and tamper suites run over both via the ``crypto`` fixture.
* In handle mode no raw key bytes sit on the SecurityContext or reach the
  logs, and handles do not show in reprs.
* The guard refuses a provider that returns a short tag, a flag instead of
  plaintext, a wrong-length result, and lets provider exceptions through.
"""

from __future__ import annotations

import logging

import pytest

from pydlms.debug import TRACE, enable_debug
from pydlms.exceptions import (
    AuthenticationError,
    CryptoProviderError,
    KeyMissingError,
    SecurityError,
)
from pydlms.security import ec, gcm, hls
from pydlms.security.ciphering import unwrap, wrap
from pydlms.security.context import SecurityContext
from pydlms.security.general import (
    ONE_PASS_DH,
    STATIC_UNIFIED_MODEL,
    KeyInfo,
    unwrap_general_ciphering,
    verify_general_signing,
    wrap_general_ciphering,
    wrap_general_signing,
)
from pydlms.security.provider import (
    AadKey,
    CryptoProvider,
    GuardedProvider,
    SoftwareProvider,
    flatten_aad,
    resolve,
)
from pydlms.security.suites import SecurityControl, SecuritySuite
from tests.crypto.handle_provider import HandleProvider
from tests.crypto.vectors import (
    GB_AK,
    GB_CIPHERTEXT,
    GB_EK,
    GB_IC,
    GB_PLAINTEXT,
    GB_SYSTEM_TITLE,
    GB_TAG_AUTH_ENC,
)

S1 = SecuritySuite.ECDH_ECDSA_AES_GCM_128_SHA256
S2 = SecuritySuite.ECDH_ECDSA_AES_GCM_256_SHA384
CLIENT, SERVER = b"CLIENT01", b"SERVER01"
AUTH_ENC = SecurityControl.from_byte(0x30)


# -- protocol and defaults ---------------------------------------------------------


def test_providers_satisfy_the_protocol():
    assert isinstance(SoftwareProvider(), CryptoProvider)
    assert isinstance(HandleProvider(), CryptoProvider)
    assert not isinstance(object(), CryptoProvider)


def test_context_defaults_to_software_and_refuses_a_non_provider():
    assert type(SecurityContext(GB_EK, GB_AK).provider) is SoftwareProvider
    with pytest.raises(CryptoProviderError, match="not a crypto provider"):
        SecurityContext(GB_EK, GB_AK, provider=object())


def test_software_provider_refuses_a_handle():
    with pytest.raises(CryptoProviderError, match="raw key bytes"):
        gcm.encrypt(AUTH_ENC, 0x1000, GB_AK, GB_SYSTEM_TITLE, GB_IC, GB_PLAINTEXT)


def test_aad_key_hides_its_reference():
    assert "1234" not in repr(AadKey(1234))
    assert flatten_aad((b"\x30", AadKey(b"KEY!"), b"x"), bytes) == b"\x30KEY!x"
    with pytest.raises(CryptoProviderError):
        flatten_aad(("text",), bytes)


# -- parity: handle mode gives the same bytes ------------------------------------------


def _general_pair(provider_factory, suite=S1):
    """Client/server contexts for general-ciphering; keys through ``provider_factory``.

    Returns the two contexts and the HandleProvider of the client (or None).
    """
    n = 32 if suite == S2 else 16
    ek, ak, kek = bytes(range(n)), bytes(range(16, 32)), bytes(range(40, 40 + n))
    bk = bytes(reversed(range(n)))
    keys = {r: (ec.generate_private_key(suite), ec.generate_private_key(suite)) for r in "cs"}
    contexts = []
    for own, peer, title in (("c", "s", CLIENT), ("s", "c", SERVER)):
        provider = provider_factory()
        ref = provider.add if isinstance(provider, HandleProvider) else (lambda k: k)
        contexts.append(
            SecurityContext(
                ref(ek),
                ref(ak),
                client_system_title=title,
                suite=suite,
                master_key=ref(kek),
                broadcast_key=ref(bk),
                signing_key=ref(keys[own][0]),
                key_agreement_key=ref(keys[own][1]),
                peer_signing_key=keys[peer][0].public_key(),
                peer_key_agreement_key=keys[peer][1].public_key(),
                provider=provider,
            )
        )
    return contexts


INFOS = [
    KeyInfo("none"),
    KeyInfo("identified", 0),
    KeyInfo("identified", 1),
    KeyInfo("wrapped"),
    KeyInfo("agreed", scheme=ONE_PASS_DH),
    KeyInfo("agreed", scheme=STATIC_UNIFIED_MODEL),
]


@pytest.mark.parametrize("suite", [S1, S2], ids=["suite1", "suite2"])
@pytest.mark.parametrize("info", INFOS, ids=lambda i: f"{i.kind}-{i.key_id}-{i.scheme}")
@pytest.mark.parametrize(
    "sender,receiver",
    [("handle", "software"), ("software", "handle"), ("handle", "handle")],
)
def test_general_ciphering_interoperates_across_providers(suite, info, sender, receiver):
    factories = {"handle": HandleProvider, "software": SoftwareProvider}
    client, server = _general_pair(factories[sender], suite)
    if receiver != sender:
        server = _rehome(server, factories[receiver]())
    apdu = wrap_general_ciphering(client, GB_PLAINTEXT, SERVER, key_info=info)
    assert unwrap_general_ciphering(server, apdu).plaintext == GB_PLAINTEXT


def _rehome(ctx, provider):
    """The same keys as ``ctx`` under another provider (raw values from its store)."""
    old = ctx.provider

    def raw(key):
        if isinstance(old, HandleProvider) and isinstance(key, int):
            key = old._key(key)
        return provider.add(key) if isinstance(provider, HandleProvider) else key

    return SecurityContext(
        raw(ctx.encryption_key),
        raw(ctx.authentication_key),
        client_system_title=ctx.client_system_title,
        suite=ctx.suite,
        master_key=raw(ctx.master_key),
        broadcast_key=raw(ctx.broadcast_key),
        signing_key=raw(ctx.signing_key),
        key_agreement_key=raw(ctx.key_agreement_key),
        peer_signing_key=ctx.peer_signing_key,
        peer_key_agreement_key=ctx.peer_key_agreement_key,
        provider=provider,
    )


def test_static_unified_prefers_ecdh_kdf_and_falls_back_to_ecdh():
    client, server = _general_pair(HandleProvider)
    info = KeyInfo("agreed", scheme=STATIC_UNIFIED_MODEL)
    apdu = wrap_general_ciphering(client, GB_PLAINTEXT, SERVER, key_info=info)
    assert "ecdh_kdf" in client.provider.ops() and "ecdh" not in client.provider.ops()
    # A provider without ecdh_kdf: Z comes out through ecdh, the KDF runs here.
    server = _rehome(server, HandleProvider(with_ecdh_kdf=False))
    assert unwrap_general_ciphering(server, apdu).plaintext == GB_PLAINTEXT
    assert "ecdh" in server.provider.ops() and "ecdh_kdf" not in server.provider.ops()
    # The agreed key under ecdh_kdf stayed a handle: the gcm_open ran on an int.
    assert any(op == "gcm_seal" and isinstance(ref, int) for op, ref in client.provider.calls)


def test_wrapped_key_unwrapped_into_a_handle():
    client, server = _general_pair(HandleProvider)
    server = _rehome(server, HandleProvider(unwrap_to_handle=True))
    apdu = wrap_general_ciphering(client, GB_PLAINTEXT, SERVER, key_info=KeyInfo("wrapped"))
    assert unwrap_general_ciphering(server, apdu).plaintext == GB_PLAINTEXT
    opened = [ref for op, ref in server.provider.calls if op == "gcm_open"]
    assert opened and all(isinstance(ref, int) for ref in opened)


def test_general_signing_with_handle_key():
    client, server = _general_pair(HandleProvider)
    signed = wrap_general_signing(client, GB_PLAINTEXT, SERVER)
    assert verify_general_signing(server, signed) == (CLIENT, GB_PLAINTEXT)
    assert ("ecdsa_sign", client.signing_key) in client.provider.calls


def test_handle_context_wraps_the_greenbook_apdu_byte_for_byte():
    provider = HandleProvider()
    ctx = SecurityContext(
        provider.add(GB_EK),
        provider.add(GB_AK),
        client_system_title=GB_SYSTEM_TITLE,
        invocation_counter=GB_IC,
        provider=provider,
    )
    assert wrap(ctx, GB_PLAINTEXT) == (
        bytes.fromhex("C81E3001234567") + GB_CIPHERTEXT + GB_TAG_AUTH_ENC
    )
    assert provider.calls == [("gcm_seal", ctx.encryption_key)]


# -- no key bytes in handle mode -------------------------------------------------------


def _attribute_bytes(obj) -> list[bytes]:
    found = []
    for value in vars(obj).values():
        if isinstance(value, (bytes, bytearray)):
            found.append(bytes(value))
    return found


def test_handle_mode_keeps_key_bytes_off_the_context_and_out_of_logs(caplog):
    provider = HandleProvider()
    secrets = [GB_EK, GB_AK, bytes(range(40, 56)), bytes(reversed(range(16)))]
    ek, ak, kek, bk = (provider.add(k) for k in secrets)
    sender = SecurityContext(
        ek,
        ak,
        client_system_title=GB_SYSTEM_TITLE,
        master_key=kek,
        broadcast_key=bk,
        provider=provider,
    )
    receiver = SecurityContext(
        ek, ak, server_system_title=GB_SYSTEM_TITLE, master_key=kek, provider=provider
    )
    for ctx in (sender, receiver):
        for value in _attribute_bytes(ctx):
            for secret in secrets:
                assert secret not in value
        text = repr(ctx)
        assert "provider=HandleProvider" in text
        for handle in (ek, ak, kek, bk):
            assert str(handle) not in text and hex(handle) not in text
    enable_debug(TRACE)
    try:
        with caplog.at_level(TRACE, logger="pydlms"):
            apdu = wrap(sender, GB_PLAINTEXT)
            assert unwrap(receiver, apdu).plaintext == GB_PLAINTEXT
            bad = bytearray(apdu)
            bad[-1] ^= 1
            with pytest.raises(AuthenticationError):
                unwrap(receiver, bytes(bad))
    finally:
        logging.getLogger("pydlms").setLevel(logging.WARNING)
    log = caplog.text
    assert "decipher" in log  # the trace really ran
    for secret in secrets:
        for rendering in (secret.hex(), secret.hex().upper(), secret.hex(" ")):
            assert rendering not in log


def test_handle_context_skips_raw_length_checks_but_not_raw_ones():
    provider = HandleProvider()
    SecurityContext(provider.add(bytes(16)), provider.add(bytes(16)), provider=provider)
    with pytest.raises(ValueError, match="encryption_key"):
        SecurityContext(bytes(15), provider.add(bytes(16)), provider=provider)
    ctx = SecurityContext(provider.add(GB_EK), provider=provider)
    ctx.set_dedicated_key(provider.add(GB_EK))
    with pytest.raises(ValueError, match="dedicated"):
        ctx.set_dedicated_key(bytes(15))


# -- policy stays in pydlms --------------------------------------------------------------


def test_inbound_policy_and_counter_checks_hold_in_handle_mode():
    from pydlms.exceptions import ReplayError

    provider = HandleProvider()
    ek, ak = provider.add(GB_EK), provider.add(GB_AK)
    sender = SecurityContext(ek, ak, client_system_title=GB_SYSTEM_TITLE, provider=provider)
    receiver = SecurityContext(ek, ak, server_system_title=GB_SYSTEM_TITLE, provider=provider)
    apdu = wrap(sender, GB_PLAINTEXT)
    unwrap(receiver, apdu)
    with pytest.raises(ReplayError):
        unwrap(receiver, apdu)
    weak = wrap(sender, GB_PLAINTEXT, sc=SecurityControl.from_byte(0x20))
    with pytest.raises(AuthenticationError, match="not authenticated"):
        unwrap(receiver, weak)


# -- the guard ---------------------------------------------------------------------------


class _Liar(SoftwareProvider):
    """A SoftwareProvider with one operation replaced."""

    def __init__(self, **overrides):
        for name, fn in overrides.items():
            setattr(self, name, fn)


def _liar_ctx(**overrides):
    return SecurityContext(
        GB_EK,
        GB_AK,
        client_system_title=GB_SYSTEM_TITLE,
        server_system_title=GB_SYSTEM_TITLE,
        provider=_Liar(**overrides),
    )


def test_short_tag_from_gcm_seal_refused():
    def seal(key, iv, pt, aad):
        ct, tag = SoftwareProvider().gcm_seal(key, iv, pt, aad)
        return ct, tag[:8]

    with pytest.raises(CryptoProviderError, match="8-octet tag"):
        wrap(_liar_ctx(gcm_seal=seal), GB_PLAINTEXT)


def test_full_length_tag_from_gmac_refused():
    def full_gmac(key, iv, aad):
        return SoftwareProvider().gmac(key, iv, aad) + b"\x00" * 4

    ctx = _liar_ctx(gmac=full_gmac)
    with pytest.raises(CryptoProviderError, match="16-octet tag"):
        wrap(ctx, GB_PLAINTEXT, sc=SecurityControl.from_byte(0x10))


@pytest.mark.parametrize(
    "returned",
    [None, False, True, (b"plaintext", False), "text", 0],
    ids=["None", "False", "True", "tuple-flag", "str", "int"],
)
def test_gcm_open_returning_a_flag_is_refused(returned):
    sender = SecurityContext(GB_EK, GB_AK, client_system_title=GB_SYSTEM_TITLE)
    apdu = wrap(sender, GB_PLAINTEXT)
    receiver = _liar_ctx(gcm_open=lambda *a: returned)
    with pytest.raises(CryptoProviderError):
        unwrap(receiver, apdu)
    # Nothing was accepted: the counter did not move.
    assert receiver.last_inbound_counter(GB_SYSTEM_TITLE) is None


def test_plaintext_on_failure_with_wrong_length_refused():
    """A provider that "returns what it decrypted" on a bad tag: the
    plaintext of a truncated APDU no longer has the ciphertext's length."""
    sender = SecurityContext(GB_EK, GB_AK, client_system_title=GB_SYSTEM_TITLE)
    apdu = wrap(sender, GB_PLAINTEXT)
    receiver = _liar_ctx(gcm_open=lambda key, iv, ct, aad, tag: GB_PLAINTEXT + b"\x00")
    with pytest.raises(CryptoProviderError, match="octets"):
        unwrap(receiver, apdu)


def test_short_tag_never_reaches_the_provider():
    calls = []

    def gcm_open(*args):
        calls.append(args)
        return b""

    guarded = resolve(_Liar(gcm_open=gcm_open))
    with pytest.raises(AuthenticationError):
        guarded.gcm_open(GB_EK, bytes(12), b"", (b"",), b"\x00" * 11)
    assert not calls


@pytest.mark.parametrize(
    "operation,args,bad",
    [
        ("ctr", (GB_EK, bytes(16), b"abc"), b"ab"),
        ("aes_ecb_block", (GB_EK, bytes(16)), bytes(15)),
        ("aes_wrap", (GB_EK, bytes(16)), bytes(16)),
        ("aes_unwrap", (GB_EK, bytes(24)), None),
        ("aes_unwrap", (GB_EK, bytes(24)), bytes(15)),
        ("ecdsa_sign", (object(), b"m", S1), bytes(96)),
        ("ecdsa_sign", (object(), b"m", None), bytes(70)),
        ("key_fingerprint", (1,), b"short"),
    ],
)
def test_guard_checks_every_output(operation, args, bad):
    guarded = resolve(_Liar(**{operation: lambda *a: bad, "key_fingerprint": lambda *a: bad}))
    with pytest.raises(CryptoProviderError):
        getattr(guarded, operation)(*args)


def test_guard_checks_ecdh_lengths():
    peer = ec.generate_private_key(S1).public_key()
    with pytest.raises(CryptoProviderError):
        resolve(_Liar(ecdh=lambda *a: bytes(31))).ecdh(object(), peer)
    with pytest.raises(CryptoProviderError):
        resolve(_Liar(ecdh_kdf=lambda *a: bytes(32))).ecdh_kdf(object(), peer, S1, b"")
    with pytest.raises(CryptoProviderError):
        resolve(_Liar(ecdh_kdf=lambda *a: None)).ecdh_kdf(object(), peer, S1, b"")
    with pytest.raises(CryptoProviderError):
        resolve(_Liar(public_key=lambda *a: b"not a key")).public_key(object())


def test_provider_exceptions_propagate_unchanged():
    class TokenRemoved(Exception):
        pass

    def broken(*args):
        raise TokenRemoved("HSM gone")

    sender = SecurityContext(GB_EK, GB_AK, client_system_title=GB_SYSTEM_TITLE)
    apdu = wrap(sender, GB_PLAINTEXT)
    with pytest.raises(TokenRemoved):
        unwrap(_liar_ctx(gcm_open=broken), apdu)
    with pytest.raises(TokenRemoved):
        wrap(_liar_ctx(gcm_seal=broken), GB_PLAINTEXT)


def test_missing_optional_operation_fails_closed():
    class Minimal:
        def __init__(self):
            self.inner = SoftwareProvider()

        def gcm_seal(self, *a):
            return self.inner.gcm_seal(*a)

        def gcm_open(self, *a):
            return self.inner.gcm_open(*a)

        def ctr(self, *a):
            return self.inner.ctr(*a)

        def gmac(self, *a):
            return self.inner.gmac(*a)

    ctx = SecurityContext(
        GB_EK, GB_AK, master_key=GB_EK, server_system_title=GB_SYSTEM_TITLE, provider=Minimal()
    )
    sender = SecurityContext(GB_EK, GB_AK, client_system_title=GB_SYSTEM_TITLE)
    assert unwrap(ctx, wrap(sender, GB_PLAINTEXT)).authenticated
    with pytest.raises(CryptoProviderError, match="does not implement aes_wrap"):
        wrap_general_ciphering(ctx, GB_PLAINTEXT, SERVER, key_info=KeyInfo("wrapped"))
    with pytest.raises(CryptoProviderError, match="does not implement aes_ecb_block"):
        hls.hls_manufacturer_aes(bytes(16), 7, provider=Minimal())


def test_guarded_provider_repr_and_rewrap():
    provider = HandleProvider()
    provider.add(GB_EK)
    guarded = GuardedProvider(provider)
    assert repr(guarded) == "GuardedProvider(HandleProvider)"
    assert resolve(guarded) is guarded
    assert GuardedProvider(guarded).inner is provider


# -- HLS, certificates, key agreement, counter store with handles -----------------------------


def test_hls_gmac_and_mechanism_2_secret_behind_handles():
    from tests.crypto.vectors import GB_HLS_CLIENT_TITLE, GB_HLS_F_STOC, GB_HLS_STOC

    provider = HandleProvider()
    out = hls.hls_gmac(
        provider.add(GB_EK),
        provider.add(GB_AK),
        GB_HLS_CLIENT_TITLE,
        1,
        GB_HLS_STOC,
        provider=provider,
    )
    assert out == GB_HLS_F_STOC
    secret = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
    assert hls.hls_manufacturer_aes(
        bytes.fromhex("00112233445566778899AABBCCDDEEFF"), provider.add(secret), provider=provider
    ) == bytes.fromhex("69C4E0D86A7B0430D8CDB78070B4C55A")


def test_certificate_checked_against_a_handle_signing_key():
    from tests.crypto.test_certificates import make_cert

    key = ec.generate_private_key(S1)
    provider = HandleProvider()
    handle = provider.add(key)
    title = bytes.fromhex("4D4D4D0000BC614E")
    ctx = SecurityContext(
        bytes(16),
        bytes(16),
        suite=S1,
        signing_key=handle,
        certificate=make_cert(key),
        provider=provider,
    )
    assert ctx.client_system_title == title
    assert ("public_key", handle) in provider.calls
    with pytest.raises(SecurityError, match="does not match"):
        SecurityContext(
            bytes(16),
            bytes(16),
            suite=S1,
            signing_key=provider.add(ec.generate_private_key(S1)),
            certificate=make_cert(key),
            provider=provider,
        )

    class NoPublicKey(HandleProvider):
        public_key = None

    blind = NoPublicKey()
    with pytest.raises(CryptoProviderError, match="public_key"):
        SecurityContext(
            bytes(16),
            bytes(16),
            suite=S1,
            signing_key=blind.add(key),
            certificate=make_cert(key),
            provider=blind,
        )


@pytest.mark.parametrize("suite", [S1, S2], ids=["suite1", "suite2"])
def test_key_agreement_offer_signed_by_a_handle(suite):
    from pydlms.security import keyagreement

    key = ec.generate_private_key(suite)
    provider = HandleProvider()
    handle = provider.add(key)
    ephemeral, offer = keyagreement.make_offer(handle, suite, 0, provider=provider)
    keyagreement.open_offer(key.public_key(), suite, 0, offer)  # verifies
    wrong = ec.generate_private_key(S2 if suite == S1 else S1)
    with pytest.raises(SecurityError, match="needs"):
        keyagreement.make_offer(provider.add(wrong), suite, 0, provider=provider)

    class NoPublicKey(HandleProvider):
        public_key = None

    blind = NoPublicKey()
    # Without public_key the curve check falls to the guard's signature size.
    with pytest.raises(CryptoProviderError, match="r \\|\\| s"):
        keyagreement.make_offer(blind.add(wrong), suite, 0, provider=blind)


def test_counter_store_key_of_a_handle(tmp_path):
    from pydlms.client import DlmsClient

    provider = HandleProvider()
    ctx = SecurityContext(provider.add(GB_EK), provider.add(GB_AK), provider=provider)
    client = DlmsClient.tcp("127.0.0.1", 1, security=ctx, counter_store=tmp_path / "ic.json")
    first = client._store_key()
    assert first == client._store_key()  # stable
    assert GB_EK.hex() not in first

    class NoFingerprint(HandleProvider):
        key_fingerprint = None

    blind = NoFingerprint()
    ctx = SecurityContext(blind.add(GB_EK), blind.add(GB_AK), provider=blind)
    client = DlmsClient.tcp("127.0.0.1", 1, security=ctx, counter_store=tmp_path / "ic.json")
    with pytest.raises(CryptoProviderError, match="key_fingerprint"):
        client._store_key()


def test_missing_key_still_reported_as_missing():
    ctx = SecurityContext(None, None, provider=HandleProvider())
    with pytest.raises(KeyMissingError):
        wrap(ctx, GB_PLAINTEXT)


# -- end to end against the simulator -------------------------------------------------------


@pytest.fixture
def sim():
    from pydlms.simulator import example_meter, serve

    meter = example_meter(encryption_key=GB_EK, authentication_key=GB_AK)
    server = serve(meter)
    meter.address = server.server_address
    yield meter
    server.shutdown()
    server.server_close()


def _connect(sim, **settings):
    from pydlms.client import DlmsClient

    host, port = sim.address
    return DlmsClient.tcp(host, port, timeout=3, **settings)


@pytest.mark.parametrize("dedicated", [False, True], ids=["glo", "ded"])
def test_hls_gmac_association_with_handle_keys(sim, dedicated):
    from pydlms.security.hls import Mechanism
    from pydlms.simulator import ClientProfile

    sim.clients[16] = ClientProfile(Mechanism.HLS_GMAC, ciphered=True)
    provider = HandleProvider()
    ctx = SecurityContext(
        provider.add(GB_EK),
        provider.add(GB_AK),
        client_system_title=b"PYDCLNT1",
        provider=provider,
    )
    with _connect(
        sim, mechanism=Mechanism.HLS_GMAC, security=ctx, use_dedicated_key=dedicated
    ) as meter:
        assert meter.get_register("1.0.1.8.0.255").value == 12345678
    assert {"gcm_seal", "gcm_open", "gmac"} <= provider.ops()
    assert not any(isinstance(v, bytes) and GB_EK in v for v in vars(ctx).values())


def test_hls_mechanism_2_and_7_with_handles(sim):
    from pydlms.security.hls import Mechanism
    from pydlms.simulator import ClientProfile

    secret = b"0123456789ABCDEF"
    provider = HandleProvider()
    sim.clients[16] = ClientProfile(Mechanism.HLS, secret)
    with _connect(
        sim, mechanism=Mechanism.HLS, password=provider.add(secret), provider=provider
    ) as meter:
        assert meter.get_register("1.0.1.8.0.255").value == 12345678
    assert "aes_ecb_block" in provider.ops()

    client_key, server_key = ec.generate_private_key(S1), ec.generate_private_key(S1)
    sim.signing_key = server_key
    sim.clients[16] = ClientProfile(Mechanism.HLS_ECDSA, client_public_key=client_key.public_key())
    with _connect(
        sim,
        mechanism=Mechanism.HLS_ECDSA,
        signing_key=provider.add(client_key),
        server_public_key=server_key.public_key(),
        client_system_title=b"PYDCLNT1",
        provider=provider,
    ) as meter:
        assert meter.get_register("1.0.1.8.0.255").value == 12345678
    assert "ecdsa_sign" in provider.ops()
