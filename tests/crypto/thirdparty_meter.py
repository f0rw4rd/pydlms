"""The meter's side of third-party layers, for tests (annex J; cB-Sigma's Responder).

:class:`TpMeter` opens a request's third-party layers (general-ciphering
under an agreed key outside, general-signing inside) and answers with the
meter's layers for the third party: the same kinds, the request's
transaction-id, invocation counter 0 under every new agreed key, or the
unprotected annex J.3 layer when the third party neither ciphered nor gets
a signed answer. Built from pydlms' own general-ciphering/-signing
primitives with a context whose own title is the meter's.
"""

from __future__ import annotations

from dataclasses import dataclass

from pydlms.apdu.tags import Tag
from pydlms.security.context import SecurityContext
from pydlms.security.general import (
    GeneralAad,
    KeyInfo,
    SigningForm,
    _read_os,
    unwrap_general_ciphering,
    verify_general_signing,
    wrap_general_ciphering,
    wrap_general_signing,
)
from pydlms.security.suites import SecurityControl, SecurityPolicy
from pydlms.security.thirdparty import wrap_unprotected_general_ciphering


@dataclass
class TpTransaction:
    signed: bool = False
    policy: int = 0
    scheme: int = 1
    transaction_id: bytes = b""


@dataclass
class TpMeter:
    suite: int
    meter_title: bytes
    tp_title: bytes
    meter_sign: object
    meter_ka: object
    tp_sign_pub: object
    tp_ka_pub: object
    ak: bytes | None
    sign_answers: bool = True
    general_aad: GeneralAad = GeneralAad.SC_AK
    signing_form: SigningForm = SigningForm.CONTENT

    def ctx(self, policy: int = 0) -> SecurityContext:
        """A fresh meter-side context (invocation counter 0) towards the TP."""
        return SecurityContext(
            None,
            self.ak,
            client_system_title=self.meter_title,
            server_system_title=self.tp_title,
            suite=self.suite,
            policy=SecurityPolicy(policy),
            signing_key=self.meter_sign,
            key_agreement_key=self.meter_ka,
            peer_signing_key=self.tp_sign_pub,
            peer_key_agreement_key=self.tp_ka_pub,
            general_aad=self.general_aad,
            signing_form=self.signing_form,
        )

    def open(self, apdu: bytes) -> tuple[bytes, TpTransaction]:
        tx = TpTransaction()
        while apdu and apdu[0] in (Tag.GENERAL_CIPHERING, Tag.GENERAL_SIGNING):
            if apdu[0] == Tag.GENERAL_CIPHERING:
                assert not tx.signed and not tx.policy, "layer order"
                pos = 1
                tx.transaction_id, pos = _read_os(apdu, pos, "tid")
                for _ in range(4):
                    _, pos = _read_os(apdu, pos, "header")
                assert apdu[pos : pos + 3] == b"\x01\x02\x01", "agreed key-info"
                tx.scheme = apdu[pos + 3]
                result = unwrap_general_ciphering(self.ctx(), apdu)
                tx.policy = result.security_control.to_byte() & 0x30
                apdu = result.plaintext
            else:
                assert not tx.signed, "signed twice"
                pos = 1
                tid, _ = _read_os(apdu, pos, "tid")
                tx.transaction_id = tx.transaction_id or tid
                _, apdu = verify_general_signing(self.ctx(), apdu)
                tx.signed = True
        return apdu, tx

    def answer(self, tx: TpTransaction, response: bytes) -> bytes:
        sign = tx.signed and self.sign_answers
        if not sign and not tx.policy:
            return wrap_unprotected_general_ciphering(
                self.suite, response, self.meter_title, self.tp_title, tx.transaction_id
            )
        out = response
        if sign:
            out = wrap_general_signing(
                self.ctx(), out, self.tp_title, transaction_id=tx.transaction_id
            )
        if tx.policy:
            out = wrap_general_ciphering(
                self.ctx(tx.policy),
                out,
                self.tp_title,
                KeyInfo("agreed", scheme=tx.scheme),
                transaction_id=tx.transaction_id,
                sc=SecurityControl.for_policy(SecurityPolicy(tx.policy), self.suite),
            )
        return out
