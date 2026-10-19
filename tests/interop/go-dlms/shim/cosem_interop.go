package cosem

// Added by the pydlms interop image (tests/interop/go-dlms/Dockerfile),
// not part of github.com/cB-Sigma/dlms. It only exports unexported
// functions of this package so the adapter can call the library's own
// code; it adds no behaviour.

import "errors"

// InteropGeneralGloDed is decodeGeneralGloDed.
func InteropGeneralGloDed(apdu []byte) (systemTitle, content []byte, err error) {
	return decodeGeneralGloDed(apdu)
}

// InteropOpen removes glo-, ded- or general-glo/-ded ciphering from one
// APDU the way SecureTransport.incoming (client) does: the length form of
// getLen, keySetZero for dedicated forms, UnprotectKeys or
// unprotectGeneral, and the inner tag check. Request tags (the server's
// side) are opened with the same functions. bkey opens content whose
// security control names the global broadcast key (bit 6), as the
// library's broadcastKey setting does.
func InteropOpen(suite Suite, key, bkey, ak, systemTitle, apdu []byte) ([]byte, error) {
	if len(apdu) == 0 {
		return nil, errors.New("empty APDU")
	}
	switch apdu[0] {
	case TagGeneralGlo, TagGeneralDed:
		st, content, err := decodeGeneralGloDed(apdu)
		if err != nil {
			return nil, err
		}
		if len(systemTitle) != 0 && string(st) != string(systemTitle) {
			return nil, errors.New("the general-ciphering APDU names another sender's system title")
		}
		if apdu[0] == TagGeneralDed {
			if err := keySetZero(content); err != nil {
				return nil, err
			}
		}
		plain, _, err := unprotectGeneral(nil, suite, key, bkey, ak, st, content, nil)
		return plain, err
	}
	tag, ded, ok := byte(0), false, false
	if p, found := plainOf[apdu[0]]; found {
		tag, ded, ok = p.tag, p.ded, true
	}
	for plainTag, glo := range gloOf {
		if glo == apdu[0] {
			tag, ok = plainTag, true
		}
	}
	for plainTag, d := range dedOf {
		if d == apdu[0] {
			tag, ded, ok = plainTag, true, true
		}
	}
	if !ok {
		return nil, errors.New("not a protected APDU this library opens")
	}
	n, sz, err := getLen(apdu[1:])
	if err != nil || 1+sz+n > len(apdu) {
		return nil, errors.New("protected APDU length is wrong")
	}
	if ded {
		if err := keySetZero(apdu[1+sz : 1+sz+n]); err != nil {
			return nil, err
		}
	}
	plain, _, err := UnprotectKeys(suite, key, bkey, ak, systemTitle, apdu[1+sz:1+sz+n], nil)
	if err != nil {
		return nil, err
	}
	if len(plain) == 0 || plain[0] != tag {
		return nil, errors.New("the protected APDU holds a different service than its tag says")
	}
	return plain, nil
}
