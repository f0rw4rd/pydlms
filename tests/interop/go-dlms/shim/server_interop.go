package server

// Added by the pydlms interop image (tests/interop/go-dlms/Dockerfile),
// not part of github.com/cB-Sigma/dlms. It only exports the server's own
// AARQ and InitiateRequest parsers (aa.go), its configuration check and
// its per-client session handler (session.go, transport.go) for the
// adapter; no behaviour is added.

// InteropInitiate is what parseInitiate reads from an InitiateRequest.
type InteropInitiate struct {
	DedicatedKey []byte
	Unconfirmed  bool
	Version      byte
	Conformance  uint32
	MaxPDU       int
}

// InteropBerItems is berItems.
func InteropBerItems(apdu []byte) (map[byte][]byte, bool) { return berItems(apdu) }

// InteropParseInitiate is parseInitiate.
func InteropParseInitiate(ir []byte) (InteropInitiate, bool) {
	r, ok := parseInitiate(ir)
	return InteropInitiate{r.dedKey, r.unconfirmed, r.version, r.conformance, r.maxPDU}, ok
}

// InteropCheck is check.
func (s *Server) InteropCheck() error { return s.check() }

// InteropSession is newSession(s, client).answer: the APDU handler of one
// client's session, for an hdlc.Station the adapter builds itself.
func (s *Server) InteropSession(client uint16) func(apdu []byte) []byte {
	return newSession(s, client).answer
}
