// Command godlms is the pydlms interop adapter for github.com/cB-Sigma/dlms.
//
//	godlms                 the oracle line protocol on stdin/stdout (PROTOCOL.md)
//	godlms server [-port]  the library's meter (server package) on the TCP wrapper
//	godlms client ...      the library's client reading a meter, JSON on stdout
//	godlms iec21 [-wake]   the library's IEC 62056-21 meter on TCP (iec21.go)
//	godlms hdlc [-modulo128] the library's HDLC station on TCP (hdlc.go)
//
// Logs go to stderr; stdout carries only protocol replies (oracle) or the
// one JSON report (client).
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"

	"github.com/cB-Sigma/dlms/classes"
	"github.com/cB-Sigma/dlms/cosem"
	"github.com/cB-Sigma/dlms/server"
	"github.com/cB-Sigma/dlms/wrapper"
)

func main() {
	log.SetOutput(os.Stderr)
	if len(os.Args) < 2 {
		runOracle()
		return
	}
	switch os.Args[1] {
	case "server":
		runServer(os.Args[2:])
	case "client":
		runClient(os.Args[2:])
	case "iec21":
		runIEC21(os.Args[2:])
	case "hdlc":
		runHDLC(os.Args[2:])
	default:
		log.Fatalf("unknown command %q (server, client, iec21, hdlc, or none for the oracle)", os.Args[1])
	}
}

// --- shared test material (mirrored in tests/interop/test_go_dlms.py) ----

var (
	serverTitle = []byte("GODLMS01")
	clientTitle = []byte("PYDLMS01")
	tpTitle     = []byte("TPHEAD01")
	ek16        = mustHex("000102030405060708090a0b0c0d0e0f")
	ak16        = mustHex("d0d1d2d3d4d5d6d7d8d9dadbdcdddedf")
	ek32        = mustHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	ak32        = mustHex("d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef")
	kek16       = mustHex("31313131313131313131313131313131")
	kek32       = mustHex("3131313131313131313131313131313131313131313131313131313131313131")
	lls         = []byte("12345678")
	hlsSecret   = []byte("0123456789ABCDEF")
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// testKey derives a fixed ECDSA key: d = SHA-256(label) (P-256) or
// SHA-384(label) (P-384), reduced mod n-1 plus 1.
func testKey(label string, curve elliptic.Curve) *ecdsa.PrivateKey {
	h256, h384 := sha256.Sum256([]byte(label)), sha512.Sum384([]byte(label))
	digest := h256[:]
	if curve == elliptic.P384() {
		digest = h384[:]
	}
	n := new(big.Int).Sub(curve.Params().N, big.NewInt(1))
	d := new(big.Int).Mod(new(big.Int).SetBytes(digest), n)
	d.Add(d, big.NewInt(1))
	k := &ecdsa.PrivateKey{D: d}
	k.Curve = curve
	k.X, k.Y = curve.ScalarBaseMult(d.FillBytes(make([]byte, (curve.Params().BitSize+7)/8)))
	return k
}

func curveFor(suite int) elliptic.Curve {
	if suite == 2 {
		return elliptic.P384()
	}
	return elliptic.P256()
}

func privPEM(k *ecdsa.PrivateKey) string {
	b, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}))
}

func pubPEM(k *ecdsa.PublicKey) string {
	b, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: b}))
}

// --- server ----------------------------------------------------------------

func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	port := fs.Int("port", 4059, "TCP wrapper port")
	gbt := fs.Bool("gbt", false, "offer general-block-transfer")
	_ = fs.Parse(args)

	loc := time.FixedZone("UTC+2", 2*3600)
	now := time.Date(2024, 5, 1, 12, 0, 0, 0, loc)
	s := &server.Server{SystemTitle: serverTitle, GBT: *gbt, Logf: func(f string, a ...any) { log.Printf(f, a...) }}

	s.Add(
		&classes.Data{LN: "0.0.42.0.0.255", Value: axdr.CreateAxdrOctetString(hex.EncodeToString([]byte("GODLMS0000000001")))},
		&classes.Data{LN: "0.0.96.1.0.255", Value: axdr.CreateAxdrVisibleString("GOD0000000001")},
		&classes.Register{LN: "1.0.1.8.0.255", Value: axdr.CreateAxdrDoubleLongUnsigned(12345678), Scaler: 0, Unit: 30},
		&classes.Register{LN: "1.0.32.7.0.255", Value: axdr.CreateAxdrLongUnsigned(2301), Scaler: -1, Unit: 35},
		&classes.Register{LN: "1.0.31.7.0.255", Value: axdr.CreateAxdrLong(523), Scaler: -2, Unit: 33},
		&classes.ExtendedRegister{LN: "1.0.1.6.0.255", Value: axdr.CreateAxdrDoubleLongUnsigned(4200), Scaler: 1, Unit: 27,
			Status: axdr.CreateAxdrUnsigned(0), CaptureTime: now, Location: loc, Now: func() time.Time { return now }},
		&classes.Clock{LN: "0.0.1.0.0.255", Now: func() time.Time { return now }, Location: loc, TimeZone: -120},
	)
	start := time.Date(2024, 5, 1, 0, 0, 0, 0, time.UTC)
	rows := make([][]*axdr.DlmsData, 0, 96)
	for i := range 96 {
		t := start.Add(time.Duration(15*i) * time.Minute)
		rows = append(rows, []*axdr.DlmsData{
			axdr.CreateAxdrOctetString(hex.EncodeToString(classes.DateTime(t, time.UTC))),
			axdr.CreateAxdrDoubleLongUnsigned(uint32(1000 + 7*i)),
		})
	}
	s.Add(&classes.ProfileGeneric{
		LN: "1.0.99.1.0.255", Buffer: rows, CapturePeriod: 900, ProfileEntries: 96, SortMethod: 1, Location: time.UTC,
		CaptureObjects: []classes.CaptureObject{
			{Class: 8, LN: "0.0.1.0.0.255", Attr: 2},
			{Class: 3, LN: "1.0.1.8.0.255", Attr: 2},
		},
	})

	ecdsaAssoc := func(sap uint16, suite int, signing bool) *server.Association {
		c := curveFor(suite)
		key, ak, kek := ek16, ak16, kek16
		if suite == 2 {
			key, ak, kek = ek32, ak32, kek32
		}
		return &server.Association{ClientAddress: sap, Mechanism: 7, Policy: cosem.SecAuthentication | cosem.SecEncryption,
			Suite: byte(suite), Key: key, AuthKey: ak, MasterKey: kek,
			SigningKey: testKey(fmt.Sprintf("server-sign-%d", suite), c), ClientKey: &testKey(fmt.Sprintf("client-sign-%d", suite), c).PublicKey,
			KAKey: testKey(fmt.Sprintf("server-ka-%d", suite), c), ClientKAKey: &testKey(fmt.Sprintf("client-ka-%d", suite), c).PublicKey,
			Signing: signing}
	}
	// Third-party layers (IEC 62056-5-3:2023 annex J): the third party
	// "TPHEAD01" signs and/or ciphers inside the client's protection; the
	// meter answers with its layers for it (signed when signAnswers) or,
	// when neither applies, the unprotected annex J.3 layer.
	tpAssoc := func(sap uint16, suite int, signAnswers bool) *server.Association {
		a := ecdsaAssoc(sap, suite, false)
		c := curveFor(suite)
		ak := ak16
		if suite == 2 {
			ak = ak32
		}
		a.ThirdParties = []cosem.ResponderThirdParty{{SystemTitle: tpTitle,
			SignKey: &testKey(fmt.Sprintf("tp-sign-%d", suite), c).PublicKey,
			KAKey:   &testKey(fmt.Sprintf("tp-ka-%d", suite), c).PublicKey,
			AuthKey: ak, SignAnswers: signAnswers}}
		return a
	}
	glo := cosem.SecAuthentication | cosem.SecEncryption
	s.Associations = []*server.Association{
		{ClientAddress: 16},
		{ClientAddress: 17, Mechanism: 1, Secret: lls},
		{ClientAddress: 18, Mechanism: 2, Secret: hlsSecret},
		{ClientAddress: 19, Mechanism: 3, Secret: hlsSecret},
		{ClientAddress: 20, Mechanism: 4, Secret: hlsSecret},
		{ClientAddress: 21, Mechanism: 6, Secret: hlsSecret},
		{ClientAddress: 1, Mechanism: 5, Policy: glo, Key: ek16, AuthKey: ak16, MasterKey: kek16},
		{ClientAddress: 2, Mechanism: 5, Policy: glo, Suite: 1, Key: ek16, AuthKey: ak16, MasterKey: kek16},
		ecdsaAssoc(3, 1, false),
		ecdsaAssoc(4, 1, true),
		ecdsaAssoc(5, 2, false),
		tpAssoc(6, 1, true),
		tpAssoc(7, 1, false),
		tpAssoc(8, 2, true),
	}
	addr, err := s.ListenWrapper(fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("godlms server listening on %s", addr)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}

// --- client ----------------------------------------------------------------

func runClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	host := fs.String("host", "127.0.0.1", "meter host")
	port := fs.Int("port", 4059, "meter TCP wrapper port")
	sap := fs.Int("client", 16, "client SAP")
	auth := fs.String("auth", "none", "none, low, hls, hls-md5, hls-sha1, hls-sha256, hls-gmac, hls-ecdsa")
	password := fs.String("password", "", "LLS password / HLS secret")
	security := fs.String("security", "none", "none, authenticated, encrypted, authenticated-encrypted")
	suite := fs.Int("suite", 0, "security suite")
	ciphering := fs.String("ciphering", "", "service-specific, general-glo, general-ded, general")
	dedicated := fs.Bool("dedicated", false, "agree a dedicated key")
	generalKey := fs.String("general-key", "", "general-ciphering key-info: identified, wrapped, agreed-one-pass, agreed-static")
	masterKey := fs.String("master-key", "", "master key / KEK (hex)")
	signing := fs.Bool("signing", false, "general-signing on every request")
	key := fs.String("key", "", "block cipher key (hex)")
	authKey := fs.String("auth-key", "", "authentication key (hex)")
	tp := fs.Bool("tp", false, "protect requests for the third party TPHEAD01 (annex J)")
	tpSign := fs.Bool("tp-sign", true, "the third party signs")
	tpSecurity := fs.String("tp-security", "", "the third party's general-ciphering: none, authenticated, encrypted, authenticated-encrypted")
	tpKey := fs.String("tp-key", "", "its key agreement: agreed-one-pass, agreed-static")
	tpSigned := fs.Bool("tp-signed-responses", true, "require the meter's signed layer for the third party")
	tpCiphered := fs.Bool("tp-ciphered-responses", false, "require the meter's ciphered layer for the third party")
	profile := fs.String("profile", "1.0.99.1.0.255", "profile generic to read by range")
	from := fs.String("from", "2024-05-01T00:00:00Z", "range start (RFC 3339)")
	to := fs.String("to", "2024-05-01T01:00:00Z", "range end (RFC 3339)")
	_ = fs.Parse(args)

	report := map[string]any{}
	errs := map[string]string{}
	defer func() {
		report["errors"] = errs
		b, _ := json.Marshal(report)
		fmt.Println(string(b))
	}()

	sec := cosem.SecurityConfig{Name: "meter", Authentication: *auth, Password: *password, Security: *security,
		Suite: *suite, SystemTitle: hex.EncodeToString(clientTitle), BlockCipherKey: *key, AuthenticationKey: *authKey,
		Ciphering: *ciphering, DedicatedKey: *dedicated, GeneralKey: *generalKey, MasterKey: *masterKey, Signing: *signing}
	if *suite != 0 && (*auth == "hls-ecdsa" || *ciphering == "general" || *signing) {
		c := curveFor(*suite)
		sec.SigningKey = privPEM(testKey(fmt.Sprintf("client-sign-%d", *suite), c))
		sec.MeterSigningKey = pubPEM(&testKey(fmt.Sprintf("server-sign-%d", *suite), c).PublicKey)
		sec.KeyAgreementKey = privPEM(testKey(fmt.Sprintf("client-ka-%d", *suite), c))
		sec.MeterKAKey = pubPEM(&testKey(fmt.Sprintf("server-ka-%d", *suite), c).PublicKey)
	}
	if *tp {
		c := curveFor(*suite)
		sec.MeterSigningKey = pubPEM(&testKey(fmt.Sprintf("server-sign-%d", *suite), c).PublicKey)
		sec.MeterKAKey = pubPEM(&testKey(fmt.Sprintf("server-ka-%d", *suite), c).PublicKey)
		sec.ThirdParty = &cosem.ThirdParty{SystemTitle: hex.EncodeToString(tpTitle),
			SigningKey:      privPEM(testKey(fmt.Sprintf("tp-sign-%d", *suite), c)),
			KeyAgreementKey: privPEM(testKey(fmt.Sprintf("tp-ka-%d", *suite), c)),
			Sign:            tpSign, Security: *tpSecurity, GeneralKey: *tpKey,
			SignedResponses: tpSigned, CipheredResponses: tpCiphered}
		if *tpSecurity != "" && *tpSecurity != "none" {
			sec.ThirdParty.AuthenticationKey = *authKey
		}
	}
	hls, _, err := sec.Build()
	if err != nil {
		errs["config"] = err.Error()
		return
	}
	addr := fmt.Sprintf("%s:%d", *host, *port)
	c := cosem.NewClient(cosem.ClientConfig{
		Transport: func(client int) (gdlms.Transport, error) {
			return wrapper.New("tcp", addr, client, 1, 10*time.Second)
		},
		ClientAddress: *sap, HLS: hls, Password: []byte(*password), Timeout: 10 * time.Second,
	})
	if err := c.Connect(); err != nil {
		errs["associate"] = err.Error()
		return
	}
	defer c.Close()
	report["associated"] = true
	if st := c.MeterSystemTitle(); st != nil {
		report["meter_system_title"] = hex.EncodeToString(st)
	}

	values := map[string]any{}
	report["values"] = values
	read := func(class uint16, ln string, a int8) (*axdr.DlmsData, bool) {
		k := fmt.Sprintf("%s/%d/%d", ln, class, a)
		d, err := c.Get(class, ln, a)
		if err != nil {
			errs[k] = err.Error()
			return nil, false
		}
		t, err := toTree(&d)
		if err != nil {
			errs[k] = err.Error()
			return nil, false
		}
		values[k] = t
		return &d, true
	}

	list, ok := read(15, "0.0.40.0.0.255", 2)
	var objects []map[string]any
	if ok {
		items, err := classes.ParseObjectListLN(*list)
		if err != nil {
			errs["object_list"] = err.Error()
		}
		for _, it := range items {
			objects = append(objects, map[string]any{"class_id": it.Class, "version": it.Version, "logical_name": it.LN})
		}
		delete(values, "0.0.40.0.0.255/15/2")
	}
	report["objects"] = objects
	for _, o := range objects {
		class, ln := o["class_id"].(uint16), o["logical_name"].(string)
		switch class {
		case 1:
			read(class, ln, 2)
		case 3:
			read(class, ln, 2)
			if _, ok := read(class, ln, 3); ok {
				if sc, err := cosem.ReadScaler(c.Association().Client, class, ln); err == nil {
					values[ln+"/scaler"] = sc
				} else {
					errs[ln+"/scaler"] = err.Error()
				}
			}
		case 8:
			read(class, ln, 2)
			read(class, ln, 3)
		case 7:
			read(class, ln, 3)
			read(class, ln, 4)
			read(class, ln, 7)
		}
	}

	cols, err := cosem.ReadCaptureObjects(c.Association().Client, *profile)
	if err != nil {
		errs["profile_columns"] = err.Error()
		return
	}
	tc, ok := cosem.TimeColumn(cols)
	if !ok {
		errs["profile_columns"] = "no time column"
		return
	}
	t0, _ := time.Parse(time.RFC3339, *from)
	t1, _ := time.Parse(time.RFC3339, *to)
	rows, err := cosem.ReadProfileRange(c.Association().Client, *profile, cols[tc], t0, t1, time.UTC)
	if err != nil {
		errs["profile_range"] = err.Error()
		return
	}
	var out []any
	for _, r := range rows {
		t, err := toTree(r)
		if err != nil {
			errs["profile_range"] = err.Error()
			return
		}
		out = append(out, t)
	}
	report["profile_range"] = out
}
