package main

// godlms hdlc [-port] [-modulo128] [-window N] [-max-info N]: the library's
// secondary station (package hdlc, Station) on TCP, as a meter behind a
// transparent converter, in front of the library's DLMS server sessions.
// -modulo128 sets Station.Modulo128: SNRME (ISO/IEC 13239 extended
// numbering, two-octet control fields on I and S frames, windows up to
// 127) is taken; without it SNRME is answered with DM, which is what
// pydlms's modulo fallback is tested against. IEC 62056-46 itself uses
// modulo 8 only.
//
// Server.ServeHDLC builds its Station without Modulo128, so the station is
// built here; the shim exports only the server's check and session
// handler (shim/server_interop.go).

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"gitlab.com/circutor-library/gosem/pkg/axdr"

	"github.com/cB-Sigma/dlms/classes"
	"github.com/cB-Sigma/dlms/hdlc"
	"github.com/cB-Sigma/dlms/server"
)

func runHDLC(args []string) {
	fs := flag.NewFlagSet("hdlc", flag.ExitOnError)
	port := fs.Int("port", 4059, "TCP port of the converter")
	mod128 := fs.Bool("modulo128", false, "take SNRME (modulo 128); without it SNRME gets DM")
	window := fs.Int("window", 1, "receive and transmit window offered (1-7, or 1-127 with -modulo128)")
	maxInfo := fs.Int("max-info", 128, "maximum information field length offered")
	_ = fs.Parse(args)

	s := &server.Server{SystemTitle: serverTitle, Logf: func(f string, a ...any) { log.Printf(f, a...) }}
	s.Add(
		&classes.Data{LN: "0.0.96.1.0.255", Value: axdr.CreateAxdrVisibleString("GOD0000000001")},
		&classes.Register{LN: "1.0.1.8.0.255", Value: axdr.CreateAxdrDoubleLongUnsigned(12345678), Scaler: 0, Unit: 30},
		// A large value, so a GET answer and a SET request span many
		// I-frames and windows.
		&classes.Data{LN: "0.0.128.0.0.255", Value: axdr.CreateAxdrOctetString(fmt.Sprintf("%02x", make([]byte, 1500)))},
	)
	s.Associations = []*server.Association{{ClientAddress: 16}}
	if err := s.InteropCheck(); err != nil {
		log.Fatal(err)
	}
	own := hdlc.Params{MaxInfoTX: *maxInfo, MaxInfoRX: *maxInfo, WindowTX: *window, WindowRX: *window}

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("godlms hdlc listening on %s (modulo128 %v, window %d)", ln.Addr(), *mod128, *window)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveHDLC(s, c, own, *mod128)
		}
	}()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}

func serveHDLC(s *server.Server, c net.Conn, own hdlc.Params, mod128 bool) {
	defer c.Close()
	var mu sync.Mutex
	sessions := map[int]func([]byte) []byte{}
	session := func(client int) func([]byte) []byte {
		mu.Lock()
		defer mu.Unlock()
		if sessions[client] == nil {
			sessions[client] = s.InteropSession(uint16(client))
		}
		return sessions[client]
	}
	st := &hdlc.Station{Upper: 1, Size: 1, Own: own, Modulo128: mod128,
		OnLink: func(client int, up bool) {
			mu.Lock()
			defer mu.Unlock()
			delete(sessions, client)
			log.Printf("hdlc link client %d up %v", client, up)
		},
		Log: func(event string) { log.Printf("hdlc: %s", event) },
	}
	st.Handle = func(client int, apdu []byte, unconfirmed bool) []byte {
		resp := session(client)(apdu)
		if unconfirmed {
			return nil
		}
		return resp
	}
	if err := st.Serve(c); err != nil && !errors.Is(err, io.EOF) {
		log.Printf("hdlc: %v", err)
	}
}
