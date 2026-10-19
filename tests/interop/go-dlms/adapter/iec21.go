package main

// godlms iec21 [-port] [-wake none|normal|fast]: the library's IEC 62056-21
// meter (package iec6205621/meter) on TCP, as through a transparent
// converter, with 7E1 emulated (parity in bit 7). It offers mode E (`\2`):
// a binary option select hands the line to a small DLMS server over HDLC;
// a data readout option select (Y = 0) gets the data message. -wake makes
// it answer only after the annex B.1 wake-up (normal) or acknowledge the
// annex B.2 NUL strings and expect B1 after a readout (fast).
//
// The meter's records are logged to stderr as one "iec21 state ..." line
// whenever they change, for the test to read from the container log.

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"

	"github.com/cB-Sigma/dlms/classes"
	"github.com/cB-Sigma/dlms/iec6205621/meter"
	"github.com/cB-Sigma/dlms/server"
)

func runIEC21(args []string) {
	fs := flag.NewFlagSet("iec21", flag.ExitOnError)
	port := fs.Int("port", 4059, "TCP port of the converter")
	wake := fs.String("wake", "none", "none, normal (annex B.1) or fast (annex B.2)")
	_ = fs.Parse(args)
	if *wake != "none" && *wake != "normal" && *wake != "fast" {
		log.Fatalf("unknown -wake %q", *wake)
	}

	s := &server.Server{SystemTitle: serverTitle, Logf: func(f string, a ...any) { log.Printf(f, a...) }}
	s.Add(&classes.Register{LN: "1.0.1.8.0.255", Value: axdr.CreateAxdrDoubleLongUnsigned(12345678), Scaler: 0, Unit: 30})
	s.Associations = []*server.Association{{ClientAddress: 16}}

	m := &meter.Meter{
		Manufacturer: "GOD",
		BaudChar:     '5',
		Escapes:      `\2`,
		Model:        "SIGMA21",
		Registers:    map[string]string{"0.0.0": "12345678", "1.8.0": "001234.5*kWh"},
		WakeUp:       *wake == "normal",
		FastWakeUp:   *wake == "fast",
		DLMS:         s,
	}
	if err := m.ListenOn(fmt.Sprintf(":%d", *port)); err != nil {
		log.Fatal(err)
	}
	log.Printf("godlms iec21 listening on %s (wake %s)", m.Addr(), *wake)

	go func() {
		last := ""
		for range time.Tick(50 * time.Millisecond) {
			sessions, _, _ := m.Counts()
			state := fmt.Sprintf("iec21 state sessions=%d options=%q commands=%q wakeNULs=%v fastWakes=%d",
				sessions, m.Options(), m.Commands(), m.WakeNULs(), m.FastWakes())
			if state != last {
				log.Print(state)
				last = state
			}
		}
	}()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}
