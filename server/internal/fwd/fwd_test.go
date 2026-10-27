package fwd

import (
	"bufio"

	"net"
	"path/filepath"
	"testing"
	"time"

	"wispp/protocol"
	"wispp/server/internal/db"
	"wispp/server/internal/rcp"
	"wispp/server/internal/rcptest"
)

// startEcho: local TCP echo server
func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					_, _ = c.Write([]byte("echo:" + line))
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

func TestFwdBridge(t *testing.T) {
	// NOTE: the fake agent above owns the rcp conn; inbound frames for the fwd
	// chan must reach the target too. For a focused bridge test we drive Svc
	// against a scripted hub-side peer instead of the full agent.
	store, err := db.Open(filepath.Join(t.TempDir(), "f.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.DB.Close()
	hub := rcp.NewHub("psk-f", nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go hub.Serve(ln)

	// scripted peer: hello → wait Open(fwd) → echo frames back with prefix
	go func() {
		c, err := rcptest.Dial(ln.Addr().String(), "psk-f", "fwdpeer")
		if err != nil {
			return
		}
		defer c.Close() // ack
		for {
			f, err := protocol.ReadRCPFrame(c)
			if err != nil {
				return
			}
			if f.Kind == protocol.RCPKindOpen {
				continue
			}
			if f.Kind == protocol.RCPKindFrame {
				_ = protocol.WriteRCPFrame(c, &protocol.RCPFrame{Chan: f.Chan, Kind: protocol.RCPKindFrame,
					Payload: append([]byte("peer:"), f.Payload...)})
			}
		}
	}()
	for !hub.Online("fwdpeer") {
		time.Sleep(20 * time.Millisecond)
	}

	svc := New(hub, store, func(string, string) {})
	id, bound, err := svc.Start("fwdpeer", "127.0.0.1:0", "10.0.0.1:80")
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Stop(id)

	conn, err := net.Dial("tcp", bound)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("hello-fwd\n")); err != nil {
		t.Fatal(err)
	}
	got, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if got != "peer:hello-fwd\n" {
		t.Fatalf("bridge roundtrip: %q", got)
	}
	rows, _ := store.FwdList()
	if len(rows) != 1 || rows[0].Status != "active" {
		t.Fatalf("db: %+v", rows)
	}
}
