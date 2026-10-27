package socks

import (
	"bufio"
	"encoding/binary"
	"net"
	"path/filepath"
	"testing"
	"time"

	"wispp/protocol"
	"wispp/server/internal/db"
	"wispp/server/internal/rcp"
	"wispp/server/internal/rcptest"
)

func TestSocks5ConnectBridge(t *testing.T) {
	store, err := db.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.DB.Close()
	hub := rcp.NewHub("psk-s", nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go hub.Serve(ln)

	go func() {
		c, err := rcptest.Dial(ln.Addr().String(), "psk-s", "sockspeer")
		if err != nil {
			return
		}
		defer c.Close()
		for {
			f, err := protocol.ReadRCPFrame(c)
			if err != nil {
				return
			}
			if f.Kind == protocol.RCPKindFrame {
				_ = protocol.WriteRCPFrame(c, &protocol.RCPFrame{Chan: f.Chan, Kind: protocol.RCPKindFrame,
					Payload: append([]byte("peer:"), f.Payload...)})
			}
		}
	}()
	for !hub.Online("sockspeer") {
		time.Sleep(20 * time.Millisecond)
	}

	svc := New(hub, store, func(string, string) {})
	id, bound, err := svc.Start("sockspeer", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Stop(id)

	c, err := net.Dial("tcp", bound)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(c)

	// greeting → no-auth
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	g := make([]byte, 2)
	if _, err := io_ReadFull(br, g); err != nil || g[0] != 0x05 || g[1] != 0x00 {
		t.Fatalf("greeting reply %v %v", g, err)
	}
	// CONNECT example.com:8080 (domain form)
	host := "example.com"
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, 8080)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, pb...)
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 10)
	if _, err := io_ReadFull(br, rep); err != nil || rep[1] != 0x00 {
		t.Fatalf("connect reply %v %v", rep, err)
	}
	// data plane through the fwd bridge
	if _, err := c.Write([]byte("ping\n")); err != nil {
		t.Fatal(err)
	}
	got, err := br.ReadString('\n')
	if err != nil || got != "peer:ping\n" {
		t.Fatalf("bridge roundtrip %q %v", got, err)
	}
}

func io_ReadFull(r *bufio.Reader, b []byte) (int, error) {
	var n int
	for n < len(b) {
		m, err := r.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
