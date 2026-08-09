package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/user/wisp/internal/db"
	"github.com/user/wisp/shared/protocol"
)

// TestQUICListenerExchange verifies the QUIC listener accepts a QUIC client and
// serves the same packet protocol as the TCP/KCP listeners (here: the public
// key request/response used by CLI-mode agents).
func TestQUICListenerExchange(t *testing.T) {
	database, err := db.Open(filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer database.Close()

	srv, err := New(database, nil)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	l := newQUICListener(srv, &db.ListenerRow{
		ID:       "quic-test",
		Name:     "quic-test",
		Protocol: "quic",
		BindHost: "127.0.0.1",
		BindPort: 0,
	})
	if err := l.Start(); err != nil {
		t.Fatalf("start quic listener: %v", err)
	}
	defer l.Stop()

	// QUIC client dials the chosen UDP port and performs a key request.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tlsConfig := &tls.Config{
		NextProtos:         []string{quicNextProto},
		InsecureSkipVerify: true,
	}
	conn, err := quic.DialAddr(ctx, fmt.Sprintf("127.0.0.1:%d", l.Port()), tlsConfig, nil)
	if err != nil {
		t.Fatalf("quic dial: %v", err)
	}
	defer conn.CloseWithError(0, "done")

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer stream.Close()

	adapter := &quicStreamAdapter{conn: conn, stream: stream}

	if err := protocol.WritePacket(adapter, &protocol.Packet{Type: protocol.TypeRequestKey}); err != nil {
		t.Fatalf("write key request: %v", err)
	}
	_ = adapter.SetReadDeadline(time.Now().Add(5 * time.Second))
	pkt, err := protocol.ReadPacket(adapter)
	if err != nil {
		t.Fatalf("read key response: %v", err)
	}
	if pkt.Type != protocol.TypeServerKey {
		t.Fatalf("got packet type 0x%02x, want server key", pkt.Type)
	}
	if len(pkt.Payload) == 0 {
		t.Fatal("server returned an empty public key")
	}
}
