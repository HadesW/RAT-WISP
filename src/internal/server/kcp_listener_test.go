package server

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/xtaci/kcp-go/v5"

	"github.com/user/wisp/internal/db"
	"github.com/user/wisp/shared/protocol"
)

// TestKCPListenerExchange verifies the KCP listener accepts a KCP/UDP client and
// serves the same packet protocol as the TCP listener (here: the public key
// request/response used by CLI-mode agents).
func TestKCPListenerExchange(t *testing.T) {
	database, err := db.Open(filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer database.Close()

	srv, err := New(database, nil)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	l := newKCPListener(srv, &db.ListenerRow{
		ID:       "kcp-test",
		Name:     "kcp-test",
		Protocol: "kcp",
		BindHost: "127.0.0.1",
		BindPort: 0,
	})
	if err := l.Start(); err != nil {
		t.Fatalf("start kcp listener: %v", err)
	}
	defer l.Stop()

	// KCP client dials the chosen UDP port and performs a key request.
	sess, err := kcp.DialWithOptions(fmt.Sprintf("127.0.0.1:%d", l.Port()), nil, 0, 0)
	if err != nil {
		t.Fatalf("kcp dial: %v", err)
	}
	defer sess.Close()

	if err := protocol.WritePacket(sess, &protocol.Packet{Type: protocol.TypeRequestKey}); err != nil {
		t.Fatalf("write key request: %v", err)
	}
	_ = sess.SetReadDeadline(time.Now().Add(5 * time.Second))
	pkt, err := protocol.ReadPacket(sess)
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
