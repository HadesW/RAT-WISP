package server

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/xtaci/kcp-go/v5"

	"github.com/user/wisp/internal/db"
	"github.com/user/wisp/shared/protocol"
)

// rcpTestAgent emulates the agent side of the RCP channel in-process.
// Set kcp=true to dial over KCP/UDP instead of TCP.
type rcpTestAgent struct {
	keys *protocol.SessionKeys
	conn net.Conn
	kcp  bool
}

func (a *rcpTestAgent) connect(t *testing.T, host string, port int, pubPEM []byte) error {
	t.Helper()
	var conn net.Conn
	var err error
	if a.kcp {
		sess, derr := kcp.DialWithOptions(net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil, 0, 0)
		if derr != nil {
			return derr
		}
		conn = sess
	} else {
		conn, err = net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)), 5*time.Second)
		if err != nil {
			return err
		}
	}
	a.conn = conn
	challenge := []byte("0123456789abcdef")
	// raw 8 bytes that hex-encode back to the session id "ab12cd3400000000"
	rawID, _ := hex.DecodeString("ab12cd3400000000")
	hello, err := protocol.BuildRCPHello(rawID, challenge, pubPEM)
	if err != nil {
		return err
	}
	if err := protocol.WritePacket(conn, hello); err != nil {
		return err
	}
	ack, err := protocol.ReadPacket(conn)
	if err != nil {
		return err
	}
	if ack.Type != protocol.TypeRCPAck {
		return fmt.Errorf("expected ack, got %d", ack.Type)
	}
	dec, err := a.keys.Decrypt(ack.Payload)
	if err != nil {
		return err
	}
	if !bytes.Equal(dec, challenge) {
		return fmt.Errorf("challenge mismatch")
	}
	return nil
}

func (a *rcpTestAgent) sendFrame(t *testing.T, seq uint64, w, h int, jpeg []byte) {
	t.Helper()
	payload := protocol.EncodeRCPFrame(seq, w, h, jpeg)
	enc, err := a.keys.Encrypt(payload)
	if err != nil {
		t.Fatalf("encrypt frame: %v", err)
	}
	if err := protocol.WritePacket(a.conn, &protocol.Packet{Type: protocol.TypeRCPFrame, Payload: enc}); err != nil {
		t.Fatalf("send frame: %v", err)
	}
}

func (a *rcpTestAgent) expectInput(t *testing.T) string {
	t.Helper()
	pkt, err := protocol.ReadPacket(a.conn)
	if err != nil {
		t.Fatalf("read input: %v", err)
	}
	if pkt.Type != protocol.TypeRCPInput {
		t.Fatalf("expected input packet, got %d", pkt.Type)
	}
	dec, err := a.keys.Decrypt(pkt.Payload)
	if err != nil {
		t.Fatalf("decrypt input: %v", err)
	}
	return string(dec)
}

func newRCPServer(t *testing.T) (*Server, *namedEmitter) {
	t.Helper()
	database, err := db.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	em := &namedEmitter{}
	s, err := New(database, em)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return s, em
}

func TestRCPHandshakeFrameAndInput(t *testing.T) {
	s, em := newRCPServer(t)
	defer s.StopRCP()

	// Register a session so the server can authenticate the agent
	keys, err := protocol.GenerateSessionKeys()
	if err != nil {
		t.Fatal(err)
	}
	agentID := "ab12cd3400000000"
	sess := &db.SessionRow{ID: agentID, ListenerID: "l1", Hostname: "testhost", Username: "user", ExternalIP: "1.2.3.4"}
	s.RegisterSession(sess, keys)

	port, err := s.EnsureRCP("tcp")
	if err != nil {
		t.Fatalf("ensure rcp: %v", err)
	}

	agent := &rcpTestAgent{keys: keys}
	if err := agent.connect(t, "127.0.0.1", port, s.GetRSAPublicKeyPEM()); err != nil {
		t.Fatalf("agent connect: %v", err)
	}
	defer agent.conn.Close()

	// Unknown sessions must be rejected
	badConn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port)), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	badRawID, _ := hex.DecodeString("deadbeef00000000")
	hello, _ := protocol.BuildRCPHello(badRawID, []byte("0123456789abcdef"), s.GetRSAPublicKeyPEM())
	_ = protocol.WritePacket(badConn, hello)
	badConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if pkt, err := protocol.ReadPacket(badConn); err == nil && pkt.Type == protocol.TypeRCPAck {
		t.Error("unknown session should not be authenticated")
	}
	badConn.Close()

	// Stream a frame and verify the frontend event
	agent.sendFrame(t, 1, 640, 480, []byte{0xff, 0xd8, 0xff, 0x01})
	waitFor(t, 2*time.Second, func() bool {
		for _, e := range em.events {
			if e.name == "rc:frame" && e.data["session_id"] == agentID && e.data["seq"] == "1" {
				return true
			}
		}
		return false
	})

	// Send input down the channel and verify the agent receives it
	if err := s.SendRCPInput(agentID, []byte(`{"type":"click","x":10,"y":20}`)); err != nil {
		t.Fatalf("send input: %v", err)
	}
	if got := agent.expectInput(t); got != `{"type":"click","x":10,"y":20}` {
		t.Errorf("input = %q", got)
	}

	// Closing the channel makes further input fail
	s.CloseRCPChannel(agentID)
	if err := s.SendRCPInput(agentID, []byte(`{}`)); err == nil {
		t.Error("expected error after close")
	}
}

// TestRCPKCPChannel verifies the RCP listener can serve a KCP/UDP channel: an
// agent dials over KCP, handshakes and streams a frame that reaches the UI.
func TestRCPKCPChannel(t *testing.T) {
	s, em := newRCPServer(t)
	defer s.StopRCP()

	keys, err := protocol.GenerateSessionKeys()
	if err != nil {
		t.Fatal(err)
	}
	agentID := "ab12cd3400000000"
	sess := &db.SessionRow{ID: agentID, ListenerID: "l1", Hostname: "testhost", Username: "user", ExternalIP: "1.2.3.4"}
	s.RegisterSession(sess, keys)

	port, err := s.EnsureRCP("kcp")
	if err != nil {
		t.Fatalf("ensure rcp kcp: %v", err)
	}

	agent := &rcpTestAgent{keys: keys, kcp: true}
	if err := agent.connect(t, "127.0.0.1", port, s.GetRSAPublicKeyPEM()); err != nil {
		t.Fatalf("kcp agent connect: %v", err)
	}
	defer agent.conn.Close()

	// Stream a frame and verify the frontend event over KCP
	agent.sendFrame(t, 7, 320, 240, []byte{0xff, 0xd8, 0xff, 0x01})
	waitFor(t, 3*time.Second, func() bool {
		for _, e := range em.events {
			if e.name == "rc:frame" && e.data["session_id"] == agentID && e.data["seq"] == "7" {
				return true
			}
		}
		return false
	})

	// Input must travel down the KCP channel too
	if err := s.SendRCPInput(agentID, []byte(`{"type":"move","x":5,"y":6}`)); err != nil {
		t.Fatalf("send input over kcp: %v", err)
	}
	if got := agent.expectInput(t); got != `{"type":"move","x":5,"y":6}` {
		t.Errorf("input = %q", got)
	}
}

func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}
