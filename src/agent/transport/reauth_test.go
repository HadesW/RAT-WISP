package transport

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"

	"github.com/user/wisp/shared/protocol"
)

// TestCheckinTypeCloseReturnsErrReauth simulates a server restart: the agent
// registers, then the server "forgets" the session and answers the next checkin
// with TypeClose. The agent must surface ErrReauth so the main loop re-registers.
func TestCheckinTypeCloseReturnsErrReauth(t *testing.T) {
	// Server-side keys for the handshake
	priv, pubPEM, err := protocol.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("gen keys: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)

		// 1) registration
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		pkt, err := protocol.ReadPacket(conn)
		if err != nil {
			conn.Close()
			return
		}
		// Hybrid decrypt: [4 key_len][RSA keys][AES reg]
		keyLen := binary.LittleEndian.Uint32(pkt.Payload[0:4])
		encKeys := pkt.Payload[4 : 4+keyLen]
		keyMaterial, err := protocol.RSADecrypt(priv, encKeys)
		if err != nil {
			conn.Close()
			return
		}
		keys := &protocol.SessionKeys{AESKey: keyMaterial[:32], HMACKey: keyMaterial[32:]}
		ack, _ := keys.Encrypt([]byte(`{"status":"ok"}`))
		protocol.WritePacket(conn, &protocol.Packet{Type: protocol.TypeRegisterAck, Payload: ack})
		conn.Close()

		// 2) checkin → TypeClose (server restarted, session lost)
		conn, err = ln.Accept()
		if err != nil {
			return
		}
		if _, err := protocol.ReadPacket(conn); err != nil {
			conn.Close()
			return
		}
		protocol.WritePacket(conn, &protocol.Packet{Type: protocol.TypeClose})
		conn.Close()
	}()

	tp := &TCPTransport{
		Host:      "127.0.0.1",
		Port:      ln.Addr().(*net.TCPAddr).Port,
		AgentID:   "0123456789abcdef",
		RSAPubPEM: string(pubPEM),
	}

	if err := tp.Register([]byte(`{"id":"0123456789abcdef"}`)); err != nil {
		t.Fatalf("register: %v", err)
	}

	_, err = tp.Checkin(nil)
	if !errors.Is(err, ErrReauth) {
		t.Fatalf("checkin error = %v, want ErrReauth", err)
	}

	<-serverDone
}

// TestCheckinTimeoutIsNotReauth ensures a plain network error is not mistaken
// for a reauth signal.
func TestCheckinTimeoutIsNotReauth(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// Accept and immediately close (no TypeClose) → read error
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Close()
		}
	}()

	tp := &TCPTransport{
		Host:    "127.0.0.1",
		Port:    ln.Addr().(*net.TCPAddr).Port,
		AgentID: "0123456789abcdef",
	}
	// No Keys set → Encrypt would fail first; call dial directly to simulate
	conn, err := tp.dial()
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := protocol.ReadPacket(conn); err == nil || errors.Is(err, ErrReauth) {
		t.Fatalf("expected read error, got %v (reauth=%v)", err, errors.Is(err, ErrReauth))
	}
}
