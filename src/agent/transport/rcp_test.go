package transport

import (
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/xtaci/kcp-go/v5"

	"github.com/user/wisp/shared/protocol"
)

// runRCPClientTest runs the fake-server RCP test over the given transport
// ("tcp" or "kcp").
func runRCPClientTest(t *testing.T, useKCP bool) {
	t.Helper()
	priv, pubPEM, err := protocol.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keys, err := protocol.GenerateSessionKeys()
	if err != nil {
		t.Fatal(err)
	}

	var ln net.Listener
	var port int
	if useKCP {
		ln, err = kcp.ListenWithOptions("127.0.0.1:0", nil, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		port = ln.Addr().(*net.UDPAddr).Port
	} else {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port = ln.Addr().(*net.TCPAddr).Port
	}
	defer ln.Close()

	frameCh := make(chan *protocol.RCPFrame, 10)
	inputCh := make(chan string, 1)
	serverDone := make(chan struct{})

	go func() {
		defer close(serverDone)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Handshake
		hello, err := protocol.ReadPacket(conn)
		if err != nil || hello.Type != protocol.TypeRCPHello {
			return
		}
		rawID, encChallenge, err := protocol.ParseRCPHello(hello.Payload)
		if err != nil {
			return
		}
		if hex.EncodeToString(rawID) != "ab12cd3400000000" {
			return
		}
		challenge, err := protocol.RSADecrypt(priv, encChallenge)
		if err != nil {
			return
		}
		ack, err := keys.Encrypt(challenge)
		if err != nil {
			return
		}
		if err := protocol.WritePacket(conn, &protocol.Packet{Type: protocol.TypeRCPAck, Payload: ack}); err != nil {
			return
		}

		// Read three frames (payloads are encrypted with the session keys)
		for i := 0; i < 3; i++ {
			pkt, err := protocol.ReadPacket(conn)
			if err != nil {
				return
			}
			if pkt.Type == protocol.TypeRCPFrame {
				dec, err := keys.Decrypt(pkt.Payload)
				if err != nil {
					continue
				}
				f, err := protocol.DecodeRCPFrame(dec)
				if err == nil {
					frameCh <- f
				}
			}
		}

		// Push an input event back (encrypted)
		encInput, _ := keys.Encrypt([]byte(`{"type":"click","x":1,"y":2}`))
		_ = protocol.WritePacket(conn, &protocol.Packet{Type: protocol.TypeRCPInput, Payload: encInput})
		time.Sleep(100 * time.Millisecond)
	}()

	client := &RCPClient{
		Host:      "127.0.0.1",
		AgentID:   "ab12cd3400000000",
		Keys:      keys,
		RSAPubPEM: string(pubPEM),
		Capture: func(quality int) ([]byte, int, int, error) {
			return []byte{0xff, 0xd8, 0xff, 0x01}, 4, 4, nil
		},
		OnInput: func(msg string) {
			select {
			case inputCh <- msg:
			default:
			}
		},
		Quality:  45,
		Interval: 30 * time.Millisecond,
	}
	if useKCP {
		client.Proto = "kcp"
	} else {
		client.Proto = "tcp"
	}

	if err := client.Connect(port); err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()

	select {
	case f := <-frameCh:
		if f.W != 4 || f.H != 4 || len(f.JPEG) == 0 || f.Seq == 0 {
			t.Errorf("unexpected frame: %+v", f)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no frame received by fake server")
	}

	select {
	case msg := <-inputCh:
		if msg != `{"type":"click","x":1,"y":2}` {
			t.Errorf("input = %q", msg)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no input received by client")
	}

	client.Close()
	select {
	case <-serverDone:
	case <-time.After(2 * time.Second):
		t.Fatal("fake server did not finish")
	}
}

// TestRCPClientStreamAndInput runs the channel over plain TCP.
func TestRCPClientStreamAndInput(t *testing.T) {
	runRCPClientTest(t, false)
}

// TestRCPClientKCPStreamAndInput runs the same channel over KCP/UDP: the
// client must dial with the KCP transport and stream frames just as over TCP.
func TestRCPClientKCPStreamAndInput(t *testing.T) {
	runRCPClientTest(t, true)
}
