package main

import (
	"context"
	"encoding/json"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"wispp/protocol"
)

// TestRCPShellChannel runs the real agent-side rcpSession against a fake
// teamserver hub: hello/ack -> Open(shell) -> input "id" -> output frames.
func TestRCPShellChannel(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell channel test needs POSIX `id`")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	psk := "test-psk"
	agent := "rt01"
	token := protocol.RCPToken(psk, agent)

	go rcpLoop(context.Background(), ln.Addr().String(), agent, token)

	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	nonce, err := protocol.NewRCPNonce()
	if err != nil {
		t.Fatal(err)
	}
	ch, _ := json.Marshal(protocol.RCPChallenge{Nonce: nonce})
	if err := protocol.WriteRCPFrame(conn, &protocol.RCPFrame{Kind: protocol.RCPKindChallenge, Payload: ch}); err != nil {
		t.Fatal(err)
	}
	hf, err := protocol.ReadRCPFrame(conn)
	if err != nil || hf.Kind != protocol.RCPKindHello {
		t.Fatalf("hello: %v %+v", err, hf)
	}
	var hello protocol.RCPHello
	_ = json.Unmarshal(hf.Payload, &hello)
	key, ok := protocol.RCPKeyFromToken(token)
	if !ok || hello.Agent != agent {
		t.Fatal("hub-side hello invalid")
	}
	want := protocol.RCPAgentProof(key, agent, nonce, hello.Nonce)
	if hello.Proof != want {
		t.Fatal("hub-side agent proof failed")
	}
	ack, _ := json.Marshal(protocol.RCPAck{OK: true,
		Proof: protocol.RCPServerProof(key, agent, nonce, hello.Nonce)})
	if err := protocol.WriteRCPFrame(conn, &protocol.RCPFrame{Kind: protocol.RCPKindAck, Payload: ack}); err != nil {
		t.Fatal(err)
	}

	open, _ := json.Marshal(protocol.RCPOpen{Chan: 7, Kind: protocol.RCPChanShell})
	if err := protocol.WriteRCPFrame(conn, &protocol.RCPFrame{Chan: 7, Kind: protocol.RCPKindOpen, Payload: open}); err != nil {
		t.Fatal(err)
	}
	if err := protocol.WriteRCPFrame(conn, &protocol.RCPFrame{Chan: 7, Kind: protocol.RCPKindFrame, Payload: []byte("id\n")}); err != nil {
		t.Fatal(err)
	}

	seen := ""
	for time.Now().Before(time.Now().Add(15 * time.Second)) {
		f, err := protocol.ReadRCPFrame(conn)
		if err != nil {
			t.Fatalf("frame: %v", err)
		}
		if f.Kind == protocol.RCPKindFrame && f.Chan == 7 {
			seen += string(f.Payload)
			if strings.Contains(seen, "uid=") {
				break
			}
		}
		if f.Kind == protocol.RCPKindPong {
			continue
		}
	}
	if !strings.Contains(seen, "uid=") {
		t.Fatalf("no shell output; got %q", seen[:min(len(seen), 200)])
	}
	// close must terminate the shell cleanly (agent sends its own KindClose or dies quiet)
	cl, _ := json.Marshal(protocol.RCPClose{Chan: 7})
	_ = protocol.WriteRCPFrame(conn, &protocol.RCPFrame{Chan: 7, Kind: protocol.RCPKindClose, Payload: cl})
	time.Sleep(200 * time.Millisecond)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
