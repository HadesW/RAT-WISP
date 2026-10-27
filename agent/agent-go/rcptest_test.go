package main

import (
	"encoding/json"
	"net"
	"testing"

	"wispp/protocol"
)

// testRCPHandshake plays the server side of the v2 challenge-response for
// tests that script a fake hub around the real agent rcpLoop.
func testRCPHandshake(t *testing.T, conn net.Conn, psk, agent string) {
	t.Helper()
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
	key, ok := protocol.RCPKeyFromToken(protocol.RCPToken(psk, agent))
	if !ok || hello.Agent != agent {
		t.Fatal("hub-side hello invalid")
	}
	if hello.Proof != protocol.RCPAgentProof(key, agent, nonce, hello.Nonce) {
		t.Fatal("hub-side agent proof failed")
	}
	ack, _ := json.Marshal(protocol.RCPAck{OK: true,
		Proof: protocol.RCPServerProof(key, agent, nonce, hello.Nonce)})
	if err := protocol.WriteRCPFrame(conn, &protocol.RCPFrame{Kind: protocol.RCPKindAck, Payload: ack}); err != nil {
		t.Fatal(err)
	}
}
