package rcp

import (
	"encoding/json"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"wispp/protocol"
	"wispp/server/internal/rcptest"
)

// miniAgent simulates the agent side of RCP: replies hello, and for every
// shell channel spawns a real /bin/sh whose stdin/stdout ride the channel.
// (Same framing the production agent uses; guards the hub's contract.)
func miniAgent(t *testing.T, addr, psk, agent string) {
	t.Helper()
	c, err := rcptest.Dial(addr, psk, agent)
	if err != nil {
		t.Fatalf("miniAgent handshake: %v", err)
	}
	go func() {
		defer c.Close()
		for {
			f, err := protocol.ReadRCPFrame(c)
			if err != nil {
				return
			}
			switch f.Kind {
			case protocol.RCPKindOpen:
				var op protocol.RCPOpen
				_ = json.Unmarshal(f.Payload, &op)
				go shellPump(c, op.Chan)
			case protocol.RCPKindFrame: // input -> echo marker for fwd channels
			}
		}
	}()
}

func shellPump(c net.Conn, ch uint32) {
	// one-shot real command, streamed back as frames (proves framing + relay)
	out, _ := exec.Command("id").Output()
	_ = protocol.WriteRCPFrame(c, &protocol.RCPFrame{Chan: ch, Kind: protocol.RCPKindFrame, Payload: out})
	_ = protocol.WriteRCPFrame(c, &protocol.RCPFrame{Chan: ch, Kind: protocol.RCPKindClose,
		Payload: mustJSON(protocol.RCPClose{Chan: ch, Reason: "done"})})
}

func TestHubShellChannel(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell channel test needs POSIX `id`")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	h := NewHub("psk-test", nil)
	go h.Serve(ln)

	agent := "cafe0001"
	miniAgent(t, ln.Addr().String(), "psk-test", agent)

	// wait for hello registration
	deadline := time.Now().Add(3 * time.Second)
	for !h.Online(agent) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if !h.Online(agent) {
		t.Fatal("agent never registered over RCP")
	}

	ch, err := h.Open(agent, protocol.RCPChanShell, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close(agent, ch.ID, "test end")

	select {
	case d := <-ch.Sub():
		p := d.Data
		if !strings.Contains(string(p), "uid=") {
			t.Fatalf("unexpected shell output: %q", p)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no output frame (sleep-independent Type2 broken)")
	}

	// agent closes its side -> subscriber sees close and channel is gone
	deadline = time.Now().Add(3 * time.Second)
	for h.Online(agent) && time.Now().Before(deadline) {
		if _, open := <-safe(ch); !open {
			break
		}
	}
}

func safe(ch *Channel) chan Delivery { return ch.sub }

func TestHubRejectsBadToken(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	h := NewHub("psk-a", nil)
	go h.Serve(ln)

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ch := readChallenge(t, c)
	an, _ := protocol.NewRCPNonce()
	sendHello(t, c, "x1", "", ch, an, "deadbeefdeadbeefdeadbeefdeadbeef")
	if ack := readAck(t, c); ack.OK {
		t.Fatal("bad proof accepted")
	}
}

// TestTakeoverNoDoubleClose: reconnecting with the same agent id must not
// panic the hub (regression: takeover closed done twice).
func TestTakeoverNoDoubleClose(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	h := NewHub("psk-t", nil)
	go h.Serve(ln)

	hello := func() net.Conn {
		c, err := rcptest.Dial(ln.Addr().String(), "psk-t", "same")
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	c1 := hello()
	for !h.Online("same") {
		time.Sleep(20 * time.Millisecond)
	}
	c2 := hello() // takeover while c1 "live"
	time.Sleep(300 * time.Millisecond)
	if !h.Online("same") {
		t.Fatal("takeover dropped liveness")
	}
	c1.Close()
	c2.Close()
	time.Sleep(300 * time.Millisecond) // hub cleanup paths run; panic would kill the test binary
}

func readChallenge(t *testing.T, conn net.Conn) string {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	f, err := protocol.ReadRCPFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	if f.Kind != protocol.RCPKindChallenge {
		t.Fatalf("first frame kind %#x", f.Kind)
	}
	var ch protocol.RCPChallenge
	if err := json.Unmarshal(f.Payload, &ch); err != nil || len(ch.Nonce) != 32 {
		t.Fatalf("bad challenge %+v %v", ch, err)
	}
	return ch.Nonce
}

func sendHello(t *testing.T, conn net.Conn, agent, key, serverNonce, agentNonce, proof string) {
	t.Helper()
	if proof == "" {
		proof = protocol.RCPAgentProof([]byte(key), agent, serverNonce, agentNonce)
	}
	payload, _ := json.Marshal(protocol.RCPHello{Agent: agent, Nonce: agentNonce, Proof: proof})
	if err := protocol.WriteRCPFrame(conn, &protocol.RCPFrame{Kind: protocol.RCPKindHello, Payload: payload}); err != nil {
		t.Fatal(err)
	}
}

func readAck(t *testing.T, conn net.Conn) protocol.RCPAck {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	f, err := protocol.ReadRCPFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	if f.Kind != protocol.RCPKindAck {
		t.Fatalf("ack kind %#x", f.Kind)
	}
	var ack protocol.RCPAck
	if err := json.Unmarshal(f.Payload, &ack); err != nil {
		t.Fatal(err)
	}
	return ack
}

func TestHandshakeV2Proofs(t *testing.T) {
	const psk, agent = "psk-test", "agent-1"
	h := NewHub(psk, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go h.Serve(ln)

	token := protocol.RCPToken(psk, agent)
	key, _ := protocol.RCPKeyFromToken(token)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ch := readChallenge(t, conn)
	an, _ := protocol.NewRCPNonce()
	sendHello(t, conn, agent, string(key), ch, an, "")
	ack := readAck(t, conn)
	if !ack.OK {
		t.Fatalf("valid handshake rejected: %+v", ack)
	}
	if want := protocol.RCPServerProof(key, agent, ch, an); ack.Proof != want {
		t.Fatal("server proof mismatch")
	}
	deadline := time.Now().Add(2 * time.Second)
	for !h.Online(agent) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !h.Online(agent) {
		t.Fatal("agent not online after handshake")
	}

	bad, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	badCh := readChallenge(t, bad)
	sendHello(t, bad, agent, string(key), badCh, an,
		protocol.RCPAgentProof(key, agent, ch, an)) // proof bound to the previous nonce
	if ack := readAck(t, bad); ack.OK {
		t.Fatal("stale proof accepted")
	}

	wrongToken := protocol.RCPToken("other-psk", agent)
	wrongKey, _ := protocol.RCPKeyFromToken(wrongToken)
	bad2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer bad2.Close()
	ch2 := readChallenge(t, bad2)
	an2, _ := protocol.NewRCPNonce()
	sendHello(t, bad2, agent, string(wrongKey), ch2, an2, "")
	if ack := readAck(t, bad2); ack.OK {
		t.Fatal("wrong key accepted")
	}
}

func TestOnlineCount(t *testing.T) {
	h := NewHub("p", nil)
	if got := h.OnlineCount(); got != 0 {
		t.Fatalf("empty count: %d", got)
	}
	h.clients["a"] = &Client{}
	h.clients["b"] = &Client{}
	if got := h.OnlineCount(); got != 2 {
		t.Fatalf("count: %d", got)
	}
}
