package listener

import (
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"
	"wispp/protocol"
	"wispp/server/internal/core"
	"wispp/server/internal/stage"
)

// TestKCPRegister: full Type1 handshake over KCP (nodelay+stream) using the
// managed listener stack.
func TestKCPRegister(t *testing.T) {
	hub := core.NewHub(nil)
	key := newTestKey(t)
	ln, err := kcp.ListenWithOptions("127.0.0.1:0", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	tl := &TCPListener{Addr: ln.Addr().String()}
	tl.Core.ID = "kcp1"
	tl.Core.Hub, tl.Core.PSK, tl.Core.Priv = hub, "kcppsk", key
	tl.Core.Stage = stage.New(time.Minute)
	kln := &kcpListener{Listener: ln}
	go tl.Serve(kln)
	defer tl.Close()

	conn, err := kcp.DialWithOptions(ln.Addr().String(), nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetNoDelay(1, 10, 2, 1)
	conn.SetStreamMode(true)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	sk, _ := protocol.NewSessionKey()
	wrapped, _ := protocol.WrapSessionKey(&key.PublicKey, sk)
	reg, _ := protocol.NewPlainEnvelope(protocol.MsgRegister, "kcpagent01", protocol.RegisterInfo{
		Agent: "kcpagent01", System: protocol.SystemInfo{Hostname: "K1"},
		WrappedKey: wrapped, PSKProof: protocol.PSKProof("kcppsk", "kcpagent01", sk.ID[:]),
	})
	if err := protocol.WritePacket(conn, &protocol.Packet{Type: protocol.TypeEnvelope, Payload: reg.Marshal()}); err != nil {
		t.Fatal(err)
	}
	pkt, err := protocol.ReadPacket(conn)
	if err != nil {
		t.Fatal(err)
	}
	env, err := protocol.ReadEnvelope(pkt.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var ack protocol.RegisterAck
	_ = json.Unmarshal(env.Data, &ack)
	if !ack.OK {
		t.Fatal("kcp register rejected")
	}
	if hub.Sessions("")[0].Listener != "kcp1" {
		t.Fatal("listener attribution lost over kcp")
	}
	// checkin roundtrip
	ck, _ := protocol.NewSealedEnvelope(protocol.MsgCheckin, "kcpagent01", sk, protocol.Heartbeat{Seq: 1})
	_ = protocol.WritePacket(conn, &protocol.Packet{Type: protocol.TypeEnvelope, Payload: ck.Marshal()})
	pkt, err = protocol.ReadPacket(conn)
	if err != nil || pkt.Type != protocol.TypeEnvelope {
		t.Fatalf("checkin: %v", err)
	}
	env, _ = protocol.ReadEnvelope(pkt.Payload)
	var none *protocol.Task
	if err := env.OpenSealed(sk, &none); err != nil || none != nil {
		t.Fatalf("checkin payload: %v %+v", err, none)
	}
}

func newTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := protocol.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
