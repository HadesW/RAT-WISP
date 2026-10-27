package listener

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"wispp/protocol"
	"wispp/server/internal/core"
	"wispp/server/internal/stage"
)

// TestQUICRegister: full Type1 handshake (pubkey/register/checkin/result) over
// QUIC streams with a self-signed cert and skipped verification — the plan P6
// loopback acceptance (agent side uses the same framing in transport/quic.go).
func TestQUICRegister(t *testing.T) {
	hub := core.NewHub(nil)
	key := newTestKey(t)

	// free UDP port for the listener
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close()

	mgr := NewManager(Deps{Hub: hub, PSK: "quicsk", Priv: key,
		Stage: stage.New(time.Minute), DataDir: t.TempDir()}, nil)
	crt, crtKey := mgr.selfSigned(addr, "")
	if crt == "" {
		t.Fatal("selfSigned failed")
	}

	ql := &QUICListener{Addr: addr}
	ql.Core.ID = "quic1"
	ql.Core.Hub, ql.Core.PSK, ql.Core.Priv = hub, "quicsk", key
	ql.Core.Stage = stage.New(time.Minute)
	go func() { _ = ql.ListenAndServe(crt, crtKey) }()
	defer ql.Close()

	tlsCfg := &tls.Config{NextProtos: []string{"wisp"}, InsecureSkipVerify: true}
	qcfg := &quic.Config{MaxIdleTimeout: 20 * time.Second}

	dialSend := func(e *protocol.Envelope) (*protocol.Envelope, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := quic.DialAddr(ctx, addr, tlsCfg, qcfg)
		if err != nil {
			return nil, err
		}
		defer conn.CloseWithError(0, "")
		stream, err := conn.OpenStreamSync(ctx)
		if err != nil {
			return nil, err
		}
		defer stream.Close()
		_ = stream.SetDeadline(time.Now().Add(10 * time.Second))
		if err := protocol.WritePacket(stream, &protocol.Packet{Type: protocol.TypeEnvelope, Payload: e.Marshal()}); err != nil {
			return nil, err
		}
		// half-close: request complete, server may answer now
		_ = stream.Close()
		pkt, err := protocol.ReadPacket(stream)
		if err != nil {
			return nil, err
		}
		if pkt.Type != protocol.TypeEnvelope {
			t.Fatalf("quic: unexpected packet type %d", pkt.Type)
		}
		return protocol.ReadEnvelope(pkt.Payload)
	}

	// wait for bind (ListenAndServe runs in a goroutine); short dial timeouts
	// because a not-yet-bound UDP port only fails after the handshake budget.
	deadline := time.Now().Add(5 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		c, err := quic.DialAddr(ctx, addr, tlsCfg, qcfg)
		cancel()
		if c != nil {
			_ = c.CloseWithError(0, "")
		}
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("quic listener never came up: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// pubkey bootstrap over the plain envelope channel
	pkEnv, _ := protocol.NewPlainEnvelope(protocol.MsgPubkey, "", nil)
	resp, err := dialSend(pkEnv)
	if err != nil {
		t.Fatalf("pubkey: %v", err)
	}
	var pk protocol.PubkeyInfo
	if err := resp.DecodePlain(&pk); err != nil || pk.PEM == "" {
		t.Fatalf("pubkey payload: %v %+v", err, pk)
	}
	if _, err := protocol.DecodePublicKeyPEM([]byte(pk.PEM)); err != nil {
		t.Fatal(err)
	}

	sk, ack := registerRoundTrip(t, dialSend, ql.Core, "quicagent01", "quicsk")
	if !ack.OK {
		t.Fatalf("quic register rejected: %+v", ack)
	}
	if ack.Proto != protocol.ProtocolVersion {
		t.Fatalf("quic proto negotiation: %+v", ack)
	}

	// listener attribution survives the transport swap
	if sess := hub.Sessions(""); len(sess) == 0 || sess[0].Listener != "quic1" {
		t.Fatalf("listener attribution lost over quic: %+v", sess)
	}

	if _, err := hub.Enqueue("quicagent01", protocol.CmdSysinfo, nil); err != nil {
		t.Fatal(err)
	}
	ck, _ := protocol.NewSealedEnvelope(protocol.MsgCheckin, "quicagent01", sk, protocol.Heartbeat{Seq: 1})
	resp, err = dialSend(ck)
	if err != nil {
		t.Fatal(err)
	}
	var task *protocol.Task
	if err := resp.OpenSealed(sk, &task); err != nil || task == nil || task.Cmd != protocol.CmdSysinfo {
		t.Fatalf("quic task: %v %+v", err, task)
	}
	rs, _ := protocol.NewSealedEnvelope(protocol.MsgResult, "quicagent01", sk,
		protocol.TaskResult{TaskID: task.ID, OK: true, Output: `{"hostname":"q"}`})
	if _, err := dialSend(rs); err != nil {
		t.Fatal(err)
	}
	recs := hub.Tasks("quicagent01", "")
	if len(recs) != 1 || recs[0].Status != protocol.TaskCompleted {
		t.Fatalf("quic bookkeeping: %+v", recs)
	}

	// camo silence: a bad-PSK register gets no reply at all (stream closes
	// with zero bytes), matching the TCP path's failed-handshake behavior.
	badKey := newTestKey(t)
	badSk, _ := protocol.NewSessionKey()
	badWrap, _ := protocol.WrapSessionKey(&badKey.PublicKey, badSk)
	badReg, _ := protocol.NewPlainEnvelope(protocol.MsgRegister, "quicbad01", protocol.RegisterInfo{
		Agent: "quicbad01", System: protocol.SystemInfo{Hostname: "x"},
		WrappedKey: badWrap, PSKProof: protocol.PSKProof("wrong-psk", "quicbad01", badSk.ID[:]),
	})
	if env, err := dialSend(badReg); err == nil {
		var a protocol.RegisterAck
		_ = json.Unmarshal(env.Data, &a)
		t.Fatalf("bad PSK must get silence, got: %+v", a)
	}
}
