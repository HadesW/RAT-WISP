package listener

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"wispp/protocol"
	"wispp/server/internal/core"
)

func newCore(t *testing.T) Core {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return Core{
		Hub: core.NewHub(nil), PSK: "test-psk", Priv: priv,
		SleepMS: 1000, Jitter: 10, Project: "default",
	}
}

func newServer(hl *HTTPListener) *httptest.Server {
	return httptest.NewServer(hl.Handler())
}

func mkSender(t *testing.T, ts *httptest.Server) func(*protocol.Envelope) (*protocol.Envelope, error) {
	t.Helper()
	return func(e *protocol.Envelope) (*protocol.Envelope, error) {
		return doEnvRaw(t, ts, e.Marshal()), nil
	}
}

func doRaw(t *testing.T, ts *httptest.Server, body []byte) (int, []byte) {
	t.Helper()
	resp, err := ts.Client().Post(ts.URL+"/submit", "application/octet-stream", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func doEnvRaw(t *testing.T, ts *httptest.Server, body []byte) *protocol.Envelope {
	t.Helper()
	resp, err := ts.Client().Post(ts.URL+"/submit", "application/octet-stream", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	env, err := protocol.ReadEnvelope(b)
	if err != nil {
		t.Fatalf("bad envelope response (%d): %v / %s", resp.StatusCode, err, b)
	}
	return env
}

// registerRoundTrip performs a full register over any transport for reuse.
func registerRoundTrip(t *testing.T, send func(*protocol.Envelope) (*protocol.Envelope, error), l Core, agent string, psk string) (*protocol.SessionKey, protocol.RegisterAck) {
	t.Helper()
	sk, err := protocol.NewSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := protocol.WrapSessionKey(&l.Priv.PublicKey, sk)
	if err != nil {
		t.Fatal(err)
	}
	reg, _ := protocol.NewPlainEnvelope(protocol.MsgRegister, agent, protocol.RegisterInfo{
		Agent: agent, System: protocol.SystemInfo{Hostname: "h", OS: "linux", Arch: "amd64", User: "u"},
		WrappedKey: wrapped, PSKProof: protocol.PSKProof(psk, agent, sk.ID[:]),
	})
	resp, err := send(reg)
	if err != nil {
		t.Fatal(err)
	}
	var ack protocol.RegisterAck
	if err := resp.DecodePlain(&ack); err != nil {
		t.Fatal(err)
	}
	return sk, ack
}

func TestFullHandshake(t *testing.T) {
	l := newCore(t)
	hl := &HTTPListener{Core: l, Profile: protocol.DefaultProfile()}
	ts := httptest.NewServer(hl.Handler())
	defer ts.Close()

	// wrong PSK now gets the camo 404 (plan P6: never echo psk failures)
	badKey, err := protocol.NewSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	badWrapped, err := protocol.WrapSessionKey(&l.Priv.PublicKey, badKey)
	if err != nil {
		t.Fatal(err)
	}
	badReg, _ := protocol.NewPlainEnvelope(protocol.MsgRegister, "aabbccdd", protocol.RegisterInfo{
		Agent: "aabbccdd", System: protocol.SystemInfo{Hostname: "h", OS: "linux", Arch: "amd64", User: "u"},
		WrappedKey: badWrapped, PSKProof: protocol.PSKProof("wrong-psk", "aabbccdd", badKey.ID[:]),
	})
	status, body := doRaw(t, ts, badReg.Marshal())
	if status != http.StatusNotFound || bytes.Contains(body, []byte("psk")) {
		t.Fatalf("psk failure must camo: %d %s", status, body)
	}
	if _, ok := l.Hub.Key("aabbccdd"); ok {
		t.Fatal("session created despite PSK failure")
	}

	sk, ack := registerRoundTrip(t, func(e *protocol.Envelope) (*protocol.Envelope, error) {
		return doEnvRaw(t, ts, e.Marshal()), nil
	}, l, "aabbccdd", l.PSK)
	if !ack.OK || ack.SleepMS != 1000 || ack.ServerNow == 0 {
		t.Fatalf("register failed: %+v", ack)
	}
	if ack.Proto != protocol.ProtocolVersion || len(ack.Caps) == 0 {
		t.Fatalf("P6 negotiation missing: %+v", ack)
	}

	// P6: nonce-carrying register works once; a replay of the same envelope is
	// refused, as is an out-of-window timestamp.
	key2, err := protocol.NewSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	w2, err := protocol.WrapSessionKey(&l.Priv.PublicKey, key2)
	if err != nil {
		t.Fatal(err)
	}
	goodReg, _ := protocol.NewPlainEnvelope(protocol.MsgRegister, "aabbccdd", protocol.RegisterInfo{
		Agent: "aabbccdd", System: protocol.SystemInfo{Hostname: "h", OS: "linux", Arch: "amd64", User: "u"},
		WrappedKey: w2, PSKProof: protocol.PSKProof(l.PSK, "aabbccdd", key2.ID[:]),
		TS:    time.Now().Unix(),
		Nonce: "test-nonce-http-0001",
		Proto: protocol.ProtocolVersion,
	})
	if status, body := doRaw(t, ts, goodReg.Marshal()); status == http.StatusNotFound {
		t.Fatalf("fresh register rejected: %s", body)
	}
	if status, _ := doRaw(t, ts, goodReg.Marshal()); status != http.StatusNotFound {
		t.Fatal("replayed register nonce accepted")
	}
	skewed, _ := protocol.NewPlainEnvelope(protocol.MsgRegister, "aabbccdd", protocol.RegisterInfo{
		Agent: "aabbccdd", System: protocol.SystemInfo{Hostname: "h", OS: "linux", Arch: "amd64", User: "u"},
		WrappedKey: w2, PSKProof: protocol.PSKProof(l.PSK, "aabbccdd", key2.ID[:]),
		TS:    time.Now().Unix() - 4000,
		Nonce: "test-nonce-http-skew",
		Proto: protocol.ProtocolVersion,
	})
	if status, _ := doRaw(t, ts, skewed.Marshal()); status != http.StatusNotFound {
		t.Fatal("skewed register accepted")
	}
	future, _ := protocol.NewPlainEnvelope(protocol.MsgRegister, "eeffffff", protocol.RegisterInfo{
		Agent: "eeffffff", System: protocol.SystemInfo{Hostname: "h", OS: "linux", Arch: "amd64", User: "u"},
		WrappedKey: w2, PSKProof: protocol.PSKProof(l.PSK, "eeffffff", key2.ID[:]),
		Proto: protocol.ProtocolVersion + 1,
	})
	var ack2 protocol.RegisterAck
	if env := doEnvRaw(t, ts, future.Marshal()); env.DecodePlain(&ack2) != nil || ack2.OK || ack2.Reason != "proto" {
		t.Fatalf("future proto must refuse explicitly: %+v", ack2)
	}

	send := func(e *protocol.Envelope) (*protocol.Envelope, error) {
		return doEnvRaw(t, ts, e.Marshal()), nil
	}

	// checkin with empty queue -> sealed null
	ck, _ := protocol.NewSealedEnvelope(protocol.MsgCheckin, "aabbccdd", sk, protocol.Heartbeat{Seq: 1, UptimeMS: 100})
	var none *protocol.Task
	resp, err := send(ck)
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.OpenSealed(sk, &none); err != nil {
		t.Fatal(err)
	}
	if none != nil {
		t.Fatal("expected null task")
	}

	// enqueue -> next checkin carries it
	if _, err := l.Hub.Enqueue("aabbccdd", protocol.CmdShell, protocol.ShellArgs{Command: "id"}); err != nil {
		t.Fatal(err)
	}
	ck2, _ := protocol.NewSealedEnvelope(protocol.MsgCheckin, "aabbccdd", sk, protocol.Heartbeat{Seq: 2, UptimeMS: 200})
	var task *protocol.Task
	resp2, err := send(ck2)
	if err != nil {
		t.Fatal(err)
	}
	if err := resp2.OpenSealed(sk, &task); err != nil {
		t.Fatal(err)
	}
	if task == nil || task.Cmd != protocol.CmdShell {
		t.Fatalf("expected shell task, got %+v", task)
	}

	resEnv, _ := protocol.NewSealedEnvelope(protocol.MsgResult, "aabbccdd", sk,
		protocol.TaskResult{TaskID: task.ID, OK: true, Output: "uid=0"})
	if _, err := send(resEnv); err != nil {
		t.Fatal(err)
	}
	recs := l.Hub.Tasks("aabbccdd", "")
	if len(recs) != 1 || recs[0].Status != protocol.TaskCompleted {
		t.Fatalf("bad bookkeeping: %+v", recs)
	}
	s := l.Hub.Sessions("default")[0]
	if s.Status != protocol.StatusOnline || s.Seq != 2 {
		t.Fatalf("session state: %+v", s)
	}
}

func TestTamperedCheckinRejected(t *testing.T) {
	l := newCore(t)
	hl := &HTTPListener{Core: l, Profile: protocol.DefaultProfile()}
	ts := httptest.NewServer(hl.Handler())
	defer ts.Close()
	sk, _ := protocol.NewSessionKey()
	l.Hub.Register("cafe1234", "default", "tst", sk, protocol.SystemInfo{})

	ck, _ := protocol.NewSealedEnvelope(protocol.MsgCheckin, "cafe1234", sk, protocol.Heartbeat{Seq: 1})
	ck.Data = append([]byte("z"), ck.Data[1:]...)
	resp, _ := ts.Client().Post(ts.URL+"/submit", "application/octet-stream", bytes.NewReader(ck.Marshal()))
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("tampered checkin got %d, want 404 camo", resp.StatusCode)
	}
}

// TestMalleableRoundTrip runs the whole flow through the github-api profile:
// envelope in a custom header, URI placeholders, templated JSON responses.
func TestMalleableRoundTrip(t *testing.T) {
	l := newCore(t)
	prof := protocol.BuiltinProfiles()[1] // github-api
	hl := &HTTPListener{Core: l, Profile: prof}
	ts := httptest.NewServer(hl.Handler())
	defer ts.Close()

	send := func(e *protocol.Envelope) (*protocol.Envelope, error) {
		req, err := prof.ApplyAgentRequest(ts.URL, prof.PickUA(), e.Marshal())
		if err != nil {
			return nil, err
		}
		resp, err := ts.Client().Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return prof.ParseResponse(body)
	}

	// pubkey bootstrap
	pq, _ := protocol.NewPlainEnvelope(protocol.MsgPubkey, "", nil)
	resp, err := send(pq)
	if err != nil {
		t.Fatal(err)
	}
	var pk protocol.PubkeyInfo
	if err := resp.DecodePlain(&pk); err != nil || pk.PEM == "" {
		t.Fatalf("pubkey bootstrap: %v %s", err, pk.PEM)
	}

	sk, ack := registerRoundTrip(t, send, l, "ff11ee22", l.PSK)
	if !ack.OK {
		t.Fatal("malleable register rejected")
	}
	ck, _ := protocol.NewSealedEnvelope(protocol.MsgCheckin, "ff11ee22", sk, protocol.Heartbeat{Seq: 9})
	resp, err = send(ck)
	if err != nil {
		t.Fatal(err)
	}
	var none *protocol.Task
	if err := resp.OpenSealed(sk, &none); err != nil {
		t.Fatal(err)
	}
	if none != nil {
		t.Fatal("expected null")
	}

	// wrong-method/wrong-path probes must look like the profile's 404 JSON
	bad, _ := http.NewRequest(http.MethodGet, ts.URL+"/definitely-not-it", nil)
	r, err := ts.Client().Do(bad)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	body, _ := io.ReadAll(r.Body)
	if r.StatusCode != http.StatusNotFound || !bytes.Contains(body, []byte("documentation_url")) {
		t.Fatalf("camo 404 broken: %d %s", r.StatusCode, body)
	}
}

// TestTCPListener exercises register/checkin/task/result over framed TCP.
func TestTCPListener(t *testing.T) {
	l := newCore(t)
	tcpL := &TCPListener{Core: l}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = tcpL.Serve(ln) }()
	defer tcpL.Close()

	addr := ln.Addr().String()
	dialSend := func(e *protocol.Envelope) (*protocol.Envelope, error) {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if err := protocol.WritePacket(c, &protocol.Packet{Type: protocol.TypeEnvelope, Payload: e.Marshal()}); err != nil {
			return nil, err
		}
		pkt, err := protocol.ReadPacket(c)
		if err != nil {
			return nil, err
		}
		if pkt.Type != protocol.TypeEnvelope {
			return nil, err
		}
		return protocol.ReadEnvelope(pkt.Payload)
	}

	// pubkey over request-key frame
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.WritePacket(c, &protocol.Packet{Type: protocol.TypeRequestKey}); err != nil {
		t.Fatal(err)
	}
	pkt, err := protocol.ReadPacket(c)
	c.Close()
	if err != nil || pkt.Type != protocol.TypeServerKey {
		t.Fatalf("key bootstrap: %v %+v", err, pkt)
	}
	if _, err := protocol.DecodePublicKeyPEM(pkt.Payload); err != nil {
		t.Fatal(err)
	}

	sk, ack := registerRoundTrip(t, dialSend, l, "1234abcd", l.PSK)
	if !ack.OK {
		t.Fatalf("tcp register rejected: %+v", ack)
	}
	if _, err := l.Hub.Enqueue("1234abcd", protocol.CmdSysinfo, nil); err != nil {
		t.Fatal(err)
	}
	ck, _ := protocol.NewSealedEnvelope(protocol.MsgCheckin, "1234abcd", sk, protocol.Heartbeat{Seq: 1})
	resp, err := dialSend(ck)
	if err != nil {
		t.Fatal(err)
	}
	var task *protocol.Task
	if err := resp.OpenSealed(sk, &task); err != nil {
		t.Fatal(err)
	}
	if task == nil || task.Cmd != protocol.CmdSysinfo {
		t.Fatalf("tcp task: %+v", task)
	}
	rs, _ := protocol.NewSealedEnvelope(protocol.MsgResult, "1234abcd", sk,
		protocol.TaskResult{TaskID: task.ID, OK: true, Output: `{"hostname":"h"}`})
	if _, err := dialSend(rs); err != nil {
		t.Fatal(err)
	}
	recs := l.Hub.Tasks("1234abcd", "")
	if len(recs) != 1 || recs[0].Status != protocol.TaskCompleted {
		t.Fatalf("tcp bookkeeping: %+v", recs)
	}
}
