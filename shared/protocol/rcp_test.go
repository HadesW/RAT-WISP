package protocol

import (
	"bytes"
	"testing"
)

func TestRCPFrameRoundTrip(t *testing.T) {
	in := &RCPFrame{Chan: 42, Kind: RCPKindFrame, Seq: 7, Payload: []byte("typed input\r")}
	var buf bytes.Buffer
	if err := WriteRCPFrame(&buf, in); err != nil {
		t.Fatal(err)
	}
	out, err := ReadRCPFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if out.Chan != in.Chan || out.Kind != in.Kind || out.Seq != in.Seq || !bytes.Equal(out.Payload, in.Payload) {
		t.Fatalf("round trip: %+v", out)
	}
}

func TestRCPFrameEmptyAndLarge(t *testing.T) {
	var buf bytes.Buffer
	_ = WriteRCPFrame(&buf, &RCPFrame{Kind: RCPKindPing})
	f, err := ReadRCPFrame(&buf)
	if err != nil || len(f.Payload) != 0 {
		t.Fatalf("empty frame: %v %+v", err, f)
	}
	if err := WriteRCPFrame(&buf, &RCPFrame{Payload: make([]byte, RCPMaxFrame+1)}); err != ErrRCPTooLarge {
		t.Fatal("oversize not rejected on write")
	}
}

func TestRCPFrameGuards(t *testing.T) {
	var buf bytes.Buffer
	_ = WriteRCPFrame(&buf, &RCPFrame{Kind: RCPKindAck})
	raw := buf.Bytes()
	magic := append([]byte(nil), raw...)
	magic[0] = 'X'
	if _, err := ReadRCPFrame(bytes.NewReader(magic)); err != ErrRCPMagic {
		t.Fatal("bad magic accepted")
	}
	if _, err := ReadRCPFrame(bytes.NewReader(raw[:RCPHeaderLen-2])); err == nil {
		t.Fatal("truncated header accepted")
	}
	size := append([]byte(nil), raw...)
	size[15], size[16], size[17], size[18] = 0xff, 0xff, 0xff, 0xff
	if _, err := ReadRCPFrame(bytes.NewReader(size)); err != ErrRCPTooLarge {
		t.Fatal("oversize not rejected on read")
	}
}

func TestRCPProofsAndKey(t *testing.T) {
	key := RCPKey("psk-x", "agent-1")
	if len(key) != 16 {
		t.Fatalf("key len %d", len(key))
	}
	tok := RCPToken("psk-x", "agent-1")
	if len(tok) != 32 {
		t.Fatalf("token shape: %s", tok)
	}
	kb, ok := RCPKeyFromToken(tok)
	if !ok || !bytes.Equal(kb, key) {
		t.Fatal("token/key mismatch")
	}
	if _, ok := RCPKeyFromToken("not-hex"); ok {
		t.Fatal("bad token accepted")
	}
	if bytes.Equal(key, RCPKey("psk-y", "agent-1")) || bytes.Equal(key, RCPKey("psk-x", "agent-2")) {
		t.Fatal("foreign key accepted")
	}
	s, err := NewRCPNonce()
	if err != nil || len(s) != 32 {
		t.Fatal("nonce", s, err)
	}
	a, _ := NewRCPNonce()
	ap := RCPAgentProof(key, "agent-1", s, a)
	sp := RCPServerProof(key, "agent-1", s, a)
	if ap == sp {
		t.Fatal("agent and server proofs must differ")
	}
	if RCPAgentProof(key, "agent-1", s, "ffffffffffffffffffffffffffffffff") == ap {
		t.Fatal("agent nonce not bound")
	}
	other := RCPKey("psk-x", "agent-2")
	if RCPAgentProof(other, "agent-1", s, a) == ap {
		t.Fatal("agent id not bound to key")
	}
	if len(RCPSessionKey(key, "agent-1", s, a)) != 32 {
		t.Fatal("session key length")
	}
}
