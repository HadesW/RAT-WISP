package protocol

import (
	"bytes"
	"testing"
)

func TestRCPFrameEncodeDecode(t *testing.T) {
	payload := EncodeRCPFrame(42, 1920, 1080, []byte{0xff, 0xd8, 0xff, 0x01, 0x02, 0x03})
	f, err := DecodeRCPFrame(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if f.Seq != 42 || f.W != 1920 || f.H != 1080 {
		t.Errorf("frame = %+v", f)
	}
	if !bytes.Equal(f.JPEG, []byte{0xff, 0xd8, 0xff, 0x01, 0x02, 0x03}) {
		t.Errorf("jpeg mismatch: %x", f.JPEG)
	}

	if _, err := DecodeRCPFrame([]byte{0x01, 0x02}); err == nil {
		t.Error("expected error for short frame")
	}
}

func TestRCPHelloBuildParse(t *testing.T) {
	_, pubPEM, err := GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	challenge := []byte("0123456789abcdef") // 16 bytes
	agentID := []byte("abcdef01")

	pkt, err := BuildRCPHello(agentID, challenge, pubPEM)
	if err != nil {
		t.Fatalf("build hello: %v", err)
	}
	if pkt.Type != TypeRCPHello {
		t.Errorf("type = 0x%02x, want 0x10", pkt.Type)
	}

	id, _, err := ParseRCPHello(pkt.Payload)
	if err != nil {
		t.Fatalf("parse hello: %v", err)
	}
	if !bytes.Equal(id, agentID) {
		t.Errorf("agent id = %x, want %x", id, agentID)
	}

	// Round-trip with a matching key pair
	priv2, pub2, err := GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	// Rebuild with the matching pair for a real round-trip check
	pkt2, err := BuildRCPHello(agentID, challenge, pub2)
	if err != nil {
		t.Fatal(err)
	}
	_, enc2, _ := ParseRCPHello(pkt2.Payload)
	dec, err := RSADecrypt(priv2, enc2)
	if err != nil {
		t.Fatalf("rsa decrypt: %v", err)
	}
	if !bytes.Equal(dec, challenge) {
		t.Errorf("decrypted challenge mismatch")
	}

	// Invalid short payload must fail
	if _, _, err := ParseRCPHello([]byte("short")); err == nil {
		t.Error("expected error for short hello")
	}
}
