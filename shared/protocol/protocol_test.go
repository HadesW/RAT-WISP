package protocol

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func TestPacketRoundTrip(t *testing.T) {
	p := &Packet{Type: TypeRegister, Payload: []byte("hello wispp")}
	got, err := ReadPacket(bytes.NewReader(p.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != p.Type || !bytes.Equal(got.Payload, p.Payload) {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

func TestPacketRejectsBadMagic(t *testing.T) {
	bad := (&Packet{Type: TypeRegister}).Encode()
	bad[0] = 'X'
	if _, err := ReadPacket(bytes.NewReader(bad)); err == nil {
		t.Fatal("expected magic error")
	}
}

func TestPacketRejectsOversize(t *testing.T) {
	hdr := make([]byte, HeaderSize)
	copy(hdr, Magic[:])
	hdr[4] = 0xff
	hdr[5] = 0xff
	hdr[6] = 0xff
	hdr[7] = 0xff
	if _, err := ReadPacket(bytes.NewReader(hdr)); !strings.Contains(err.Error(), "too large") {
		t.Fatalf("expected too large, got %v", err)
	}
}

func newTestKey(t *testing.T) *SessionKey {
	t.Helper()
	sk, err := NewSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	return sk
}

func TestSealOpen(t *testing.T) {
	sk := newTestKey(t)
	msg := []byte(`{"seq":1,"uptime_ms":4200}`)
	blob, err := sk.Seal(msg)
	if err != nil {
		t.Fatal(err)
	}
	out, err := sk.Open(blob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, msg) {
		t.Fatalf("got %s", out)
	}
}

func TestSealOpenEmpty(t *testing.T) {
	sk := newTestKey(t)
	blob, err := sk.Seal(nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := sk.Open(blob)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Fatalf("expected empty plaintext, got %d bytes", len(out))
	}
}

func TestTamperDetected(t *testing.T) {
	sk := newTestKey(t)
	blob, _ := sk.Seal([]byte("critical data"))
	blob[len(blob)/2] ^= 0xff // flip a ciphertext byte
	if _, err := sk.Open(blob); !errors.Is(err, ErrMACMismatch) {
		t.Fatalf("expected MAC mismatch, got %v", err)
	}
	blob2, _ := sk.Seal([]byte("critical data"))
	blob2[len(blob2)-1] ^= 0x01 // flip a MAC byte
	if _, err := sk.Open(blob2); !errors.Is(err, ErrMACMismatch) {
		t.Fatalf("expected MAC mismatch on tag flip, got %v", err)
	}
}

func TestWrongKeyRejected(t *testing.T) {
	a, b := newTestKey(t), newTestKey(t)
	blob, _ := a.Seal([]byte("x"))
	if _, err := b.Open(blob); !errors.Is(err, ErrMACMismatch) {
		t.Fatalf("expected MAC mismatch with wrong key, got %v", err)
	}
}

func TestTruncatedRejected(t *testing.T) {
	sk := newTestKey(t)
	blob, _ := sk.Seal([]byte("x"))
	if _, err := sk.Open(blob[:IVSize+HMacSize-1]); !errors.Is(err, ErrSealedShort) {
		t.Fatalf("expected short error, got %v", err)
	}
}

func TestWrapUnwrapKey(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sk := newTestKey(t)
	wrapped, err := WrapSessionKey(&priv.PublicKey, sk)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnwrapSessionKey(priv, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if *got != *sk {
		t.Fatal("key material differs after wrap/unwrap")
	}
	// sealed traffic under the unwrapped key must interoperate
	blob, _ := sk.Seal([]byte("ping"))
	if _, err := got.Open(blob); err != nil {
		t.Fatal(err)
	}
}

func TestPSKProof(t *testing.T) {
	sk := newTestKey(t)
	proof := PSKProof("secret-psk", "a1b2c3", sk.ID[:])
	if !VerifyPSKProof("secret-psk", "a1b2c3", sk.ID[:], proof) {
		t.Fatal("valid proof rejected")
	}
	if VerifyPSKProof("wrong-psk", "a1b2c3", sk.ID[:], proof) {
		t.Fatal("wrong PSK accepted")
	}
	if VerifyPSKProof("secret-psk", "other-id", sk.ID[:], proof) {
		t.Fatal("agent swap accepted")
	}
}

func TestEnvelopeSealedRoundTrip(t *testing.T) {
	sk := newTestKey(t)
	hb := Heartbeat{Seq: 7, UptimeMS: 12345}
	e, err := NewSealedEnvelope(MsgCheckin, "deadbeef", sk, hb)
	if err != nil {
		t.Fatal(err)
	}
	wire := e.Marshal()
	back, err := ReadEnvelope(wire)
	if err != nil {
		t.Fatal(err)
	}
	if back.Type != MsgCheckin || back.Agent != "deadbeef" {
		t.Fatalf("header lost: %+v", back)
	}
	var out Heartbeat
	if err := back.OpenSealed(sk, &out); err != nil {
		t.Fatal(err)
	}
	if out != hb {
		t.Fatalf("payload mismatch: %+v vs %+v", out, hb)
	}
	// the wire must not contain any plaintext marker of the payload
	if bytes.Contains(wire, []byte("uptime_ms")) {
		t.Fatal("sealed envelope leaks field names")
	}
}

// TestEnvelopeZstdRoundTrip: profile-driven zstd compression of the sealed
// inner JSON (plan P6) — the `z` flag is self-describing, so a compressed
// envelope opens on any receiver that understands it, and tiny payloads stay
// uncompressed.
func TestEnvelopeZstdRoundTrip(t *testing.T) {
	sk := newTestKey(t)
	// > ZstdMinSize and highly compressible
	big := TaskResult{TaskID: "deadbeefcafe", OK: true, Exit: 0,
		Output: strings.Repeat("task output line\n", 64)}
	e, err := NewSealedEnvelopeZstd(MsgResult, "a1", sk, big, true)
	if err != nil {
		t.Fatal(err)
	}
	if !e.Z {
		t.Fatal("compressible payload not compressed")
	}
	plain, err := NewSealedEnvelopeZstd(MsgResult, "a1", sk, big, false)
	if err != nil {
		t.Fatal(err)
	}
	if plain.Z {
		t.Fatal("zstd=false must not set the flag")
	}
	// both open to the same payload regardless of the flag
	for _, env := range []*Envelope{e, plain} {
		back, err := ReadEnvelope(env.Marshal())
		if err != nil {
			t.Fatal(err)
		}
		var out TaskResult
		if err := back.OpenSealed(sk, &out); err != nil {
			t.Fatal(err)
		}
		if out != big {
			t.Fatalf("payload mismatch: %+v", out)
		}
	}
	// the compressed envelope must actually be smaller on the wire
	if len(e.Marshal()) >= len(plain.Marshal()) {
		t.Fatalf("compression did not shrink wire size: %d vs %d", len(e.Marshal()), len(plain.Marshal()))
	}
	// tiny payloads never set the flag even with zstd on
	tiny, err := NewSealedEnvelopeZstd(MsgCheckin, "a1", sk, Heartbeat{Seq: 1}, true)
	if err != nil {
		t.Fatal(err)
	}
	if tiny.Z {
		t.Fatal("tiny payload must stay uncompressed")
	}
}

// TestEnvelopeZstdBombRejected: a sealed envelope whose inner JSON decompresses
// past the cap must be refused without materialising it (plan P6).
func TestEnvelopeZstdBombRejected(t *testing.T) {
	sk := newTestKey(t)
	// craft a compressed blob over the cap directly, then seal it
	bomb := make([]byte, ZstdMaxDecompress+4096)
	var buf bytes.Buffer
	enc, err := zstd.NewWriter(&buf, zstd.WithEncoderLevel(zstd.SpeedFastest))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enc.Write(bomb); err != nil {
		t.Fatal(err)
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	sealed, err := sk.Seal(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	e := &Envelope{V: ProtocolVersion, Type: MsgResult, Agent: "a1", Z: true,
		Data: json.RawMessage(strconv.Quote(base64.StdEncoding.EncodeToString(sealed)))}
	var out TaskResult
	if err := e.OpenSealed(sk, &out); err == nil {
		t.Fatal("zstd bomb accepted")
	}
}

func TestEnvelopePlainRoundTrip(t *testing.T) {
	info := RegisterInfo{Agent: "ff00", System: SystemInfo{Hostname: "h1", OS: "linux"}}
	e, err := NewPlainEnvelope(MsgRegister, "ff00", info)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ReadEnvelope(e.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	var got RegisterInfo
	if err := back.DecodePlain(&got); err != nil {
		t.Fatal(err)
	}
	if got.System.Hostname != "h1" || got.Agent != "ff00" {
		t.Fatalf("plain payload mismatch: %+v", got)
	}
}

func TestEnvelopeVersionEnforced(t *testing.T) {
	raw, _ := json.Marshal(Envelope{V: 99, Type: MsgCheckin})
	if _, err := ReadEnvelope(raw); err == nil {
		t.Fatal("bad version accepted")
	}
}
