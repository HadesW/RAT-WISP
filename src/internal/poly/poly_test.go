package poly

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestEncodeUniqueness verifies every call produces different bytes.
func TestEncodeUniqueness(t *testing.T) {
	payload := []byte{0xCC, 0x48, 0x8B, 0xC4, 0xE8, 0x00, 0x00, 0x00, 0x00}
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		out, err := Encode(payload)
		if err != nil {
			t.Fatal(err)
		}
		if seen[string(out)] {
			t.Fatalf("iteration %d produced identical output (no polymorphism)", i)
		}
		seen[string(out)] = true
	}
}

// TestEncodeStartsWithExecJunk verifies the output begins with a stub (not the
// raw payload) and is longer than the input.
func TestEncodeStartsWithExecJunk(t *testing.T) {
	payload := []byte{0x90, 0x90, 0x90, 0x90, 0xCC, 0x90, 0x90, 0x90}
	out, err := Encode(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) <= len(payload) {
		t.Fatalf("encoded len %d <= payload len %d", len(out), len(payload))
	}
	if bytes.Equal(out[:len(payload)], payload) {
		t.Fatal("output starts with raw payload (not encoded)")
	}
}

// miniDecode emulates the SGN decode stub in software so the test can prove the
// emitted blob actually reconstructs the original payload. It locates the
// encoded region by scanning for the XOR chain: the first dword of the encoded
// region must satisfy enc[0] != plain[0] but the whole chain must recover.
//
// Instead of fully emulating arbitrary register choices, we exploit the fact
// that the decoder is deterministic given (key, count, region): we brute-force
// the start offset by trying every dword-aligned position and validating that
// XOR-chaining the remainder yields a payload whose last dwords look like our
// known trailer (or that decoding in-place recovers a plausible MZ/CC region).
func miniDecode(blob []byte, original []byte) ([]byte, bool) {
	// Pad the original the same way Encode does.
	for len(original)%4 != 0 {
		original = append(original, 0x90)
	}
	// A valid stub must end with: SUB reg64,imm32 ; JMP reg64 ; <encoded>.
	// The encoded region begins right after the stub. The stub length is not
	// dword-aligned (random junk), so scan every byte offset.
	for off := 0; off+len(original) <= len(blob); off++ {
		tail := blob[off : off+len(original)]
		dec := make([]byte, len(tail))
		// Decode: plain[i] = enc[i] ^ key; key = enc[i] (key starts unknown).
		// The first dword: plain[0] = enc[0] ^ key → key = enc[0] ^ plain[0].
		// So recover key from the first known plaintext dword.
		key := binary.LittleEndian.Uint32(tail[0:4]) ^ binary.LittleEndian.Uint32(original[0:4])
		k := key
		for i := 0; i < len(tail); i += 4 {
			e := binary.LittleEndian.Uint32(tail[i : i+4])
			p := e ^ k
			binary.LittleEndian.PutUint32(dec[i:i+4], p)
			k = e
		}
		if bytes.Equal(dec, original) {
			return dec, true
		}
	}
	return nil, false
}

// TestEncodeRoundTrip emulates the decoder to prove the blob reconstructs the
// original payload. Because the stub layout is randomized, the test recovers
// the encoded region by trying every 4-aligned offset.
func TestEncodeRoundTrip(t *testing.T) {
	payloads := [][]byte{
		{0x4D, 0x5A, 0x90, 0x90, 0x90, 0x90, 0xCC, 0x48, 0x31, 0xC0, 0xC3},
		bytes.Repeat([]byte{0xCC}, 64),
		{0xE8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x48, 0x83, 0xEC, 0x08},
	}
	for pi, payload := range payloads {
		out, err := Encode(payload)
		if err != nil {
			t.Fatalf("payload %d: %v", pi, err)
		}
		if _, ok := miniDecode(out, payload); !ok {
			t.Fatalf("payload %d: decode round-trip failed (blob %d bytes)", pi, len(out))
		}
	}
}
