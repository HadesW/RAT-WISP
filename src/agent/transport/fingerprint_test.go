package transport

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestFingerprintVerifierMismatch(t *testing.T) {
	// A DER certificate (any bytes work; we compare raw cert bytes)
	rawCert := []byte("fake-der-certificate-bytes")
	sum := sha256.Sum256(rawCert)
	fp := hex.EncodeToString(sum[:])

	verifier := fingerprintVerifier(fp)

	// Matching fingerprint passes
	if err := verifier([][]byte{rawCert}, nil); err != nil {
		t.Errorf("matching fingerprint should pass: %v", err)
	}

	// Wrong fingerprint rejected
	other := []byte("another-certificate")
	otherSum := sha256.Sum256(other)
	if err := verifier([][]byte{other}, nil); err == nil {
		t.Error("mismatched fingerprint should be rejected")
	}
	_ = otherSum

	// No certificate presented rejected
	if err := verifier(nil, nil); err == nil {
		t.Error("missing certificate should be rejected")
	}
}

func TestFingerprintVerifierExpectedHex(t *testing.T) {
	// The fingerprint must be hex-encoded (32-byte sha256 -> 64 chars)
	raw := []byte("x")
	sum := sha256.Sum256(raw)
	fp := hex.EncodeToString(sum[:])
	if len(fp) != 64 {
		t.Fatalf("fingerprint length = %d, want 64", len(fp))
	}
	verifier := fingerprintVerifier(fp)
	if err := verifier([][]byte{raw}, nil); err != nil {
		t.Errorf("should verify: %v", err)
	}
}
