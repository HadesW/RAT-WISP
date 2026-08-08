package server

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/user/wisp/internal/db"
)

// TestTLSFingerprintBeforeListenerStart reproduces the payload-generation race:
// calling TLSFingerprint() before any HTTPS listener has started must still
// yield a valid, persistent fingerprint (the certificate is generated on
// demand), and the fingerprint must match the certificate the listener later
// loads. Before the fix the fingerprint was cached empty in this scenario,
// leaving payloads without a working pin.
func TestTLSFingerprintBeforeListenerStart(t *testing.T) {
	database, err := db.Open(filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer database.Close()

	srv, err := New(database, nil)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	// Payload generation calls TLSFingerprint() even when no HTTPS listener has
	// been started yet.
	fp := srv.TLSFingerprint()
	if fp == "" {
		t.Fatal("fingerprint must be non-empty when generating an HTTPS payload")
	}

	// The certificate must now be persisted and reused by the listener.
	cert, err := srv.loadOrGenerateTLSCert()
	if err != nil {
		t.Fatalf("load cert: %v", err)
	}
	sum := sha256.Sum256(cert.Certificate[0])
	if got := hex.EncodeToString(sum[:]); got != fp {
		t.Fatalf("fingerprint mismatch: TLSFingerprint=%s persisted cert=%s", fp, got)
	}
}
