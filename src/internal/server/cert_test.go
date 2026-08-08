package server

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrGenerateTLSCert(t *testing.T) {
	s := newTestServer(t)

	// First call generates and persists
	cert1, err := s.loadOrGenerateTLSCert()
	if err != nil {
		t.Fatalf("first load: %v", err)
	}

	certPath := filepath.Join(s.db.DataDir(), "tls", "cert.pem")
	keyPath := filepath.Join(s.db.DataDir(), "tls", "key.pem")
	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("cert not persisted: %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("key not persisted: %v", err)
	}

	// Second call (simulating restart) must reuse the same certificate
	cert2, err := s.loadOrGenerateTLSCert()
	if err != nil {
		t.Fatalf("second load: %v", err)
	}

	der1, _ := x509.ParseCertificate(cert1.Certificate[0])
	der2, _ := x509.ParseCertificate(cert2.Certificate[0])
	if der1 == nil || der2 == nil {
		t.Fatal("cannot parse persisted certificates")
	}
	if der1.SerialNumber.Cmp(der2.SerialNumber) != 0 {
		t.Error("certificate changed across restarts (serial differs)")
	}
	if !der1.Equal(der2) {
		t.Error("certificate changed across restarts (DER differs)")
	}
}
