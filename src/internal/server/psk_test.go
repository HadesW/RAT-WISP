package server

import (
	"encoding/json"
	"testing"

	"github.com/user/wisp/shared/protocol"
)

// buildRegPayload builds an encrypted registration payload for the server's
// current RSA public key, embedding the given PSK.
func buildRegPayload(t *testing.T, s *Server, psk string) []byte {
	t.Helper()
	keys, err := protocol.GenerateSessionKeys()
	if err != nil {
		t.Fatalf("gen keys: %v", err)
	}
	reg, _ := jsonMarshal(map[string]any{
		"id": testAgentID, "hostname": "h", "username": "u",
		"internal_ip": "10.0.0.9", "os": "windows", "arch": "amd64",
		"sleep": 5000, "jitter": 0, "psk": psk,
	})
	encryptedReg, _ := keys.Encrypt(reg)

	keyMaterial := append(keys.AESKey, keys.HMACKey...)
	encryptedKeys, err := protocol.RSAEncrypt(s.GetRSAPubPEM(), keyMaterial)
	if err != nil {
		t.Fatalf("rsa encrypt: %v", err)
	}

	payload := make([]byte, 4+len(encryptedKeys)+len(encryptedReg))
	payload[0] = byte(len(encryptedKeys))
	payload[1] = byte(len(encryptedKeys) >> 8)
	payload[2] = byte(len(encryptedKeys) >> 16)
	payload[3] = byte(len(encryptedKeys) >> 24)
	copy(payload[4:], encryptedKeys)
	copy(payload[4+len(encryptedKeys):], encryptedReg)
	return payload
}

// GetRSAPubPEM exposes the server's public key PEM for tests.
func (s *Server) GetRSAPubPEM() []byte {
	return s.rsaPubPEM
}

func jsonMarshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

func TestPSKRegistrationAccepted(t *testing.T) {
	s := newTestServer(t)
	ln, err := s.db.CreateListener("psk-ok", "tcp", "127.0.0.1", 7001, false, "s3cret-k3y")
	if err != nil {
		t.Fatalf("create listener: %v", err)
	}

	_, ack, err := s.processRegistration(buildRegPayload(t, s, "s3cret-k3y"), ln.ID, "1.2.3.4")
	if err != nil {
		t.Fatalf("registration with correct PSK rejected: %v", err)
	}
	if len(ack) == 0 {
		t.Error("expected non-empty ACK")
	}
}

func TestPSKRegistrationRejected(t *testing.T) {
	s := newTestServer(t)
	ln, err := s.db.CreateListener("psk-rej", "tcp", "127.0.0.1", 7002, false, "s3cret-k3y")
	if err != nil {
		t.Fatalf("create listener: %v", err)
	}

	// Wrong PSK
	if _, _, err := s.processRegistration(buildRegPayload(t, s, "wrong-key"), ln.ID, "1.2.3.4"); err == nil {
		t.Error("registration with wrong PSK should be rejected")
	}
	// Missing PSK
	if _, _, err := s.processRegistration(buildRegPayload(t, s, ""), ln.ID, "1.2.3.4"); err == nil {
		t.Error("registration without PSK should be rejected")
	}
}

func TestPSKOptionalWhenUnset(t *testing.T) {
	s := newTestServer(t)
	ln, err := s.db.CreateListener("psk-none", "tcp", "127.0.0.1", 7003, false, "")
	if err != nil {
		t.Fatalf("create listener: %v", err)
	}

	// Listener without PSK accepts agents without a key
	if _, _, err := s.processRegistration(buildRegPayload(t, s, ""), ln.ID, "1.2.3.4"); err != nil {
		t.Errorf("registration without PSK should be accepted when listener has no PSK: %v", err)
	}
}

// Ensure session persists for the accepted registration.
func TestPSKRegistrationCreatesSession(t *testing.T) {
	s := newTestServer(t)
	ln, err := s.db.CreateListener("psk-sess", "tcp", "127.0.0.1", 7004, false, "k")
	if err != nil {
		t.Fatalf("create listener: %v", err)
	}

	if _, _, err := s.processRegistration(buildRegPayload(t, s, "k"), ln.ID, "5.6.7.8"); err != nil {
		t.Fatalf("register: %v", err)
	}
	row, err := s.db.GetSession(testAgentID)
	if err != nil {
		t.Fatalf("session not created: %v", err)
	}
	if row.Status != protocol.StatusAlive {
		t.Errorf("session status = %q", row.Status)
	}
}
