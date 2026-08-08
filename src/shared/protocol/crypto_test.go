package protocol

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestSessionKeysRoundTrip(t *testing.T) {
	keys, err := GenerateSessionKeys()
	if err != nil {
		t.Fatalf("generate keys: %v", err)
	}

	plaintext := []byte("registration data with some length to exercise CTR")
	encrypted, err := keys.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytes.Equal(encrypted, plaintext) {
		t.Error("encrypted data should differ from plaintext")
	}

	decrypted, err := keys.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("round trip mismatch: %q != %q", decrypted, plaintext)
	}
}

func TestDecryptTampered(t *testing.T) {
	keys, _ := GenerateSessionKeys()
	encrypted, _ := keys.Encrypt([]byte("hello"))

	// Flip a bit in the ciphertext -> HMAC must fail
	encrypted[len(encrypted)-33] ^= 0x01
	if _, err := keys.Decrypt(encrypted); err == nil {
		t.Error("expected HMAC verification failure for tampered data")
	}
}

func TestPacketEncodeDecode(t *testing.T) {
	pkt := &Packet{Type: TypeCheckin, Payload: []byte("payload-bytes")}
	encoded := pkt.Encode()

	decoded, err := ReadPacket(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("read packet: %v", err)
	}
	if decoded.Type != pkt.Type {
		t.Errorf("type = %d, want %d", decoded.Type, pkt.Type)
	}
	if !bytes.Equal(decoded.Payload, pkt.Payload) {
		t.Errorf("payload mismatch")
	}
}

func TestReadPacketRejectsBadMagic(t *testing.T) {
	buf := append([]byte{'X', 'X', 'X', 'X'}, make([]byte, HeaderSize-4+8)...)
	if _, err := ReadPacket(bytes.NewReader(buf)); err == nil {
		t.Error("expected error for invalid magic")
	}
}

func TestRSARoundTrip(t *testing.T) {
	priv, pubPEM, err := GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("gen keys: %v", err)
	}

	secret := []byte("64-byte-key-material-0123456789abcdefghijklmnopqrstuvwxyz")
	encrypted, err := RSAEncrypt(pubPEM, secret)
	if err != nil {
		t.Fatalf("rsa encrypt: %v", err)
	}
	decrypted, err := RSADecrypt(priv, encrypted)
	if err != nil {
		t.Fatalf("rsa decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, secret) {
		t.Errorf("RSA round trip mismatch")
	}
}

func TestLoadOrGenerateRSAKeyPair(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server_rsa.pem")

	// First call generates and persists
	priv1, pub1, err := LoadOrGenerateRSAKeyPair(path)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("key file not persisted: %v", err)
	}

	// Second call (simulating restart) must reuse the same key
	priv2, pub2, err := LoadOrGenerateRSAKeyPair(path)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if !priv1.Equal(priv2) {
		t.Error("private key changed across restarts")
	}
	if !bytes.Equal(pub1, pub2) {
		t.Error("public key PEM changed across restarts")
	}

	// Loaded key must be able to decrypt what the first key encrypted
	secret := []byte("session-key-material-for-agent")
	encrypted, err := RSAEncrypt(pub1, secret)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	decrypted, err := RSADecrypt(priv2, encrypted)
	if err != nil {
		t.Fatalf("decrypt with reloaded key: %v", err)
	}
	if !bytes.Equal(decrypted, secret) {
		t.Error("reloaded key cannot decrypt previous ciphertext")
	}

	// PKCS8 parseable
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("persisted key is not PEM")
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		t.Errorf("persisted key is not PKCS8: %v", err)
	}
}
