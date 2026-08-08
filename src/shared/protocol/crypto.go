package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
)

// SessionKeys holds the symmetric keys for a single agent session.
type SessionKeys struct {
	AESKey  []byte // 32 bytes (AES-256)
	HMACKey []byte // 32 bytes
}

// GenerateSessionKeys creates a new random AES-256 key and HMAC key.
func GenerateSessionKeys() (*SessionKeys, error) {
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
		return nil, err
	}
	hmacKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, hmacKey); err != nil {
		return nil, err
	}
	return &SessionKeys{AESKey: aesKey, HMACKey: hmacKey}, nil
}

// Encrypt encrypts plaintext using AES-256-CTR and appends HMAC-SHA256.
// Output format: IV(16) + Ciphertext(N) + HMAC(32)
func (sk *SessionKeys) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(sk.AESKey)
	if err != nil {
		return nil, err
	}

	// Generate random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// Encrypt
	ciphertext := make([]byte, len(plaintext))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, plaintext)

	// Build output: IV + Ciphertext
	out := make([]byte, 0, aes.BlockSize+len(ciphertext)+32)
	out = append(out, iv...)
	out = append(out, ciphertext...)

	// Compute HMAC over IV+Ciphertext
	mac := hmac.New(sha256.New, sk.HMACKey)
	mac.Write(out)
	out = append(out, mac.Sum(nil)...)

	return out, nil
}

// Decrypt verifies HMAC-SHA256 and decrypts AES-256-CTR ciphertext.
// Input format: IV(16) + Ciphertext(N) + HMAC(32)
func (sk *SessionKeys) Decrypt(data []byte) ([]byte, error) {
	if len(data) < aes.BlockSize+32 {
		return nil, errors.New("ciphertext too short")
	}

	// Split: IV | Ciphertext | HMAC
	macStart := len(data) - 32
	receivedMAC := data[macStart:]
	ivAndCiphertext := data[:macStart]

	// Verify HMAC
	mac := hmac.New(sha256.New, sk.HMACKey)
	mac.Write(ivAndCiphertext)
	expectedMAC := mac.Sum(nil)
	if !hmac.Equal(receivedMAC, expectedMAC) {
		return nil, errors.New("HMAC verification failed")
	}

	// Decrypt
	iv := ivAndCiphertext[:aes.BlockSize]
	ciphertext := ivAndCiphertext[aes.BlockSize:]

	block, err := aes.NewCipher(sk.AESKey)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ciphertext))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

// RSAEncrypt encrypts data with an RSA public key (OAEP SHA-256).
func RSAEncrypt(pubKeyPEM []byte, plaintext []byte) ([]byte, error) {
	block, _ := pem.Decode(pubKeyPEM)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	return rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, plaintext, nil)
}

// RSADecrypt decrypts data with an RSA private key (OAEP SHA-256).
func RSADecrypt(privKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, ciphertext, nil)
}

// GenerateRSAKeyPair generates a new RSA-2048 key pair.
func GenerateRSAKeyPair() (*rsa.PrivateKey, []byte, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	pubPEM, err := publicKeyPEM(&privKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	return privKey, pubPEM, nil
}

// LoadOrGenerateRSAKeyPair loads the server RSA private key from path, or
// generates and persists a fresh key pair on first run. Persisting the key
// keeps existing agents connected across server restarts.
func LoadOrGenerateRSAKeyPair(path string) (*rsa.PrivateKey, []byte, error) {
	if data, err := os.ReadFile(path); err == nil {
		if priv, pubPEM, loadErr := parsePrivateKey(data); loadErr == nil {
			return priv, pubPEM, nil
		}
	}

	priv, pubPEM, err := GenerateRSAKeyPair()
	if err != nil {
		return nil, nil, err
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, block, 0600); err != nil {
		return nil, nil, err
	}

	return priv, pubPEM, nil
}

func parsePrivateKey(data []byte) (*rsa.PrivateKey, []byte, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, nil, errors.New("invalid PEM data")
	}

	var priv *rsa.PrivateKey
	if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		var ok bool
		priv, ok = parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, errors.New("not an RSA private key")
		}
	} else if parsed, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		priv = parsed
	} else {
		return nil, nil, errors.New("unsupported private key format")
	}

	pubPEM, err := publicKeyPEM(&priv.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return priv, pubPEM, nil
}

func publicKeyPEM(pub *rsa.PublicKey) ([]byte, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	}), nil
}
