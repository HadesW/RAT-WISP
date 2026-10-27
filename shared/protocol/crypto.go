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
	"os"
)

// Session crypto: RSA-OAEP(SHA-256) wraps a 80-byte session key blob
// (Enc 32 || Mac 32 || KeyID 16). After establishment every payload travels as
// IV(16) || AES-256-CTR(plaintext) || HMAC-SHA256(macKey, IV||CT)(32),
// i.e. encrypt-then-MAC, byte-compatible with the Rust agent (plan §3).

const (
	KeySize   = 32
	MacSize   = 32
	KeyIDSize = 16
	IVSize    = 16
	HMacSize  = sha256.Size

	keyBlobSize = KeySize + MacSize + KeyIDSize
)

var (
	ErrBadKey      = errors.New("protocol: bad session key blob size")
	ErrSealedShort = errors.New("protocol: sealed blob too short")
	ErrMACMismatch = errors.New("protocol: HMAC mismatch (tampered or wrong key)")
)

// SessionKey is the per-agent symmetric material established at registration.
type SessionKey struct {
	Enc [KeySize]byte
	Mac [MacSize]byte
	ID  [KeyIDSize]byte
}

// NewSessionKey generates random session key material.
func NewSessionKey() (*SessionKey, error) {
	sk := &SessionKey{}
	b := make([]byte, keyBlobSize)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("rand: %w", err)
	}
	copy(sk.Enc[:], b[0:KeySize])
	copy(sk.Mac[:], b[KeySize:KeySize+MacSize])
	copy(sk.ID[:], b[KeySize+MacSize:])
	return sk, nil
}

// blob serializes the key for RSA wrapping.
func (sk *SessionKey) blob() []byte {
	b := make([]byte, keyBlobSize)
	copy(b[0:KeySize], sk.Enc[:])
	copy(b[KeySize:KeySize+MacSize], sk.Mac[:])
	copy(b[KeySize+MacSize:], sk.ID[:])
	return b
}

// WrapSessionKey RSA-OAEP(SHA-256) encrypts the session key with the server pubkey.
func WrapSessionKey(pub *rsa.PublicKey, sk *SessionKey) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, sk.blob(), nil)
}

// UnwrapSessionKey reverses WrapSessionKey with the server private key.
func UnwrapSessionKey(priv *rsa.PrivateKey, wrapped []byte) (*SessionKey, error) {
	b, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, wrapped, nil)
	if err != nil {
		return nil, fmt.Errorf("unwrap key: %w", err)
	}
	if len(b) != keyBlobSize {
		return nil, ErrBadKey
	}
	sk := &SessionKey{}
	copy(sk.Enc[:], b[0:KeySize])
	copy(sk.Mac[:], b[KeySize:KeySize+MacSize])
	copy(sk.ID[:], b[KeySize+MacSize:])
	return sk, nil
}

// Seal encrypts plaintext and appends an HMAC: IV || CT || MAC.
func (sk *SessionKey) Seal(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(sk.Enc[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, IVSize+len(plaintext)+HMacSize)
	iv := out[0:IVSize]
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	cipher.NewCTR(block, iv).XORKeyStream(out[IVSize:IVSize+len(plaintext)], plaintext)
	mac := hmac.New(sha256.New, sk.Mac[:])
	mac.Write(out[:IVSize+len(plaintext)])
	copy(out[IVSize+len(plaintext):], mac.Sum(nil))
	return out, nil
}

// Open verifies the HMAC then decrypts IV || CT || MAC.
func (sk *SessionKey) Open(blob []byte) ([]byte, error) {
	if len(blob) < IVSize+HMacSize {
		return nil, ErrSealedShort
	}
	body := blob[:len(blob)-HMacSize]
	want := blob[len(blob)-HMacSize:]
	mac := hmac.New(sha256.New, sk.Mac[:])
	mac.Write(body)
	if !hmac.Equal(mac.Sum(nil), want) {
		return nil, ErrMACMismatch
	}
	block, err := aes.NewCipher(sk.Enc[:])
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(body)-IVSize)
	cipher.NewCTR(block, body[:IVSize]).XORKeyStream(plain, body[IVSize:])
	return plain, nil
}

// PSKProof = HMAC-SHA256(key=psk, msg=agentID 0x7c keyID-hex). Sent in the
// plaintext register envelope so the server can reject unknown operators.
func PSKProof(psk, agentID string, keyID []byte) []byte {
	mac := hmac.New(sha256.New, []byte(psk))
	mac.Write([]byte(agentID))
	mac.Write([]byte{0x7c})
	mac.Write([]byte(fmt.Sprintf("%x", keyID)))
	return mac.Sum(nil)
}

// VerifyPSKProof compares in constant time.
func VerifyPSKProof(psk, agentID string, keyID, proof []byte) bool {
	return hmac.Equal(PSKProof(psk, agentID, keyID), proof)
}

// GenerateRSAKey creates a fresh server identity key.
func GenerateRSAKey(bits int) (*rsa.PrivateKey, error) {
	if bits < 2048 {
		bits = 2048
	}
	return rsa.GenerateKey(rand.Reader, bits)
}

// LoadOrGenerateRSAKey loads a PKCS#8 PEM key from path, creating it (0600) if absent.
func LoadOrGenerateRSAKey(path string) (*rsa.PrivateKey, error) {
	if data, err := os.ReadFile(path); err == nil {
		blk, _ := pem.Decode(data)
		if blk == nil {
			return nil, fmt.Errorf("%s: not PEM", path)
		}
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		priv, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%s: not an RSA key", path)
		}
		return priv, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	priv, err := GenerateRSAKey(2048)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dirOf(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return priv, pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// EncodePublicKeyPEM exports the public half as PKIX PEM.
func EncodePublicKeyPEM(pub *rsa.PublicKey) []byte {
	der, _ := x509.MarshalPKIXPublicKey(pub)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// DecodePublicKeyPEM parses what EncodePublicKeyPEM produced.
func DecodePublicKeyPEM(data []byte) (*rsa.PublicKey, error) {
	blk, _ := pem.Decode(data)
	if blk == nil {
		return nil, errors.New("protocol: not PEM")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := k.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("protocol: not an RSA public key")
	}
	return pub, nil
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}
