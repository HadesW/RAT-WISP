package transport

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"wispp/protocol"
)

// QUIC ships Type1 envelopes over QUIC (plan P6): one bi-directional stream
// per round-trip with the same magic framing as TCP. The connection is cached
// and re-dialed on failure so checkins stay cheap.
type QUIC struct {
	mu      sync.Mutex
	servers []string // quic://host:port
	conn    quic.Connection
	dial    int // index of the server the cached conn belongs to
}

func NewQUIC(servers []string) *QUIC { return &QUIC{servers: servers} }

func (q *QUIC) addr(i int) string { return strings.TrimPrefix(q.servers[i], "quic://") }

func (q *QUIC) tlsConfig() *tls.Config {
	// The agent authenticates the server through the RSA pubkey bootstrap
	// (same trust model as the plaintext TCP/KCP paths), so the self-signed
	// transport certificate is only for TLS confidentiality.
	return &tls.Config{
		NextProtos:         []string{"wisp"},
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}
}

func (q *QUIC) quicConfig() *quic.Config {
	return &quic.Config{
		MaxIdleTimeout:  90 * time.Second,
		KeepAlivePeriod: 20 * time.Second,
		EnableDatagrams: false,
	}
}

// connection returns a live cached connection, dialing if needed.
func (q *QUIC) connection() (quic.Connection, int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.conn != nil {
		return q.conn, q.dial, nil
	}
	var lastErr error
	for i := range q.servers {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		conn, err := quic.DialAddr(ctx, q.addr(i), q.tlsConfig(), q.quicConfig())
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		q.conn, q.dial = conn, i
		return conn, i, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("transport: no quic servers configured")
	}
	return nil, 0, lastErr
}

func (q *QUIC) drop(conn quic.Connection) {
	q.mu.Lock()
	if q.conn == conn {
		q.conn = nil
	}
	q.mu.Unlock()
	_ = conn.CloseWithError(0, "")
}

// exchange runs one envelope over a fresh stream on the cached connection;
// a dead connection is dropped and the exchange retried once on a fresh dial.
func (q *QUIC) exchange(env *protocol.Envelope) (*protocol.Envelope, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		conn, _, err := q.connection()
		if err != nil {
			return nil, err
		}
		out, err := q.roundTrip(conn, env)
		if err == nil {
			return out, nil
		}
		q.drop(conn)
		lastErr = err
	}
	return nil, lastErr
}

func (q *QUIC) roundTrip(conn quic.Connection, env *protocol.Envelope) (*protocol.Envelope, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(30 * time.Second))
	if err := protocol.WritePacket(stream, &protocol.Packet{Type: protocol.TypeEnvelope, Payload: env.Marshal()}); err != nil {
		return nil, err
	}
	// Half-close signals "request complete" to the server, which answers on
	// the same stream and closes its side.
	_ = stream.Close()
	pkt, err := protocol.ReadPacket(stream)
	if err != nil {
		return nil, err
	}
	if pkt.Type != protocol.TypeEnvelope {
		return nil, fmt.Errorf("transport: quic: unexpected packet type %d", pkt.Type)
	}
	return protocol.ReadEnvelope(pkt.Payload)
}

func (q *QUIC) Send(env *protocol.Envelope) (*protocol.Envelope, error) { return q.exchange(env) }

// Pubkey bootstraps the server RSA public key through the plain envelope
// channel (the QUIC listener only carries TypeEnvelope frames).
func (q *QUIC) Pubkey() (*rsa.PublicKey, error) {
	env, err := protocol.NewPlainEnvelope(protocol.MsgPubkey, "", nil)
	if err != nil {
		return nil, err
	}
	resp, err := q.Send(env)
	if err != nil {
		return nil, err
	}
	var pk protocol.PubkeyInfo
	if err := resp.DecodePlain(&pk); err != nil {
		return nil, err
	}
	return protocol.DecodePublicKeyPEM([]byte(pk.PEM))
}
