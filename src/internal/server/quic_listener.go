package server

// QUICListener manages a UDP listener using the QUIC protocol (HTTP/3's
// transport). It serves the exact same packet protocol as the TCP/KCP
// listeners — registration / checkin / task exchange — so agents using the
// "quic" transport are fully interoperable. QUIC brings TLS 1.3 encryption,
// connection migration and zero-RTT-style resumption on top of UDP, while the
// application layer still adds its own RSA+AES hybrid encryption.
//
// Like the KCP listener it is short-lived per exchange: every register/checkin
// dials a fresh QUIC connection from a random ephemeral UDP port and closes it
// right after. The QUIC handshake itself provides reliability (unlike raw KCP,
// acknowledged data survives Close), so no extra drain delay is required.

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/user/wisp/internal/db"
)

// quicNextProto is the ALPN token for wisp QUIC connections. Using a custom
// token prevents the server from accepting unrelated QUIC clients.
const quicNextProto = "wisp"

// QUICListener manages a QUIC/UDP listener for agent connections.
type QUICListener struct {
	mu       sync.Mutex
	id       string
	config   *db.ListenerRow
	server   *Server
	listener *quic.Listener
	running  bool
	stopCh   chan struct{}
}

// newQUICListener creates a new QUICListener bound to the given config.
func newQUICListener(s *Server, config *db.ListenerRow) *QUICListener {
	return &QUICListener{
		id:     config.ID,
		config: config,
		server: s,
		stopCh: make(chan struct{}),
	}
}

// ID returns the listener ID.
func (ql *QUICListener) ID() string {
	return ql.id
}

// Config returns the listener configuration.
func (ql *QUICListener) Config() *db.ListenerRow {
	return ql.config
}

// IsRunning reports whether the listener is currently running.
func (ql *QUICListener) IsRunning() bool {
	ql.mu.Lock()
	defer ql.mu.Unlock()
	return ql.running
}

// Start begins listening for agent connections over QUIC/UDP.
func (ql *QUICListener) Start() error {
	ql.mu.Lock()
	defer ql.mu.Unlock()

	if ql.running {
		return fmt.Errorf("listener %s already running", ql.id)
	}

	config := ql.config
	addr := fmt.Sprintf("%s:%d", config.BindHost, config.BindPort)

	cert, err := ql.server.loadOrGenerateTLSCert()
	if err != nil {
		return fmt.Errorf("load TLS cert: %w", err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{quicNextProto},
	}

	ln, err := quic.ListenAddr(addr, tlsConfig, nil)
	if err != nil {
		return fmt.Errorf("quic listen: %w", err)
	}

	ql.listener = ln
	ql.running = true
	ql.stopCh = make(chan struct{})

	// Accept connections in background
	go ql.acceptLoop()

	log.Printf("[QUICListener] Listening on %s (UDP/QUIC)", addr)
	return nil
}

// Port returns the bound UDP port, or 0 when not running.
func (ql *QUICListener) Port() int {
	ql.mu.Lock()
	defer ql.mu.Unlock()
	if ql.listener == nil {
		return 0
	}
	if a, ok := ql.listener.Addr().(*net.UDPAddr); ok {
		return a.Port
	}
	return 0
}

// Stop stops the QUIC listener.
func (ql *QUICListener) Stop() {
	ql.mu.Lock()
	defer ql.mu.Unlock()

	if !ql.running {
		return
	}
	ql.running = false
	close(ql.stopCh)
	_ = ql.listener.Close()
}

func (ql *QUICListener) acceptLoop() {
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		conn, err := ql.listener.Accept(ctx)
		cancel()
		if err != nil {
			select {
			case <-ql.stopCh:
				return
			default:
				if err == context.DeadlineExceeded {
					continue
				}
				log.Printf("[QUICListener] Accept error: %v", err)
				continue
			}
		}

		remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		if !ql.server.allowConn(remoteIP) {
			log.Printf("[QUICListener] Rate limited connection from %s", remoteIP)
			_ = conn.CloseWithError(0, "rate limited")
			continue
		}

		// Each agent exchange opens one stream on its QUIC connection. Bound the
		// wait so a client that connects but never opens a stream cannot hold a
		// goroutine (and a rate-limit slot) forever.
		go func(c *quic.Conn) {
			defer ql.server.releaseConn()
			sctx, scancel := context.WithTimeout(context.Background(), connIdleTimeout)
			stream, err := c.AcceptStream(sctx)
			scancel()
			if err != nil {
				_ = c.CloseWithError(0, "no stream")
				return
			}
			// handleConnection closes the adapter (stream + connection) when it
			// returns, matching the short-lived model of the other transports.
			handleConnection(ql.server, ql.id, &quicStreamAdapter{conn: c, stream: stream})
		}(conn)
	}
}

// quicStreamAdapter adapts a QUIC connection + one of its streams into a
// net.Conn so the shared packet protocol (protocol.ReadPacket/WritePacket) can
// run over it unchanged. Reads/writes flow through the stream; the QUIC
// connection provides the peer addresses.
// quic-go v0.61 exposes Stream as an interface and AcceptStream returns
// *quic.Stream (a pointer to that interface).
type quicStreamAdapter struct {
	conn   *quic.Conn
	stream *quic.Stream
}

func (a *quicStreamAdapter) Read(p []byte) (int, error)         { return a.stream.Read(p) }
func (a *quicStreamAdapter) Write(p []byte) (int, error)        { return a.stream.Write(p) }
func (a *quicStreamAdapter) Close() error {
	// Graceful close, mirroring the KCP listener's hold-open: CloseWithError
	// drops unacknowledged data, so tearing the connection down immediately
	// after replying would lose the reply (agent → re-register → rate-limit
	// storm). Instead, send FIN and wait for the peer to finish reading and
	// close its side — the agent does so right after a successful Read, so
	// this normally returns in a round trip. Bounded so a stuck peer cannot
	// hold the goroutine forever.
	_ = a.stream.Close()
	_ = a.stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	one := make([]byte, 1)
	for {
		if _, err := a.stream.Read(one); err != nil {
			break // peer closed / EOF / deadline
		}
	}
	return a.conn.CloseWithError(0, "done")
}
func (a *quicStreamAdapter) LocalAddr() net.Addr                { return a.conn.LocalAddr() }
func (a *quicStreamAdapter) RemoteAddr() net.Addr               { return a.conn.RemoteAddr() }
func (a *quicStreamAdapter) SetDeadline(t time.Time) error      { return a.stream.SetDeadline(t) }
func (a *quicStreamAdapter) SetReadDeadline(t time.Time) error  { return a.stream.SetReadDeadline(t) }
func (a *quicStreamAdapter) SetWriteDeadline(t time.Time) error { return a.stream.SetWriteDeadline(t) }
