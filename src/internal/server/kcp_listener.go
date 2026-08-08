package server

// KCPListener manages a UDP listener using the KCP protocol (a reliable,
// low-latency transport over UDP). It serves the exact same packet protocol as
// the TCP listener — registration / checkin / task exchange — so agents using
// the "kcp" transport are fully interoperable. KCP avoids TCP slow-start and
// head-of-line blocking, which makes checkins snappier over lossy links.

import (
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/xtaci/kcp-go/v5"

	"github.com/user/wisp/internal/db"
)

// KCPListener manages a KCP/UDP listener for agent connections.
type KCPListener struct {
	mu       sync.Mutex
	id       string
	config   *db.ListenerRow
	server   *Server
	listener net.Listener
	running  bool
	stopCh   chan struct{}
}

// newKCPListener creates a new KCPListener bound to the given config.
func newKCPListener(s *Server, config *db.ListenerRow) *KCPListener {
	return &KCPListener{
		id:     config.ID,
		config: config,
		server: s,
		stopCh: make(chan struct{}),
	}
}

// ID returns the listener ID.
func (kl *KCPListener) ID() string {
	return kl.id
}

// Config returns the listener configuration.
func (kl *KCPListener) Config() *db.ListenerRow {
	return kl.config
}

// IsRunning reports whether the listener is currently running.
func (kl *KCPListener) IsRunning() bool {
	kl.mu.Lock()
	defer kl.mu.Unlock()
	return kl.running
}

// Start begins listening for agent connections over KCP/UDP.
func (kl *KCPListener) Start() error {
	kl.mu.Lock()
	defer kl.mu.Unlock()

	if kl.running {
		return fmt.Errorf("listener %s already running", kl.id)
	}

	config := kl.config
	addr := fmt.Sprintf("%s:%d", config.BindHost, config.BindPort)

	// No FEC and no block encryption: the payload layer already encrypts with
	// session keys, and FEC would only add latency for small C2 packets.
	ln, err := kcp.ListenWithOptions(addr, nil, 0, 0)
	if err != nil {
		return fmt.Errorf("kcp listen: %w", err)
	}

	kl.listener = ln
	kl.running = true
	kl.stopCh = make(chan struct{})

	// Accept connections in background
	go kl.acceptLoop()

	log.Printf("[KCPListener] Listening on %s (UDP/KCP)", addr)
	return nil
}

// Port returns the bound UDP port, or 0 when not running.
func (kl *KCPListener) Port() int {
	kl.mu.Lock()
	defer kl.mu.Unlock()
	if kl.listener == nil {
		return 0
	}
	if a, ok := kl.listener.Addr().(*net.UDPAddr); ok {
		return a.Port
	}
	return 0
}

// Stop stops the KCP listener.
func (kl *KCPListener) Stop() {
	kl.mu.Lock()
	defer kl.mu.Unlock()

	if !kl.running {
		return
	}
	kl.running = false
	close(kl.stopCh)
	kl.listener.Close()
}

func (kl *KCPListener) acceptLoop() {
	for {
		conn, err := kl.listener.Accept()
		if err != nil {
			select {
			case <-kl.stopCh:
				return
			default:
				log.Printf("[KCPListener] Accept error: %v", err)
				continue
			}
		}

		remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		if !kl.server.allowConn(remoteIP) {
			log.Printf("[KCPListener] Rate limited connection from %s", remoteIP)
			conn.Close()
			continue
		}

		// Fast mode so small C2 exchanges stay snappy over KCP.
		tuneKCPConn(conn)

		go func() {
			defer kl.server.releaseConn()
			handleConnection(kl.server, kl.id, conn)
		}()
	}
}

// tuneKCPConn switches a KCP session into fast mode. For remote-control frames
// this trades a little reliability for much lower latency; for checkins the
// packets are small so it is effectively free.
func tuneKCPConn(conn net.Conn) {
	sess, ok := conn.(*kcp.UDPSession)
	if !ok {
		return
	}
	// nodelay=1 (fast mode), interval=10ms, fast resend=2, no congestion control
	sess.SetNoDelay(1, 10, 2, 1)
	sess.SetStreamMode(true)
	// Large window + buffering: high-res remote-control frames split into
	// hundreds of KCP segments must fit into the send window, otherwise the
	// stream-mode writer blocks and the picture freezes.
	sess.SetWindowSize(2048, 2048)
	sess.SetReadBuffer(8 << 20)
	sess.SetWriteBuffer(8 << 20)
}
