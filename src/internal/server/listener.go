package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/xtaci/kcp-go/v5"

	"github.com/user/wisp/internal/db"
	"github.com/user/wisp/shared/protocol"
)

// TCPListener manages a TCP listener for agent connections.
type TCPListener struct {
	mu       sync.Mutex
	id       string
	config   *db.ListenerRow
	server   *Server
	listener net.Listener
	running  bool
	stopCh   chan struct{}
}

// RegistrationPayload is the JSON payload sent by the agent during registration.
type RegistrationPayload struct {
	ID          string `json:"id"`
	Hostname    string `json:"hostname"`
	Username    string `json:"username"`
	Domain      string `json:"domain"`
	InternalIP  string `json:"internal_ip"`
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	PID         int    `json:"pid"`
	ProcessName string `json:"process_name"`
	IsElevated  bool   `json:"is_elevated"`
	Sleep       int    `json:"sleep"`
	Jitter      int    `json:"jitter"`
	PSK         string `json:"psk,omitempty"`
}

// newTCPListener creates a new TCPListener bound to the given config.
func newTCPListener(s *Server, config *db.ListenerRow) *TCPListener {
	return &TCPListener{
		id:     config.ID,
		config: config,
		server: s,
		stopCh: make(chan struct{}),
	}
}

// ID returns the listener ID.
func (tl *TCPListener) ID() string {
	return tl.id
}

// Config returns the listener configuration.
func (tl *TCPListener) Config() *db.ListenerRow {
	return tl.config
}

// IsRunning reports whether the listener is currently running.
func (tl *TCPListener) IsRunning() bool {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	return tl.running
}

// Start begins listening for agent connections.
func (tl *TCPListener) Start() error {
	tl.mu.Lock()
	defer tl.mu.Unlock()

	if tl.running {
		return fmt.Errorf("listener %s already running", tl.id)
	}

	config := tl.config
	addr := fmt.Sprintf("%s:%d", config.BindHost, config.BindPort)

	var ln net.Listener
	if config.UseTLS {
		tlsCert, err := tl.server.loadOrGenerateTLSCert()
		if err != nil {
			return fmt.Errorf("load TLS cert: %w", err)
		}
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			MinVersion:   tls.VersionTLS12,
		}
		ln, err = tls.Listen("tcp", addr, tlsConfig)
		if err != nil {
			return fmt.Errorf("tls listen: %w", err)
		}
	} else {
		var err error
		ln, err = net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("tcp listen: %w", err)
		}
	}

	tl.listener = ln
	tl.running = true
	tl.stopCh = make(chan struct{})

	// Accept connections in background
	go tl.acceptLoop()

	log.Printf("[TCPListener] Listening on %s (TLS: %v)", addr, config.UseTLS)
	return nil
}

// StartListener creates and starts a listener for its configured protocol.
func (s *Server) StartListener(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if already running
	if l, exists := s.listeners[id]; exists && l.IsRunning() {
		return fmt.Errorf("listener %s already running", id)
	}

	// Get listener config from database
	config, err := s.db.GetListener(id)
	if err != nil {
		return fmt.Errorf("get listener config: %w", err)
	}

	l, err := s.createListener(config)
	if err != nil {
		return fmt.Errorf("create listener: %w", err)
	}

	if err := l.Start(); err != nil {
		return err
	}

	s.listeners[id] = l

	// Update DB status
	_ = s.db.UpdateListenerStatus(id, protocol.ListenerRunning)

	if s.emitter != nil {
		s.emitter.EmitEvent("listener:status", map[string]string{"id": id, "status": protocol.ListenerRunning})
	}

	log.Printf("[Listener] Started %s (%s) on %s:%d (TLS: %v)", config.Name, config.Protocol, config.BindHost, config.BindPort, config.UseTLS)
	return nil
}

// StopListener stops a running TCP listener.
func (s *Server) StopListener(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	l, exists := s.listeners[id]
	if !exists || !l.IsRunning() {
		return fmt.Errorf("listener %s not running", id)
	}

	l.Stop()
	_ = s.db.UpdateListenerStatus(id, protocol.ListenerStopped)

	if s.emitter != nil {
		s.emitter.EmitEvent("listener:status", map[string]string{"id": id, "status": protocol.ListenerStopped})
	}

	log.Printf("[Listener] Stopped %s", id)
	return nil
}

// Stop stops the TCP listener.
func (tl *TCPListener) Stop() {
	tl.mu.Lock()
	defer tl.mu.Unlock()

	if !tl.running {
		return
	}
	tl.running = false
	close(tl.stopCh)
	tl.listener.Close()
}

func (tl *TCPListener) acceptLoop() {
	for {
		conn, err := tl.listener.Accept()
		if err != nil {
			select {
			case <-tl.stopCh:
				return
			default:
				log.Printf("[Listener] Accept error: %v", err)
				continue
			}
		}

		remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		if !tl.server.allowConn(remoteIP) {
			log.Printf("[Listener] Rate limited connection from %s", remoteIP)
			conn.Close()
			continue
		}

		go func() {
			defer tl.server.releaseConn()
			handleConnection(tl.server, tl.id, conn)
		}()
	}
}

// connIdleTimeout is how long an accepted connection may wait for its first
// packet before it is reclaimed. Agents use short-lived connections (one
// exchange per session — the stealthy UDP model), so this window is deliberately
// small: it only needs to cover the agent's dial + first packet.
const connIdleTimeout = 15 * time.Second

// handleConnection serves a single packet exchange on an accepted connection.
// It is shared by the TCP and KCP listeners. Agents dial a fresh short-lived
// connection for every register/checkin and close it right after — keeping the
// source port random (stealth) while the session on the server side is torn
// down and its rate-limit slot released as soon as the exchange completes.
func handleConnection(s *Server, listenerID string, conn net.Conn) {
	defer conn.Close()
	if _, ok := conn.(*kcp.UDPSession); ok {
		// KCP reliability: kcp-go's Close() flushes once but drops anything the
		// peer has not acknowledged — on UDP a lost first datagram is never
		// retransmitted, so short-lived agents silently lost RegisterAck/Task
		// replies → read timeout → re-register → rate-limited storm. Holding the
		// session open briefly after replying lets the KCP updater retransmit
		// unacknowledged data. (defer LIFO: this runs before conn.Close().)
		defer func() {
			time.Sleep(250 * time.Millisecond)
		}()
	}

	conn.SetReadDeadline(time.Now().Add(connIdleTimeout))
	pkt, err := protocol.ReadPacket(conn)
	if err != nil {
		return
	}

	switch pkt.Type {
	case protocol.TypeRegister:
		handleRegister(s, listenerID, conn, pkt)
	case protocol.TypeCheckin:
		handleCheckin(s, conn, pkt)
	case protocol.TypeRequestKey:
		// Agents without a compiled-in public key (e.g. CLI mode) request it
		// here before registering. The PEM is public, so no encryption needed.
		_ = protocol.WritePacket(conn, &protocol.Packet{Type: protocol.TypeServerKey, Payload: s.GetRSAPublicKeyPEM()})
	default:
		log.Printf("[Listener] Unknown packet type 0x%02x from %s", pkt.Type, conn.RemoteAddr())
	}
}

func handleRegister(s *Server, listenerID string, conn net.Conn, pkt *protocol.Packet) {
	// Extract remote IP
	remoteAddr := conn.RemoteAddr().String()
	host, _, _ := net.SplitHostPort(remoteAddr)

	_, encrypted, err := s.processRegistration(pkt.Payload, listenerID, host)
	if err != nil {
		log.Printf("[Listener] Registration rejected from %s: %v", remoteAddr, err)
		return
	}

	// Send ACK
	ackPkt := &protocol.Packet{Type: protocol.TypeRegisterAck, Payload: encrypted}
	protocol.WritePacket(conn, ackPkt)
}

func handleCheckin(s *Server, conn net.Conn, pkt *protocol.Packet) {
	// The checkin payload is: AgentID(16 bytes hex) + seq(8 bytes BE) + encrypted body
	if len(pkt.Payload) < 24 {
		return
	}

	agentID := string(pkt.Payload[:16])
	seq := binary.BigEndian.Uint64(pkt.Payload[16:24])
	encryptedBody := pkt.Payload[24:]

	encrypted, err := s.processCheckin(agentID, seq, encryptedBody)
	if err != nil {
		log.Printf("[Listener] Checkin failed for %s: %v", agentID, err)
		// Signal the agent to re-register (session unknown after restart)
		protocol.WritePacket(conn, &protocol.Packet{Type: protocol.TypeClose})
		return
	}

	taskPkt := &protocol.Packet{Type: protocol.TypeTask, Payload: encrypted}
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	protocol.WritePacket(conn, taskPkt)
}

// TaskResult is the structure sent by the agent for completed tasks.
type TaskResult struct {
	TaskID string `json:"task_id"`
	Output string `json:"output"`
	Status string `json:"status"`
}

// generateSelfSignedCert creates a self-signed TLS certificate.
func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"Wisp"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}, nil
}

// loadOrGenerateTLSCert loads the persistent self-signed TLS certificate, or
// generates and stores a new one on first run. Persisting it keeps the
// certificate fingerprint stable across server restarts.
func (s *Server) loadOrGenerateTLSCert() (tls.Certificate, error) {
	certPath := filepath.Join(s.db.DataDir(), "tls", "cert.pem")
	keyPath := filepath.Join(s.db.DataDir(), "tls", "key.pem")

	if certData, err := os.ReadFile(certPath); err == nil {
		if keyData, err := os.ReadFile(keyPath); err == nil {
			if cert, err := tls.X509KeyPair(certData, keyData); err == nil {
				return cert, nil
			}
		}
	}

	cert, err := generateSelfSignedCert()
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := os.MkdirAll(filepath.Dir(certPath), 0700); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return tls.Certificate{}, err
	}

	return cert, nil
}
