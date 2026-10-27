// Package rcp is the Type2 long-lived channel hub (plan §2.3): agents dial
// in with a stateless token, the web console relays logical channels
// (shell / view / fwd) over WebSocket without touching Type1 sleep cycles.
package rcp

import (
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"wispp/protocol"
)

// ErrNotOnline means the agent has no live RCP connection.
var ErrNotOnline = errors.New("rcp: agent not connected")

// Logger receives hub events (wired to core.Hub.Emit in wispd).
type Logger func(level, kind, text string)

// Delivery is one item on a channel's read side: a raw data payload or a
// JSON control frame (file channels use both, plan §2.4).
type Delivery struct {
	Ctrl bool
	Data []byte
}

// Channel is one logical stream inside an agent's RCP connection.
type Channel struct {
	ID   uint32
	Kind string

	sub    chan Delivery
	once   sync.Once
	closed atomic.Bool
	done   chan struct{} // parent connection teardown (blocks reliable pushes)
}

// Sub returns the read side: payloads arriving from the agent.
func (c *Channel) Sub() <-chan Delivery { return c.sub }

// push delivers a frame from the agent. Realtime (view) channels drop when
// the consumer is slow; shell/file channels apply backpressure instead —
// dropping bytes would corrupt transfers (plan §2.4 integrity guarantee).
func (c *Channel) push(d Delivery) {
	if c.closed.Load() {
		return
	}
	if c.Kind == protocol.RCPChanView {
		select {
		case c.sub <- d:
		default:
		}
		return
	}
	select {
	case c.sub <- d:
	case <-c.done:
	}
}

func (c *Channel) close() {
	c.once.Do(func() {
		c.closed.Store(true)
		close(c.sub)
	})
}

// Client is one agent's RCP connection.
type Client struct {
	agent string
	conn  net.Conn

	send    chan *protocol.RCPFrame
	seq     atomic.Uint32
	mu      sync.Mutex
	chans   map[uint32]*Channel
	done    chan struct{}
	closing sync.Once
}

// stop closes done exactly once (safe against Drop vs handshake race).
func (cl *Client) stop() { cl.closing.Do(func() { close(cl.done) }) }

// Hub tracks connected agents and their channels.
type Hub struct {
	mu      sync.RWMutex
	clients map[string]*Client
	PSK     string
	Log     Logger
}

func NewHub(psk string, log Logger) *Hub {
	return &Hub{clients: make(map[string]*Client), PSK: psk, Log: log}
}

func (h *Hub) logf(level, format string, args ...any) {
	if h.Log != nil {
		h.Log(level, "rcp", fmt.Sprintf(format, args...))
	}
}

// Serve accepts agent dials until ln closes.
func (h *Hub) Serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go h.handshake(c)
	}
}

func (h *Hub) handshake(c net.Conn) {
	serverNonce, err := protocol.NewRCPNonce()
	if err != nil {
		c.Close()
		return
	}
	_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := protocol.WriteRCPFrame(c, &protocol.RCPFrame{Kind: protocol.RCPKindChallenge,
		Payload: mustJSON(protocol.RCPChallenge{Nonce: serverNonce})}); err != nil {
		c.Close()
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	f, err := protocol.ReadRCPFrame(c)
	if err != nil || f.Kind != protocol.RCPKindHello {
		c.Close()
		return
	}
	var hello protocol.RCPHello
	if err := json.Unmarshal(f.Payload, &hello); err != nil || hello.Agent == "" ||
		len(hello.Agent) > 128 || len(hello.Nonce) != 32 {
		c.Close()
		return
	}
	key := protocol.RCPKey(h.PSK, hello.Agent)
	want := protocol.RCPAgentProof(key, hello.Agent, serverNonce, hello.Nonce)
	if !hmac.Equal([]byte(want), []byte(hello.Proof)) {
		h.logf("err", "RCP hello rejected from %v (bad proof)", c.RemoteAddr())
		_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_ = protocol.WriteRCPFrame(c, &protocol.RCPFrame{Kind: protocol.RCPKindAck,
			Payload: mustJSON(protocol.RCPAck{OK: false, Reason: "auth"})})
		c.Close()
		return
	}
	_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	ack := protocol.RCPAck{OK: true,
		Proof: protocol.RCPServerProof(key, hello.Agent, serverNonce, hello.Nonce)}
	if err := protocol.WriteRCPFrame(c, &protocol.RCPFrame{Kind: protocol.RCPKindAck,
		Payload: mustJSON(ack)}); err != nil {
		c.Close()
		return
	}

	cl := &Client{
		agent: hello.Agent, conn: c,
		send:  make(chan *protocol.RCPFrame, 64),
		chans: make(map[uint32]*Channel),
		done:  make(chan struct{}),
	}
	h.mu.Lock()
	if old, ok := h.clients[cl.agent]; ok {
		// takeover: only cut the old socket — that old handshake goroutine
		// owns its own channel cleanup and done close (never close twice).
		old.conn.Close()
	}
	h.clients[cl.agent] = cl
	h.mu.Unlock()
	h.logf("ok", "RCP channel up for agent %s (%v)", shortID(cl.agent), c.RemoteAddr())

	go cl.writeLoop()
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	go func() { // keepalive piggy-backed on the writer queue
		for {
			select {
			case <-cl.done:
				return
			case <-ticker.C:
				cl.push(&protocol.RCPFrame{Kind: protocol.RCPKindPing, Seq: cl.seq.Add(1)})
			}
		}
	}()

	cl.readLoop()

	h.mu.Lock()
	if h.clients[cl.agent] == cl {
		delete(h.clients, cl.agent)
	}
	h.mu.Unlock()
	cl.mu.Lock()
	for _, ch := range cl.chans {
		ch.close()
	}
	cl.mu.Unlock()
	cl.stop()
	c.Close()
	h.logf("warn", "RCP connection lost for %s", shortID(cl.agent))
}

func (cl *Client) readLoop() {
	for {
		_ = cl.conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		f, err := protocol.ReadRCPFrame(cl.conn)
		if err != nil {
			return
		}
		switch f.Kind {
		case protocol.RCPKindFrame:
			cl.mu.Lock()
			ch := cl.chans[f.Chan]
			cl.mu.Unlock()
			if ch != nil {
				ch.push(Delivery{Ctrl: f.Flags&protocol.RCPFlagJSON != 0, Data: f.Payload})
			}
		case protocol.RCPKindPong:
			// liveness refreshed implicitly via deadline
		case protocol.RCPKindClose: // agent refuses/notifies a channel
			var pc protocol.RCPClose
			_ = json.Unmarshal(f.Payload, &pc)
			cl.mu.Lock()
			if ch := cl.chans[pc.Chan]; ch != nil {
				delete(cl.chans, pc.Chan)
				ch.close()
			}
			cl.mu.Unlock()
		case protocol.RCPKindPing:
			cl.push(&protocol.RCPFrame{Chan: f.Chan, Kind: protocol.RCPKindPong, Seq: cl.seq.Add(1)})
		default:
			return // protocol violation: drop
		}
	}
}

func (cl *Client) writeLoop() {
	for {
		select {
		case <-cl.done:
			return
		case f := <-cl.send:
			_ = cl.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if err := protocol.WriteRCPFrame(cl.conn, f); err != nil {
				return
			}
		}
	}
}

func (cl *Client) push(f *protocol.RCPFrame) bool {
	select {
	case cl.send <- f:
		return true
	case <-cl.done:
		return false
	}
}

// Online reports whether an agent has a live RCP connection.
// Drop force-closes an agent's Type2 connection (operator disconnect).
func (h *Hub) Drop(agentID string) {
	h.mu.Lock()
	c := h.clients[agentID]
	if c != nil {
		delete(h.clients, agentID)
	}
	h.mu.Unlock()
	if c != nil {
		c.stop()
		_ = c.conn.Close()
	}
}

func (h *Hub) Online(agentID string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	_, ok := h.clients[agentID]
	return ok
}

// OnlineCount reports the number of live Type2 connections.
func (h *Hub) OnlineCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// Open starts a channel on the agent's RCP connection.
func (h *Hub) Open(agentID, kind string, args json.RawMessage) (*Channel, error) {
	h.mu.RLock()
	cl := h.clients[agentID]
	h.mu.RUnlock()
	if cl == nil {
		return nil, ErrNotOnline
	}
	ch := &Channel{ID: cl.seq.Add(1), Kind: kind, sub: make(chan Delivery, 128), done: cl.done}
	cl.mu.Lock()
	cl.chans[ch.ID] = ch
	cl.mu.Unlock()
	payload, _ := json.Marshal(protocol.RCPOpen{Chan: ch.ID, Kind: kind, Args: args})
	if !cl.push(&protocol.RCPFrame{Chan: ch.ID, Kind: protocol.RCPKindOpen,
		Seq: ch.ID, Payload: payload}) {
		return nil, errors.New("rcp: agent write queue closed")
	}
	return ch, nil
}

// Input sends user bytes toward a channel.
func (h *Hub) Input(agentID string, chanID uint32, data []byte) error {
	h.mu.RLock()
	cl := h.clients[agentID]
	h.mu.RUnlock()
	if cl == nil {
		return ErrNotOnline
	}
	// reliable queue for input: never silently drop typed keystrokes
	select {
	case cl.send <- &protocol.RCPFrame{Chan: chanID, Kind: protocol.RCPKindFrame,
		Seq: cl.seq.Add(1), Payload: data}:
		return nil
	case <-cl.done:
		return errors.New("rcp: agent gone")
	}
}

// Close tears a channel down on both sides.
func (h *Hub) Close(agentID string, chanID uint32, reason string) {
	h.mu.RLock()
	cl := h.clients[agentID]
	h.mu.RUnlock()
	if cl == nil {
		return
	}
	cl.mu.Lock()
	ch := cl.chans[chanID]
	delete(cl.chans, chanID)
	cl.mu.Unlock()
	if ch != nil {
		ch.close()
	}
	payload, _ := json.Marshal(protocol.RCPClose{Chan: chanID, Reason: reason})
	cl.push(&protocol.RCPFrame{Chan: chanID, Kind: protocol.RCPKindClose, Payload: payload})
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

// shortID never trusts the wire: agents/scanners may send arbitrarily short ids.
func shortID(s string) string {
	if len(s) <= 8 {
		return s
	}
	return s[:8]
}

// SendCtrl delivers a JSON control frame to the agent on a channel.
func (h *Hub) SendCtrl(agentID string, chanID uint32, payload []byte) error {
	h.mu.RLock()
	cl := h.clients[agentID]
	h.mu.RUnlock()
	if cl == nil {
		return ErrNotOnline
	}
	select {
	case cl.send <- &protocol.RCPFrame{Chan: chanID, Kind: protocol.RCPKindFrame, Flags: protocol.RCPFlagJSON,
		Seq: cl.seq.Add(1), Payload: payload}:
		return nil
	case <-cl.done:
		return errors.New("rcp: agent gone")
	}
}
