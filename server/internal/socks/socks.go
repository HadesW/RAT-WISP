// Package socks serves a SOCKS5 (RFC1928, no-auth, CONNECT-only) proxy that
// routes through an agent's Type2 channel: dynamic pivoting into the target's
// network without enumerating ports up front (plan §2.3).
package socks

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"wispp/server/internal/db"
	"wispp/server/internal/fwd"
	"wispp/server/internal/rcp"
)

type Svc struct {
	Hub   *rcp.Hub
	Store *db.Store
	Emit  func(level, text string)

	mu  sync.Mutex
	liv map[string]*entry
}

type entry struct {
	id, session string
	ln          net.Listener
	bound       string
}

func New(hub *rcp.Hub, store *db.Store, emit func(string, string)) *Svc {
	return &Svc{Hub: hub, Store: store, Emit: emit, liv: map[string]*entry{}}
}

// Start binds listen (":0" ok) and serves SOCKS5 CONNECT via session's RCP.
func (s *Svc) Start(session, listen string) (id, bound string, err error) {
	if !s.Hub.Online(session) {
		return "", "", errors.New("agent RCP offline (Type2 required)")
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return "", "", err
	}
	e := &entry{id: randID(), session: session, ln: ln, bound: ln.Addr().String()}
	s.mu.Lock()
	s.liv[e.id] = e
	s.mu.Unlock()
	if s.Store != nil {
		_ = s.Store.FwdInsert(e.id, session, e.bound, "socks5://dynamic")
	}
	if s.Emit != nil {
		s.Emit("ok", "SOCKS5 proxy on "+e.bound+" via "+session[:min(8, len(session))])
	}
	go s.accept(e)
	return e.id, e.bound, nil
}

func (s *Svc) accept(e *entry) {
	for {
		c, err := e.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(e, c)
	}
}

// handle speaks just enough SOCKS5: greeting (no-auth) + CONNECT.
func (s *Svc) handle(e *entry, c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	// greeting: VER NMETHODS METHODS…
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil || hdr[0] != 0x05 {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil { // no auth
		return
	}
	// request: VER CMD RSV ATYP …
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil || req[0] != 0x05 || req[1] != 0x01 /*CONNECT*/ {
		return
	}
	var host string
	switch req[3] {
	case 0x01: // ipv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x03: // domain
		lb := make([]byte, 1)
		if _, err := io.ReadFull(c, lb); err != nil {
			return
		}
		dbuf := make([]byte, lb[0])
		if _, err := io.ReadFull(c, dbuf); err != nil {
			return
		}
		host = string(dbuf)
	case 0x04: // ipv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = "[" + net.IP(b).String() + "]"
	default:
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(pb))
	target := net.JoinHostPort(host, strconv.Itoa(port))
	// success reply with bound 0.0.0.0:0
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{}) // proxy data has its own pacing
	fwd.Bridge(s.Hub, e.session, target, c)
}

// Stop closes a proxy.
func (s *Svc) Stop(id string) error {
	s.mu.Lock()
	e, ok := s.liv[id]
	if ok {
		delete(s.liv, id)
	}
	s.mu.Unlock()
	if !ok {
		return errors.New("unknown proxy")
	}
	_ = e.ln.Close()
	if s.Store != nil {
		_ = s.Store.FwdStatus(id, "stopped")
	}
	return nil
}

// View lists live proxies.
type View struct {
	ID      string `json:"id"`
	Session string `json:"session"`
	Listen  string `json:"listen"`
	Status  string `json:"status"`
}

func (s *Svc) List() []View {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]View, 0, len(s.liv))
	for _, e := range s.liv {
		out = append(out, View{e.id, e.session, e.bound, "active"})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Listen < out[j].Listen })
	return out
}

func randID() string {
	b := make([]byte, 4)
	_, _ = crand.Read(b)
	return fmt.Sprintf("%x", b)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
