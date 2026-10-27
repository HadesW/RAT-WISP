// Package fwd implements local port-forwarding over Type2 (plan §2.3):
// teamserver listens on TCP; every accepted connection opens an RCP "fwd"
// channel and the agent bridges bytes to the target from inside the network.
package fwd

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"time"

	"wispp/protocol"
	"wispp/server/internal/core"
	"wispp/server/internal/db"
	"wispp/server/internal/rcp"
)

// Svc owns live forward listeners.
type Svc struct {
	Hub   *rcp.Hub
	Store *db.Store
	Emit  func(level, text string)

	mu  sync.Mutex
	liv map[string]*entry
}

type entry struct {
	id, session, target string
	ln                  net.Listener
	stop                chan struct{}
	bound               string
}

func New(hub *rcp.Hub, store *db.Store, emit func(string, string)) *Svc {
	return &Svc{Hub: hub, Store: store, Emit: emit, liv: map[string]*entry{}}
}

func genID() string {
	b := make([]byte, 5)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Start opens listen (":0" for auto) and bridges to target via session.
func (s *Svc) Start(session, listen, target string) (string, string, error) {
	if !s.Hub.Online(session) {
		return "", "", errors.New("agent RCP offline (Type2 required)")
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return "", "", err
	}
	id := genID()
	e := &entry{id: id, session: session, target: target, ln: ln, stop: make(chan struct{}), bound: ln.Addr().String()}
	s.mu.Lock()
	s.liv[id] = e
	s.mu.Unlock()
	if s.Store != nil {
		_ = s.Store.FwdInsert(id, session, e.bound, target)
	}
	if s.Emit != nil {
		s.Emit("ok", "forward "+e.bound+" → "+target+" via "+core.ShortID(session))
	}
	go s.accept(e)
	return id, e.bound, nil
}

func (s *Svc) accept(e *entry) {
	for {
		conn, err := e.ln.Accept()
		if err != nil {
			return
		}
		go Bridge(s.Hub, e.session, e.target, conn)
	}
}

// Bridge pumps one local conn through an RCP fwd channel to target (shared
// with the SOCKS5 service).
func Bridge(hub *rcp.Hub, session, target string, conn net.Conn) {
	defer conn.Close()
	args, _ := json.Marshal(protocol.FwdArgs{Target: target})
	ch, err := hub.Open(session, protocol.RCPChanFwd, args)
	if err != nil {
		return
	}
	defer hub.Close(session, ch.ID, "fwd closed")

	done := make(chan struct{})
	go func() { // client → agent
		buf := make([]byte, 32*1024)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if e := hub.Input(session, ch.ID, append([]byte(nil), buf[:n]...)); e != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		close(done)
	}()

	// agent → client (blocking delivery; channel closes on agent EOF)
	for {
		select {
		case <-done:
			return
		case d, ok := <-ch.Sub():
			if !ok {
				return
			}
			if d.Ctrl {
				continue
			}
			_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if _, err := conn.Write(d.Data); err != nil {
				return
			}
		}
	}
}

// Stop tears down one forward.
func (s *Svc) Stop(id string) error {
	s.mu.Lock()
	e, ok := s.liv[id]
	if ok {
		delete(s.liv, id)
	}
	s.mu.Unlock()
	if !ok {
		return errors.New("unknown forward")
	}
	select {
	case <-e.stop:
	default:
		close(e.stop)
	}
	_ = e.ln.Close()
	if s.Store != nil {
		_ = s.Store.FwdStatus(id, "stopped")
	}
	return nil
}

// View is the console projection.
type View struct {
	ID      string `json:"id"`
	Session string `json:"session"`
	Listen  string `json:"listen"`
	Target  string `json:"target"`
	Status  string `json:"status"`
}

// List merges history rows with live status.
func (s *Svc) List() []View {
	if s.Store == nil {
		return nil
	}
	rows, _ := s.Store.FwdList()
	out := make([]View, 0, len(rows))
	for _, r := range rows {
		st := r.Status
		s.mu.Lock()
		_, live := s.liv[r.ID]
		s.mu.Unlock()
		if r.Status == "active" && !live {
			st = "lost" // server restarted since
		}
		out = append(out, View{r.ID, r.Session, r.Listen, r.Target, st})
	}
	return out
}
