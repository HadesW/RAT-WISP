package listener

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wispp/protocol"
	"wispp/server/internal/core"
	"wispp/server/internal/db"
	"wispp/server/internal/stage"
)

func TestManagerLifecycle(t *testing.T) {
	store, err := db.Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.DB.Close()
	hub := core.NewHub(store)
	key, _ := protocol.GenerateRSAKey(2048)
	deps := Deps{Hub: hub, PSK: "p", Priv: key, Stage: stage.New(time.Minute), DataDir: t.TempDir(), SleepMS: 1000, Jitter: 10}
	mgr := NewManager(deps, store)

	v, err := mgr.Create(Spec{Kind: "http", Addr: "127.0.0.1:18443", Project: "default"})
	if err != nil {
		t.Fatal(err)
	}
	if len(mgr.List()) != 1 {
		t.Fatal("list")
	}
	// profile persisted row restored by a fresh manager
	if _, err := mgr.Create(Spec{ID: v.ID, Kind: "http", Addr: "127.0.0.1:18444"}); err != ErrExists {
		t.Fatalf("dup id: %v", err)
	}
	// pubkey bootstrap through the managed listener
	time.Sleep(200 * time.Millisecond)
	resp, err := http.Post("http://127.0.0.1:18443/submit", "application/json", bytes.NewReader(
		mustEnv(t, protocol.MsgPubkey)))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	env, err := protocol.ReadEnvelope(body)
	if err != nil {
		t.Fatalf("pubkey via manager: %v %s", err, body)
	}
	var pk protocol.PubkeyInfo
	_ = env.DecodePlain(&pk)
	if pk.PEM == "" {
		t.Fatal("empty pem")
	}
	// stop → dead, start → alive again
	if err := mgr.Stop(v.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := http.Post("http://127.0.0.1:18443/submit", "application/json", bytes.NewReader(mustEnv(t, protocol.MsgPubkey))); err == nil {
		t.Fatal("listener alive after stop")
	}
	if err := mgr.Start(v.ID); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if _, err := http.Post("http://127.0.0.1:18443/submit", "application/json", bytes.NewReader(mustEnv(t, protocol.MsgPubkey))); err != nil {
		t.Fatalf("listener dead after start: %v", err)
	}
	// restore path: new manager over same store sees the row (free the port first)
	_ = mgr.Stop(v.ID)
	m2 := NewManager(Deps{Hub: hub, PSK: "p", Priv: key, Stage: stage.New(time.Minute), DataDir: t.TempDir()}, store)
	if err := m2.Restore(); err != nil {
		t.Fatal(err)
	}
	if len(m2.List()) != 1 || !m2.List()[0].Running {
		t.Fatalf("restore: %+v", m2.List())
	}
	_ = json.Unmarshal
}

func mustEnv(t *testing.T, typ string) []byte {
	t.Helper()
	e := &protocol.Envelope{V: protocol.ProtocolVersion, Type: typ}
	b, _ := json.Marshal(e)
	return b
}

func TestRCPAdvertisedDeterministic(t *testing.T) {
	m := &Manager{live: map[string]*running{
		"kcp": {seq: 3, on: true, spec: Spec{ID: "kcp", Kind: "rcp-kcp", Addr: "127.0.0.1:9500"}},
		"dev": {seq: 2, on: true, spec: Spec{ID: "dev", Kind: "rcp", Addr: "127.0.0.1:9200"}},
		"vm":  {seq: 1, on: true, spec: Spec{ID: "vm", Kind: "rcp", Addr: "0.0.0.0:9210", Host: "192.168.32.1:9210"}},
		"off": {seq: 0, on: false, spec: Spec{ID: "off", Kind: "rcp", Host: "dead:1"}},
	}}
	// map iteration order is random: a wrong implementation flips results here
	for i := 0; i < 200; i++ {
		if got := m.rcpAdvertised(); got != "192.168.32.1:9210" {
			t.Fatalf("advertised %q, want the explicit-host rcp listener", got)
		}
	}
	delete(m.live, "vm")
	if got := m.rcpAdvertised(); got != "127.0.0.1:9200" {
		t.Fatalf("advertised %q, want plain rcp before kcp", got)
	}
	delete(m.live, "dev")
	if got := m.rcpAdvertised(); got != "kcp://127.0.0.1:9500" {
		t.Fatalf("advertised %q, want kcp fallback", got)
	}
	delete(m.live, "kcp")
	if got := m.rcpAdvertised(); got != "" {
		t.Fatalf("advertised %q, want empty", got)
	}
}

func TestAnyHTTPPrefersReachableAdvertise(t *testing.T) {
	mgr := NewManager(Deps{}, nil)
	add := func(id, kind, addr, host string, seq int64) {
		mgr.order[id] = seq
		mgr.live[id] = &running{spec: Spec{ID: id, Kind: kind, Addr: addr, Host: host}, on: true}
	}
	add("loop", "http", "127.0.0.1:9000", "", 1)
	add("adv", "http", "0.0.0.0:9010", "192.168.32.1:9010", 2)
	if got, ok := mgr.AnyHTTP(); !ok || got.ID != "adv" {
		t.Fatalf("want advertised http, got %+v ok=%v", got, ok)
	}
	// wildcard bind with no advertised host is not dialable from a target
	add("wild", "http", "0.0.0.0:9020", "", 0)
	if got, _ := mgr.AnyHTTP(); got.ID != "adv" {
		t.Fatalf("wildcard bind won over advertised host: %+v", got)
	}
	// usable https loses to usable http
	add("tls", "https", "0.0.0.0:9443", "10.0.0.5:9443", 0)
	if got, _ := mgr.AnyHTTP(); got.ID != "adv" {
		t.Fatalf("https won over usable http: %+v", got)
	}
	// stop the preferred one: a reachable https now beats loopback http
	mgr.live["adv"].on = false
	if got, _ := mgr.AnyHTTP(); got.ID != "tls" {
		t.Fatalf("want reachable https fallback, got %+v", got)
	}
	// loopback-only fallback is still returned rather than failing
	mgr.live["tls"].on = false
	if got, ok := mgr.AnyHTTP(); !ok || got.ID != "loop" {
		t.Fatalf("want loopback fallback, got %+v ok=%v", got, ok)
	}
}

func TestCertInfo(t *testing.T) {
	mgr := NewManager(Deps{DataDir: t.TempDir()}, nil)
	if got := mgr.certInfo(Spec{ID: "t", Kind: "https", Addr: "127.0.0.1:9443"}); got != nil {
		t.Fatalf("cert before start: %+v", got)
	}
	if crt, _ := mgr.selfSigned("127.0.0.1:9443", ""); crt == "" {
		t.Fatal("selfSigned returned no cert")
	}
	info := mgr.certInfo(Spec{ID: "t", Kind: "https", Addr: "127.0.0.1:9443"})
	if info == nil {
		t.Fatal("certInfo nil after generation")
	}
	if !info.SelfSigned || len(info.SHA256) != 64 || !info.NotAfter.After(time.Now()) {
		t.Fatalf("bad cert info: %+v", info)
	}
	if !strings.Contains(info.Subject, "127.0.0.1") {
		t.Fatalf("subject: %q", info.Subject)
	}
}

func TestSelfSignedUsesAdvertise(t *testing.T) {
	mgr := NewManager(Deps{DataDir: t.TempDir()}, nil)
	if _, key := mgr.selfSigned("0.0.0.0:9443", "192.168.32.1:9011"); key == "" {
		t.Fatal("selfSigned returned no key")
	}
	info := mgr.certInfo(Spec{ID: "t2", Kind: "https", Addr: "0.0.0.0:9443"})
	if info == nil || !strings.Contains(info.Subject, "192.168.32.1") {
		t.Fatalf("CN not derived from advertise: %+v", info)
	}
	sans := strings.Join(append(append([]string{}, info.DNS...), info.IPs...), " ")
	if !strings.Contains(sans, "192.168.32.1") || !strings.Contains(sans, "127.0.0.1") {
		t.Fatalf("SANs: %q", sans)
	}
}

func TestSetAndClearCert(t *testing.T) {
	mgr := NewManager(Deps{DataDir: t.TempDir()}, nil)
	spec := Spec{ID: "x", Kind: "https", Addr: "127.0.0.1:9443"}
	mgr.live[spec.ID] = &running{spec: spec, on: false}
	autoCRT, autoKey := mgr.selfSigned(spec.Addr, "")
	certPEM, err := os.ReadFile(autoCRT)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(autoKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.SetCert(spec.ID, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	info := mgr.certInfo(spec)
	if info == nil || !info.Imported {
		t.Fatalf("imported cert not reported: %+v", info)
	}
	if err := mgr.SetCert(spec.ID, certPEM, []byte("not a key")); err == nil {
		t.Fatal("mismatched key accepted")
	}
	if err := mgr.SetCert("missing", certPEM, keyPEM); err != ErrNotFound {
		t.Fatalf("missing listener: %v", err)
	}
	tcp := Spec{ID: "tcp", Kind: "tcp", Addr: "127.0.0.1:9000"}
	mgr.live[tcp.ID] = &running{spec: tcp}
	if err := mgr.SetCert(tcp.ID, certPEM, keyPEM); err != ErrNotTLS {
		t.Fatalf("tcp listener accepted a cert: %v", err)
	}
	if err := mgr.ClearCert(spec.ID); err != nil {
		t.Fatal(err)
	}
	if info := mgr.certInfo(spec); info == nil || info.Imported {
		t.Fatalf("self-signed fallback not restored: %+v", info)
	}
}

func TestStatsMiddleware(t *testing.T) {
	st := &listenerStats{}
	h := withStats(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("oops"))
	}), st)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader("abc")))
	v := st.view()
	if v.Requests != 1 || v.BytesIn != 3 || v.BytesOut != 4 || v.Errors != 1 {
		t.Fatalf("stats: %+v", v)
	}
	if !strings.Contains(v.LastError, "500") || v.LastSeen.IsZero() {
		t.Fatalf("last error/seen: %+v", v)
	}
}

func TestStatsConnCounts(t *testing.T) {
	st := &listenerStats{}
	a, b := net.Pipe()
	defer b.Close()
	c := &statsConn{Conn: a, st: st}
	go func() { _, _ = b.Write([]byte("in")) }()
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = io.ReadFull(b, buf[:2]) }()
	if _, err := c.Write([]byte("ou")); err != nil {
		t.Fatal(err)
	}
	v := st.view()
	if v.BytesIn != 2 || v.BytesOut != 2 {
		t.Fatalf("conn bytes: %+v", v)
	}
}
