package services

import (
	"strings"
	"testing"

	"github.com/user/wisp/internal/db"
)

// openTestDB opens a temp database cleaned up at test end.
func openTestDB(t *testing.T) (*db.Database, error) {
	database, err := db.Open(t.TempDir())
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { database.Close() })
	return database, nil
}

func newTestListenerService(t *testing.T) (*ListenerService, *ServerService) {
	t.Helper()
	svc := &ServerService{}
	// Minimal server service with a temp db so Create can persist
	dbase, err := openTestDB(t)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	svc.db = dbase
	return &ListenerService{serverSvc: svc}, svc
}

func TestCreateValidation(t *testing.T) {
	ls, _ := newTestListenerService(t)

	// Empty name
	if _, err := ls.Create("", "tcp", "127.0.0.1", "0.0.0.0", 4444, false, ""); err == nil {
		t.Error("empty name should fail")
	}

	// Unsupported protocol
	if _, err := ls.Create("x", "dns", "127.0.0.1", "0.0.0.0", 53, false, ""); err == nil {
		t.Error("unsupported protocol should fail")
	}

	// Invalid port
	if _, err := ls.Create("x", "tcp", "127.0.0.1", "0.0.0.0", 70000, false, ""); err == nil {
		t.Error("invalid port should fail")
	}
	if _, err := ls.Create("x", "tcp", "127.0.0.1", "0.0.0.0", 0, false, ""); err == nil {
		t.Error("zero port should fail")
	}
}

func TestCreateHTTPSEnablesTLS(t *testing.T) {
	ls, _ := newTestListenerService(t)

	info, err := ls.Create("https-01", "https", "127.0.0.1", "0.0.0.0", 8443, false, "k")
	if err != nil {
		t.Fatalf("create https: %v", err)
	}
	if !info.UseTLS {
		t.Error("https listener should have TLS enabled")
	}
	if info.Protocol != "https" {
		t.Errorf("protocol = %q", info.Protocol)
	}
	if info.PSK != "k" {
		t.Errorf("psk = %q", info.PSK)
	}
}

func TestCreateDefaultBindHost(t *testing.T) {
	ls, _ := newTestListenerService(t)

	info, err := ls.Create("tcp-01", "tcp", "127.0.0.1", "", 4444, false, "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if info.BindHost != "0.0.0.0" {
		t.Errorf("bind host = %q, want 0.0.0.0", info.BindHost)
	}
	if info.Host != "127.0.0.1" {
		t.Errorf("callback host = %q, want 127.0.0.1", info.Host)
	}
}

func TestCreateHostAutoDetected(t *testing.T) {
	ls, _ := newTestListenerService(t)

	// Empty callback host must be replaced with a real, routable IP
	// (never 0.0.0.0 or empty), otherwise generated payloads cannot connect.
	info, err := ls.Create("tcp-auto", "tcp", "", "0.0.0.0", 5555, false, "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if info.Host == "" || info.Host == "0.0.0.0" || info.Host == "::" {
		t.Errorf("callback host not auto-detected: %q", info.Host)
	}
	if info.BindHost != "0.0.0.0" {
		t.Errorf("bind host = %q, want 0.0.0.0", info.BindHost)
	}
}

func TestSupportedProtocols(t *testing.T) {
	ls, _ := newTestListenerService(t)
	protos := ls.GetSupportedProtocols()
	if len(protos) != 5 {
		t.Fatalf("protocols = %v, want 5", protos)
	}
	joined := strings.Join(protos, ",")
	for _, p := range []string{"tcp", "http", "https", "kcp", "quic"} {
		if !strings.Contains(joined, p) {
			t.Errorf("missing protocol %s in %v", p, protos)
		}
	}
}
