package services

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/user/wisp/internal/db"
	"github.com/user/wisp/internal/server"
	"github.com/user/wisp/shared/protocol"
)

// newPayloadTestService returns a ListenerService + a ServerService whose
// server engine is fully initialized (needed by makeAgentConfig).
func newPayloadTestService(t *testing.T) (*ListenerService, *ServerService) {
	t.Helper()
	ls, svc := newTestListenerService(t)
	srv, err := server.New(svc.db, nil)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	svc.server = srv
	return ls, svc
}

// TestPayloadUsesCallbackHost verifies the config baked into a generated
// payload uses the listener callback address (Host), never the bind address
// (0.0.0.0 -> 127.0.0.1 bug). This is the Cobalt Strike Host/Bind separation.
func TestPayloadUsesCallbackHost(t *testing.T) {
	ls, svc := newPayloadTestService(t)
	ps := NewPayloadService(svc)

	// Template payloads are read from <exe>/templates; point generation at a
	// temp dir holding a dummy template (only the overlay matters here).
	tmplDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmplDir, "agent_windows_amd64.exe"), []byte("MZ\x90\x00\x03"), 0755); err != nil {
		t.Fatalf("write dummy template: %v", err)
	}
	templateDirOverride = tmplDir
	t.Cleanup(func() { templateDirOverride = "" })

	// Listener with a distinct callback host vs bind host.
	info, err := ls.Create("cb-test", "tcp", "192.168.75.130", "0.0.0.0", 4444, false, "")
	if err != nil {
		t.Fatalf("create listener: %v", err)
	}

	out := filepath.Join(t.TempDir(), "agent.exe")
	path, err := ps.Generate(PayloadConfig{
		ListenerID: info.ID,
		TargetOS:   "windows",
		TargetArch: "amd64",
		Type:       "exe",
		Method:     "template",
		Sleep:      5000,
		Jitter:     20,
		OutputPath: out,
	})
	if err != nil {
		t.Fatalf("generate payload: %v", err)
	}
	if path != out {
		t.Errorf("output path = %q, want %q", path, out)
	}

	// Read the overlay config from the end of the payload.
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read payload: %v", err)
	}
	idx := lastIndexBytes(data, protocol.OverlayMarker)
	if idx < 0 {
		t.Fatal("overlay marker not found in payload")
	}
	cfgB64 := strings.TrimSpace(string(data[idx+len(protocol.OverlayMarker):]))
	cfgJSON, err := base64.StdEncoding.DecodeString(cfgB64)
	if err != nil {
		t.Fatalf("decode overlay: %v", err)
	}
	var cfg AgentConfig
	if err := json.Unmarshal(cfgJSON, &cfg); err != nil {
		t.Fatalf("unmarshal overlay: %v", err)
	}

	if cfg.ServerHost != "192.168.75.130" {
		t.Errorf("payload server_host = %q, want 192.168.75.130 (callback host)", cfg.ServerHost)
	}
	if cfg.ServerPort != 4444 {
		t.Errorf("payload server_port = %d, want 4444", cfg.ServerPort)
	}
	if cfg.Transport != "tcp" {
		t.Errorf("payload transport = %q, want tcp", cfg.Transport)
	}
	if cfg.Sleep != 5000 {
		t.Errorf("payload sleep = %d, want 5000", cfg.Sleep)
	}
}

// TestPayloadFallbackCallbackHost covers legacy listeners with an empty Host:
// the payload must still fall back to a routable address, never 127.0.0.1 for
// a 0.0.0.0 bind.
func TestPayloadFallbackCallbackHost(t *testing.T) {
	_, svc := newPayloadTestService(t)
	ps := NewPayloadService(svc)

	// Simulate a legacy row where Host was never populated.
	legacy := &db.ListenerRow{
		ID:       "legacy-1",
		Name:     "legacy",
		Protocol: "tcp",
		Host:     "",
		BindHost: "0.0.0.0",
		BindPort: 5555,
	}
	cfg := ps.makeAgentConfig(PayloadConfig{Sleep: 5000, Jitter: 10}, legacy)
	if cfg.ServerHost == "" || cfg.ServerHost == "0.0.0.0" || cfg.ServerHost == "127.0.0.1" {
		t.Errorf("fallback callback host is unusable: %q", cfg.ServerHost)
	}
}

func lastIndexBytes(haystack []byte, needle []byte) int {
	for i := len(haystack) - len(needle); i >= 0; i-- {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// TestPayloadDLLTemplate verifies DLL payloads can be generated from a prebuilt
// DLL template (c-shared agent), appending the same config overlay. The overlay
// is read back by the DLL via its own module path at load time.
func TestPayloadDLLTemplate(t *testing.T) {
	ls, svc := newPayloadTestService(t)
	ps := NewPayloadService(svc)

	tmplDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmplDir, "agent_windows_amd64.dll"), []byte("MZ\x90\x00\x00\x00\x00\x00"), 0755); err != nil {
		t.Fatalf("write dummy dll template: %v", err)
	}
	templateDirOverride = tmplDir
	t.Cleanup(func() { templateDirOverride = "" })

	info, err := ls.Create("dll-test", "tcp", "192.168.75.130", "0.0.0.0", 4444, false, "")
	if err != nil {
		t.Fatalf("create listener: %v", err)
	}

	out := filepath.Join(t.TempDir(), "agent.dll")
	path, err := ps.Generate(PayloadConfig{
		ListenerID: info.ID,
		TargetOS:   "windows",
		TargetArch: "amd64",
		Type:       "dll",
		Method:     "template",
		Sleep:      5000,
		Jitter:     20,
		OutputPath: out,
	})
	if err != nil {
		t.Fatalf("generate dll payload: %v", err)
	}
	if path != out {
		t.Errorf("output path = %q, want %q", path, out)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read dll payload: %v", err)
	}
	idx := lastIndexBytes(data, protocol.OverlayMarker)
	if idx < 0 {
		t.Fatal("overlay marker not found in dll payload")
	}
	cfgB64 := strings.TrimSpace(string(data[idx+len(protocol.OverlayMarker):]))
	cfgJSON, err := base64.StdEncoding.DecodeString(cfgB64)
	if err != nil {
		t.Fatalf("decode overlay: %v", err)
	}
	var cfg AgentConfig
	if err := json.Unmarshal(cfgJSON, &cfg); err != nil {
		t.Fatalf("unmarshal overlay: %v", err)
	}
	if cfg.ServerHost != "192.168.75.130" {
		t.Errorf("dll payload server_host = %q, want callback host", cfg.ServerHost)
	}
}

// TestPayloadDLLNonWindowsRejected verifies DLL payloads are Windows-only.
func TestPayloadDLLNonWindowsRejected(t *testing.T) {
	ls, svc := newPayloadTestService(t)
	ps := NewPayloadService(svc)

	info, err := ls.Create("dll-x", "tcp", "127.0.0.1", "0.0.0.0", 4444, false, "")
	if err != nil {
		t.Fatalf("create listener: %v", err)
	}

	_, err = ps.Generate(PayloadConfig{
		ListenerID: info.ID,
		TargetOS:   "linux",
		TargetArch: "amd64",
		Type:       "dll",
		Method:     "template",
		Sleep:      5000,
		Jitter:     20,
	})
	if err == nil || !strings.Contains(err.Error(), "dll") {
		t.Fatalf("want a dll/windows error, got: %v", err)
	}
}
