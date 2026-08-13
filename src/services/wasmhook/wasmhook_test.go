package wasmhook

import (
	"path/filepath"
	"testing"
)

// TestLoadAndHook verifies a .wasm module is loaded and its wisp_handle output
// is merged back into the hook context (abort flag works end to end).
func TestLoadAndHook(t *testing.T) {
	dir := filepath.Join("testdata")
	r := NewRuntime()
	defer r.Close()

	if err := r.LoadDir(dir); err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	r.mu.Lock()
	n := len(r.modules)
	r.mu.Unlock()
	if n != 1 {
		t.Fatalf("loaded modules = %d, want 1", n)
	}

	// Input WITHOUT a '1' byte in the IP → abort stays false.
	hc := &HookContext{Event: "listener:checkin", Phase: "pre",
		Input: map[string]any{"ip": "9.9.9.9"}}
	r.Hook(hc)
	if hc.Abort {
		t.Fatal("unexpected abort for 9.9.9.9")
	}

	// Input WITH a '1' byte → module sets abort=true.
	hc2 := &HookContext{Event: "listener:checkin", Phase: "pre",
		Input: map[string]any{"ip": "192.168.1.9"}}
	r.Hook(hc2)
	if !hc2.Abort {
		t.Fatal("expected abort for IP containing '1'")
	}
}
