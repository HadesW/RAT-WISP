package payload

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wispp/protocol"
	"wispp/server/internal/poly"
	"wispp/server/internal/stage"
)

// synthTemplate mimics a compiled binary: junk + the sentinel slot + junk.
func synthTemplate(t *testing.T, dir, name string) {
	t.Helper()
	var img []byte
	img = append(img, make([]byte, 100)...)
	slot := protocol.SentinelSlot
	img = append(img, slot[:]...)
	img = append(img, make([]byte, 200)...)
	if err := os.WriteFile(filepath.Join(dir, name), img, 0o600); err != nil {
		t.Fatal(err)
	}
}

// synthPE builds a minimal PE32+ with one RX section, used where the payload
// path really parses the image (sRDI conversion).
func synthPE(dll bool, section ...byte) []byte {
	const (
		ntOff   = 0x80
		optOff  = ntOff + 24
		secOff  = optOff + 240
		rawOff  = 0x200
		rawSize = 0x2000
	)
	b := make([]byte, rawOff+rawSize)
	copy(b, "MZ")
	binary.LittleEndian.PutUint32(b[0x3c:], ntOff)
	copy(b[ntOff:], "PE\x00\x00")
	fh := b[ntOff+4:]
	binary.LittleEndian.PutUint16(fh[0:], 0x8664)
	binary.LittleEndian.PutUint16(fh[2:], 1)
	binary.LittleEndian.PutUint16(fh[16:], 240)
	chars := uint16(0x0022)
	if dll {
		chars |= 0x2000
	}
	binary.LittleEndian.PutUint16(fh[18:], chars)
	opt := b[optOff:]
	binary.LittleEndian.PutUint16(opt[0:], 0x20b)
	binary.LittleEndian.PutUint32(opt[16:], 0x1000)
	binary.LittleEndian.PutUint64(opt[24:], 0x140000000)
	binary.LittleEndian.PutUint32(opt[32:], 0x1000)
	binary.LittleEndian.PutUint32(opt[36:], 0x200)
	binary.LittleEndian.PutUint32(opt[56:], 0x3000)
	binary.LittleEndian.PutUint32(opt[60:], 0x200)
	binary.LittleEndian.PutUint16(opt[68:], 3)
	binary.LittleEndian.PutUint32(opt[108:], 16)
	sec := b[secOff:]
	copy(sec, ".text")
	binary.LittleEndian.PutUint32(sec[8:], rawSize)
	binary.LittleEndian.PutUint32(sec[12:], 0x1000)
	binary.LittleEndian.PutUint32(sec[16:], rawSize)
	binary.LittleEndian.PutUint32(sec[20:], rawOff)
	binary.LittleEndian.PutUint32(sec[36:], 0x60000020)
	copy(b[rawOff:], section)
	return b
}

func TestCreateDirectAndStaged(t *testing.T) {
	dir := t.TempDir()
	synthTemplate(t, dir, "agent_darwin_arm64")
	synthTemplate(t, dir, "stage_darwin_arm64")
	st := stage.New(time.Minute)
	svc := &Service{
		TemplatesDir: dir,
		PayloadsDir:  filepath.Join(t.TempDir(), "out"),
		Stage:        st,
		Defaults: func(string) ([]string, string, string, error) {
			return []string{"http://127.0.0.1:9000"}, "/submit", "psk-x", nil
		},
	}

	m, err := svc.Create(Spec{OS: "darwin", Arch: "arm64", SleepMS: 4000, JitterPct: 20})
	if err != nil {
		t.Fatal(err)
	}
	if m.Mode != "direct" || m.Size == 0 {
		t.Fatalf("meta: %+v", m)
	}
	if m.Project != "default" {
		t.Fatalf("default project not recorded: %+v", m)
	}
	img, err := os.ReadFile(m.Path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, ok, err := protocol.FindCfgSlot(img)
	if !ok || err != nil || cfg.PSK != "psk-x" || cfg.SleepMS != 4000 {
		t.Fatalf("embedded cfg: %+v %v %v", cfg, ok, err)
	}

	sm, err := svc.Create(Spec{OS: "darwin", Arch: "arm64", Staged: true})
	if err != nil {
		t.Fatal(err)
	}
	simg, _ := os.ReadFile(sm.Path)
	scfg, ok, err := protocol.FindCfgSlot(simg)
	if !ok || err != nil || !scfg.StagedSet() {
		t.Fatalf("stager cfg: %+v", scfg)
	}
	if scfg.Staged == "" || scfg.Staged[:7] != "http://" {
		t.Fatalf("stage url: %q", scfg.Staged)
	}
	if err := svc.Stage.SetPath("/assets/sync"); err != nil {
		t.Fatal(err)
	}
	pm, err := svc.Create(Spec{OS: "darwin", Arch: "arm64", Staged: true})
	if err != nil {
		t.Fatal(err)
	}
	pimg, _ := os.ReadFile(pm.Path)
	pcfg, _, _ := protocol.FindCfgSlot(pimg)
	if !strings.Contains(pcfg.Staged, "/assets/sync/") {
		t.Fatalf("custom stage path not embedded: %q", pcfg.Staged)
	}
	if err := svc.Stage.SetPath("/stage"); err != nil {
		t.Fatal(err)
	}

	// the token baked into the stager must deliver the stage2 image exactly once
	token := scfg.Staged[strings.LastIndex(scfg.Staged, "/")+1:]
	rec := httptest.NewRecorder()
	st.ServeHTTP(rec, httptest.NewRequest("GET", "/stage/"+token, nil))
	if rec.Code != 200 {
		t.Fatalf("stage fetch: %d", rec.Code)
	}
	var sr struct {
		V, IV, CT string
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &sr)
	rec2 := httptest.NewRecorder()
	st.ServeHTTP(rec2, httptest.NewRequest("GET", "/stage/"+token, nil))
	if rec2.Code != 404 {
		t.Fatal("stage token replay allowed")
	}

	// unknown platform template -> clear error
	if _, err := svc.Create(Spec{OS: "plan9", Arch: "riscv"}); err == nil {
		t.Fatal("missing template accepted")
	}
}

// TestRustQUICGuard: the Rust QUIC transport is feature-gated (plan P6
// decision #7), so a payload bound to a quic:// listener is gated on what the
// RS template manifest actually advertises — not blanket-rejected. Staged
// payloads never carry quic and must fail even with the feature present.
func TestRustQUICGuard(t *testing.T) {
	svc := p1Service(t)
	svc.Defaults = func(string) ([]string, string, string, error) {
		return []string{"quic://192.168.32.1:9080"}, "", "psk-x", nil
	}
	// manifest missing/lacks quic -> readable rejection
	_, err := svc.Create(Spec{OS: "windows", Arch: "amd64", Agent: AgentRust})
	if err == nil || !strings.Contains(err.Error(), "lacks the quic feature") {
		t.Fatalf("rust+quic without feature: %v", err)
	}

	// Go agent speaks QUIC unconditionally and must build normally
	m, err := svc.Create(Spec{OS: "windows", Arch: "amd64", Agent: AgentGo})
	if err != nil {
		t.Fatalf("go+quic: %v", err)
	}
	img, err := os.ReadFile(m.Path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, ok, err := protocol.FindCfgSlot(img)
	if !ok || err != nil || len(cfg.Servers) != 1 || !strings.HasPrefix(cfg.Servers[0], "quic://") {
		t.Fatalf("quic server not baked: %+v %v %v", cfg, ok, err)
	}
}

// TestRustQUICAllowedWithFeature: once the RS manifest advertises quic (the
// template build passes --features quic), a direct rust payload bound to a
// quic listener builds and bakes the endpoint — while staged stays rejected.
func TestRustQUICAllowedWithFeature(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{
		"agent_windows_amd64.exe", "stage_windows_amd64.exe",
		"rs_stager_windows_amd64.exe", "rs_loader_windows_amd64.dll",
		"rs_core_windows_amd64.dll", "rs_agent_windows_amd64.exe",
	} {
		synthTemplate(t, dir, name)
	}
	mf := manifest{Schema: 2, Kind: "rs", Agent: "rust", Features: []string{"rcp", "quic"}}
	raw, _ := json.Marshal(mf)
	if err := os.WriteFile(filepath.Join(dir, "rs_manifest.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	svc := &Service{
		TemplatesDir: dir,
		PayloadsDir:  filepath.Join(t.TempDir(), "out"),
		Stage:        stage.New(time.Minute),
		Defaults: func(string) ([]string, string, string, error) {
			return []string{"quic://192.168.32.1:9080"}, "", "psk-x", nil
		},
	}

	// direct rust exe: allowed, endpoint baked
	m, err := svc.Create(Spec{OS: "windows", Arch: "amd64", Agent: AgentRust, Format: FormatEXE, Delivery: DeliveryDirect})
	if err != nil {
		t.Fatalf("rust direct+quic with feature: %v", err)
	}
	img, err := os.ReadFile(m.Path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, ok, err := protocol.FindCfgSlot(img)
	if !ok || err != nil || len(cfg.Servers) != 1 || !strings.HasPrefix(cfg.Servers[0], "quic://") {
		t.Fatalf("quic server not baked for rust: %+v %v %v", cfg, ok, err)
	}

	// staged rust: never carries quic, still rejected with the feature present
	_, err = svc.Create(Spec{OS: "windows", Arch: "amd64", Agent: AgentRust, RSStaged: true})
	if err == nil || !strings.Contains(err.Error(), "staged payloads do not carry the quic transport") {
		t.Fatalf("rust staged+quic rejected: %v", err)
	}
}

// p1Service wires a service with the P1 format templates on disk.
func p1Service(t *testing.T) *Service {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{
		"agent_darwin_arm64", "stage_darwin_arm64",
		"agent_windows_amd64.exe", "stage_windows_amd64.exe", "agent_windows_arm64.exe",
		"agent_dll_windows_amd64.dll", CLoaderName, CPPLoaderName, SRDIBootstrapName,
		"rs_agent_windows_amd64.exe", "rs_agent_windows_amd64.dll", "rs_agent_linux_amd64",
	} {
		synthTemplate(t, dir, name)
	}
	return &Service{
		TemplatesDir: dir,
		PayloadsDir:  filepath.Join(t.TempDir(), "out"),
		Stage:        stage.New(time.Minute),
		Defaults: func(string) ([]string, string, string, error) {
			return []string{"http://127.0.0.1:9000"}, "/submit", "psk-x", nil
		},
	}
}

func assertPatched(t *testing.T, path string) {
	t.Helper()
	img, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, ok, err := protocol.FindCfgSlot(img)
	if !ok || err != nil || cfg.PSK != "psk-x" {
		t.Fatalf("embedded cfg: %+v ok=%v err=%v", cfg, ok, err)
	}
}

func TestCreateP1Formats(t *testing.T) {
	svc := p1Service(t)

	dll, err := svc.Create(Spec{OS: "windows", Arch: "amd64", Format: FormatDLL})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(dll.Name, ".dll") || dll.Format != FormatDLL || dll.Mode != "direct" {
		t.Fatalf("dll meta: %+v", dll)
	}
	if !strings.Contains(dll.Hint, "rundll32") || !strings.Contains(dll.Hint, "WispStart") {
		t.Fatalf("dll hint: %q", dll.Hint)
	}
	assertPatched(t, dll.Path)

	rsDLL, err := svc.Create(Spec{OS: "windows", Arch: "amd64", Agent: AgentRust, Format: FormatDLL})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(rsDLL.Name, ".dll") || rsDLL.Agent != AgentRust {
		t.Fatalf("rust dll meta: %+v", rsDLL)
	}
	assertPatched(t, rsDLL.Path)

	svcM, err := svc.Create(Spec{OS: "windows", Arch: "amd64", Format: FormatSvc})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(svcM.Name, ".exe") || !strings.Contains(svcM.Hint, "sc create") ||
		!strings.Contains(svcM.Hint, "--service") {
		t.Fatalf("svc meta: %+v", svcM)
	}
	assertPatched(t, svcM.Path)

	arm, err := svc.Create(Spec{OS: "windows", Arch: "arm64"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(arm.Name, ".exe") || arm.Arch != "arm64" {
		t.Fatalf("windows_arm64 meta: %+v", arm)
	}
	assertPatched(t, arm.Path)

	rsLinux, err := svc.Create(Spec{OS: "linux", Arch: "amd64", Agent: AgentRust})
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasSuffix(rsLinux.Name, ".exe") || rsLinux.Agent != AgentRust || rsLinux.Mode != "direct" {
		t.Fatalf("rust linux meta: %+v", rsLinux)
	}
	assertPatched(t, rsLinux.Path)
}

func TestCreateCLoader(t *testing.T) {
	svc := p1Service(t)
	m, err := svc.Create(Spec{OS: "windows", Arch: "amd64", Agent: AgentGo,
		Format: FormatEXE, Delivery: DeliveryStaged, Loader: LoaderC, StageUses: 1})
	if err != nil {
		t.Fatal(err)
	}
	if m.Loader != LoaderC || m.Mode != "staged" || !strings.HasSuffix(m.Name, ".exe") {
		t.Fatalf("c loader meta: %+v", m)
	}
	if m.Size > CLoaderBudget {
		t.Fatalf("c loader artifact %d bytes exceeds %d", m.Size, CLoaderBudget)
	}
	img, err := os.ReadFile(m.Path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, ok, err := protocol.FindCfgSlot(img)
	if !ok || err != nil || !cfg.StagedSet() {
		t.Fatalf("c loader cfg: %+v ok=%v err=%v", cfg, ok, err)
	}
	if strings.Contains(cfg.Staged, "/stage/"+m.StageToken) == false {
		t.Fatalf("stage url %q lacks token %q", cfg.Staged, m.StageToken)
	}

	// The token still hands out the fully patched Go agent as stage2.
	rec := httptest.NewRecorder()
	svc.Stage.ServeHTTP(rec, httptest.NewRequest("GET", "/stage/"+m.StageToken+"?b64=1", nil))
	if rec.Code != 200 {
		t.Fatalf("c loader stage fetch: %d", rec.Code)
	}
	raw, err := base64.StdEncoding.DecodeString(rec.Body.String())
	if err != nil {
		t.Fatal(err)
	}
	stageCfg, ok, err := protocol.FindCfgSlot(raw)
	if !ok || err != nil || stageCfg.PSK != "psk-x" || stageCfg.StagedSet() {
		t.Fatalf("c loader stage2 cfg: %+v ok=%v err=%v", stageCfg, ok, err)
	}
}

func TestCreateCLoaderRustMemory(t *testing.T) {
	svc := p1Service(t)
	m, err := svc.Create(Spec{OS: "windows", Arch: "amd64", Agent: AgentRust,
		Format: FormatEXE, Delivery: DeliveryStaged, Loader: LoaderC, StageUses: 1})
	if err != nil {
		t.Fatal(err)
	}
	if m.Loader != LoaderC || m.Agent != AgentRust || m.Mode != "staged-mem" {
		t.Fatalf("c mem meta: %+v", m)
	}
	if m.Size > CLoaderBudget {
		t.Fatalf("c loader artifact %d bytes exceeds %d", m.Size, CLoaderBudget)
	}
	img, err := os.ReadFile(m.Path)
	if err != nil {
		t.Fatal(err)
	}
	loaderCfg, ok, err := protocol.FindCfgSlot(img)
	if !ok || err != nil || !loaderCfg.StagedSet() {
		t.Fatalf("c mem loader cfg: %+v ok=%v err=%v", loaderCfg, ok, err)
	}
	if !strings.Contains(loaderCfg.Staged, "/stage/"+m.StageToken) {
		t.Fatalf("stage url %q lacks token %q", loaderCfg.Staged, m.StageToken)
	}

	// Stage2 is the patched Rust DLL, not the Go agent.
	rec := httptest.NewRecorder()
	svc.Stage.ServeHTTP(rec, httptest.NewRequest("GET", "/stage/"+m.StageToken+"?b64=1", nil))
	if rec.Code != 200 {
		t.Fatalf("c mem stage fetch: %d", rec.Code)
	}
	raw, err := base64.StdEncoding.DecodeString(rec.Body.String())
	if err != nil {
		t.Fatal(err)
	}
	stageCfg, ok, err := protocol.FindCfgSlot(raw)
	if !ok || err != nil || stageCfg.PSK != "psk-x" || stageCfg.StagedSet() {
		t.Fatalf("c mem stage2 cfg: %+v ok=%v err=%v", stageCfg, ok, err)
	}
}

func TestCreateCPPLoader(t *testing.T) {
	svc := p1Service(t)
	m, err := svc.Create(Spec{OS: "windows", Arch: "amd64", Agent: AgentGo,
		Format: FormatEXE, Delivery: DeliveryStaged, Loader: LoaderCPP, StageUses: 1})
	if err != nil {
		t.Fatal(err)
	}
	if m.Loader != LoaderCPP || m.Mode != "staged" || !strings.HasSuffix(m.Name, ".exe") {
		t.Fatalf("c++ loader meta: %+v", m)
	}
	if m.Size > CPPLoaderBudget {
		t.Fatalf("c++ loader artifact %d bytes exceeds %d", m.Size, CPPLoaderBudget)
	}
	img, err := os.ReadFile(m.Path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, ok, err := protocol.FindCfgSlot(img)
	if !ok || err != nil || !cfg.StagedSet() {
		t.Fatalf("c++ loader cfg: %+v ok=%v err=%v", cfg, ok, err)
	}
	if !strings.Contains(cfg.Staged, "/stage/"+m.StageToken) {
		t.Fatalf("stage url %q lacks token %q", cfg.Staged, m.StageToken)
	}
	rec := httptest.NewRecorder()
	svc.Stage.ServeHTTP(rec, httptest.NewRequest("GET", "/stage/"+m.StageToken+"?b64=1", nil))
	if rec.Code != 200 {
		t.Fatalf("c++ loader stage fetch: %d", rec.Code)
	}
	raw, err := base64.StdEncoding.DecodeString(rec.Body.String())
	if err != nil {
		t.Fatal(err)
	}
	stageCfg, ok, err := protocol.FindCfgSlot(raw)
	if !ok || err != nil || stageCfg.PSK != "psk-x" || stageCfg.StagedSet() {
		t.Fatalf("c++ loader stage2 cfg: %+v ok=%v err=%v", stageCfg, ok, err)
	}
}

func TestCreateCPPLoaderRustMemory(t *testing.T) {
	svc := p1Service(t)
	m, err := svc.Create(Spec{OS: "windows", Arch: "amd64", Agent: AgentRust,
		Format: FormatEXE, Delivery: DeliveryStaged, Loader: LoaderCPP, StageUses: 1})
	if err != nil {
		t.Fatal(err)
	}
	if m.Loader != LoaderCPP || m.Agent != AgentRust || m.Mode != "staged-mem" {
		t.Fatalf("c++ mem meta: %+v", m)
	}
	if m.Size > CPPLoaderBudget {
		t.Fatalf("c++ loader artifact %d bytes exceeds %d", m.Size, CPPLoaderBudget)
	}
	img, err := os.ReadFile(m.Path)
	if err != nil {
		t.Fatal(err)
	}
	loaderCfg, ok, err := protocol.FindCfgSlot(img)
	if !ok || err != nil || !loaderCfg.StagedSet() {
		t.Fatalf("c++ mem loader cfg: %+v ok=%v err=%v", loaderCfg, ok, err)
	}
	rec := httptest.NewRecorder()
	svc.Stage.ServeHTTP(rec, httptest.NewRequest("GET", "/stage/"+m.StageToken+"?b64=1", nil))
	if rec.Code != 200 {
		t.Fatalf("c++ mem stage fetch: %d", rec.Code)
	}
	raw, err := base64.StdEncoding.DecodeString(rec.Body.String())
	if err != nil {
		t.Fatal(err)
	}
	stageCfg, ok, err := protocol.FindCfgSlot(raw)
	if !ok || err != nil || stageCfg.PSK != "psk-x" || stageCfg.StagedSet() {
		t.Fatalf("c++ mem stage2 cfg: %+v ok=%v err=%v", stageCfg, ok, err)
	}
}

func TestCreateShellcode(t *testing.T) {
	dir := t.TempDir()
	bootText := make([]byte, 0x2000)
	copy(bootText[0x40:], "SRDICFG\x01")
	binary.LittleEndian.PutUint32(bootText[0x48:], 1) // SRDICFG ABI version
	dllText := make([]byte, 0x2000)
	copy(dllText[0x100:], protocol.SentinelSlot[:])
	if err := os.WriteFile(filepath.Join(dir, SRDIBootstrapName), synthPE(false, bootText...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rs_agent_windows_amd64.dll"), synthPE(true, dllText...), 0o600); err != nil {
		t.Fatal(err)
	}
	svc := &Service{
		TemplatesDir: dir,
		PayloadsDir:  filepath.Join(t.TempDir(), "out"),
		Defaults: func(string) ([]string, string, string, error) {
			return []string{"http://127.0.0.1:9000"}, "/submit", "psk-x", nil
		},
	}

	m, err := svc.Create(Spec{OS: "windows", Arch: "amd64", Agent: AgentRust, Format: FormatShellcode})
	if err != nil {
		t.Fatal(err)
	}
	if m.Format != FormatShellcode || m.Mode != "direct" || m.Loader != LoaderCPP ||
		!strings.HasSuffix(m.Name, ".bin") {
		t.Fatalf("shellcode meta: %+v", m)
	}
	if m.Hint == "" {
		t.Fatal("shellcode hint missing")
	}
	img, err := os.ReadFile(m.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(img, []byte("SRDICFG")) {
		t.Fatal("cfg sentinel missing from shellcode")
	}
	cfg, ok, err := protocol.FindCfgSlot(img)
	if !ok || err != nil || cfg.PSK != "psk-x" || cfg.StagedSet() {
		t.Fatalf("embedded dll cfg: %+v ok=%v err=%v", cfg, ok, err)
	}
}

func TestCreateSubprocessDLL(t *testing.T) {
	svc := p1Service(t)
	for _, tc := range []struct{ agent, loader string }{
		{AgentGo, LoaderC},
		{AgentRust, LoaderCPP},
	} {
		m, err := svc.Create(Spec{OS: "windows", Arch: "amd64", Agent: tc.agent,
			Format: FormatDLL, Delivery: DeliverySubprocess, Loader: tc.loader})
		if err != nil {
			t.Fatalf("%s/%s: %v", tc.agent, tc.loader, err)
		}
		if m.Mode != "subprocess" || m.Format != FormatDLL || m.Loader != tc.loader ||
			!strings.HasSuffix(m.Name, ".exe") {
			t.Fatalf("%s/%s meta: %+v", tc.agent, tc.loader, m)
		}
		if m.Hint != m.Name {
			t.Fatalf("%s/%s hint: %q", tc.agent, tc.loader, m.Hint)
		}
		img, err := os.ReadFile(m.Path)
		if err != nil {
			t.Fatal(err)
		}
		foot := img[len(img)-EmbeddedFooterSize:]
		if string(foot[16:]) != EmbeddedMagic {
			t.Fatalf("%s/%s footer magic: %q", tc.agent, tc.loader, foot[16:])
		}
		off := binary.LittleEndian.Uint64(foot)
		size := binary.LittleEndian.Uint32(foot[8:])
		if got := binary.LittleEndian.Uint32(foot[12:]); got != EmbeddedFlagRundll {
			t.Fatalf("%s/%s footer flags: %#x", tc.agent, tc.loader, got)
		}
		if off%16 != 0 || off+uint64(size)+EmbeddedFooterSize != uint64(len(img)) {
			t.Fatalf("%s/%s footer bounds: off=%d size=%d total=%d",
				tc.agent, tc.loader, off, size, len(img))
		}
		cfg, ok, err := protocol.FindCfgSlot(img)
		if !ok || err != nil || cfg.PSK != "psk-x" || cfg.StagedSet() {
			t.Fatalf("%s/%s embedded dll cfg: %+v ok=%v err=%v", tc.agent, tc.loader, cfg, ok, err)
		}
	}
}

func TestScriptStagerFetchesStage2(t *testing.T) {
	svc := p1Service(t)

	win, err := svc.Create(Spec{OS: "windows", Arch: "amd64", Format: FormatScript, StageUses: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(win.Name, ".ps1") || win.Mode != "staged" || win.StageToken == "" {
		t.Fatalf("script meta: %+v", win)
	}
	if !strings.Contains(win.Hint, "powershell") {
		t.Fatalf("script hint: %q", win.Hint)
	}
	body, err := os.ReadFile(win.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "?b64=1") || !strings.Contains(string(body), win.StageToken) {
		t.Fatalf("script body: %s", body)
	}

	rec := httptest.NewRecorder()
	svc.Stage.ServeHTTP(rec, httptest.NewRequest("GET", "/stage/"+win.StageToken+"?b64=1", nil))
	if rec.Code != 200 {
		t.Fatalf("b64 fetch: %d", rec.Code)
	}
	raw, err := base64.StdEncoding.DecodeString(rec.Body.String())
	if err != nil {
		t.Fatalf("b64 decode: %v", err)
	}
	cfg, ok, err := protocol.FindCfgSlot(raw)
	if !ok || err != nil || cfg.PSK != "psk-x" {
		t.Fatalf("stage2 cfg: %+v ok=%v err=%v", cfg, ok, err)
	}
	rec2 := httptest.NewRecorder()
	svc.Stage.ServeHTTP(rec2, httptest.NewRequest("GET", "/stage/"+win.StageToken+"?b64=1", nil))
	if rec2.Code != 404 {
		t.Fatalf("script token replay: %d", rec2.Code)
	}

	unixM, err := svc.Create(Spec{OS: "darwin", Arch: "arm64", Format: FormatScript})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(unixM.Name, ".sh") || !strings.HasPrefix(unixM.Hint, "sh ") {
		t.Fatalf("unix script meta: %+v", unixM)
	}
	shBody, _ := os.ReadFile(unixM.Path)
	if !strings.HasPrefix(string(shBody), "#!/bin/sh") {
		t.Fatalf("sh body: %s", shBody)
	}
}

func TestHistoryPersistAndDelete(t *testing.T) {
	dir := t.TempDir()
	synthTemplate(t, dir, "agent_darwin_arm64")
	out := t.TempDir()
	mk := func() *Service {
		return &Service{
			TemplatesDir: dir,
			PayloadsDir:  out,
			Stage:        stage.New(time.Minute),
			Defaults: func(string) ([]string, string, string, error) {
				return []string{"http://127.0.0.1:9000"}, "/submit", "psk-x", nil
			},
		}
	}
	svc := mk()
	m1, err := svc.Create(Spec{OS: "darwin", Arch: "arm64", Note: "alpha", Listener: "L1"})
	if err != nil {
		t.Fatal(err)
	}
	if m1.Note != "alpha" || m1.Listener != "L1" {
		t.Fatalf("meta fields: %+v", m1)
	}
	if _, err := svc.Create(Spec{OS: "darwin", Arch: "arm64"}); err != nil {
		t.Fatal(err)
	}

	svc2 := mk()
	svc2.Restore()
	if got := svc2.List(); len(got) != 2 || got[1].Note != "alpha" {
		t.Fatalf("restored history: %+v", got)
	}
	if err := svc2.Delete(m1.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(m1.Path); !os.IsNotExist(err) {
		t.Fatal("artifact still on disk after delete")
	}
	if err := svc2.Delete("missing"); err == nil {
		t.Fatal("unknown id accepted")
	}

	svc3 := mk()
	svc3.Restore()
	if got := svc3.List(); len(got) != 1 {
		t.Fatalf("history after delete: %+v", got)
	}
}

func TestStagedMetaRearmAndDelete(t *testing.T) {
	dir := t.TempDir()
	synthTemplate(t, dir, "agent_darwin_arm64")
	synthTemplate(t, dir, "stage_darwin_arm64")
	out := t.TempDir()
	st := stage.New(time.Minute)
	svc := &Service{
		TemplatesDir: dir,
		PayloadsDir:  out,
		Stage:        st,
		Defaults: func(string) ([]string, string, string, error) {
			return []string{"http://127.0.0.1:9000"}, "/submit", "psk-x", nil
		},
	}
	m, err := svc.Create(Spec{OS: "darwin", Arch: "arm64", Staged: true, StageTTLSeconds: 120, StageUses: 2})
	if err != nil {
		t.Fatal(err)
	}
	if m.StageToken == "" || m.StageLeft != 2 || m.StageTotal != 2 || !m.StageActive {
		t.Fatalf("stage meta: %+v", m)
	}
	if _, ok := st.Status(m.StageToken); !ok {
		t.Fatal("stage token not issued")
	}

	rm, err := svc.Rearm(m.ID, 300, 3)
	if err != nil {
		t.Fatal(err)
	}
	if rm.StageLeft != 3 || rm.StageTotal != 3 || !rm.StageActive {
		t.Fatalf("rearm meta: %+v", rm)
	}

	// History persistence must keep the hidden stage token so re-arm works.
	svc2 := &Service{TemplatesDir: dir, PayloadsDir: out, Stage: st,
		Defaults: func(string) ([]string, string, string, error) {
			return []string{"http://127.0.0.1:9000"}, "/submit", "psk-x", nil
		}}
	svc2.Restore()
	list := svc2.List()
	if len(list) != 1 || list[0].StageToken == "" {
		t.Fatalf("restored stage token: %+v", list)
	}
	if _, err := svc2.Rearm(m.ID, 60, 1); err != nil {
		t.Fatal(err)
	}

	if err := svc2.Delete(m.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.Status(m.StageToken); ok {
		t.Fatal("delete did not revoke stage token")
	}
}

func TestTemplatesManifestValidation(t *testing.T) {
	dir := t.TempDir()
	synthTemplate(t, dir, "agent_darwin_arm64")
	name := "agent_darwin_arm64"
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	good := manifest{Kind: "go", Git: "abc123", BuiltAt: time.Now().UTC(),
		Files: []manifestFile{{Name: name, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(raw))}}}
	writeManifest := func(m manifest) {
		b, _ := json.Marshal(m)
		if err := os.WriteFile(filepath.Join(dir, "go_manifest.json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	bad := good
	bad.Files = []manifestFile{{Name: name, SHA256: "deadbeef", Size: int64(len(raw))}}
	writeManifest(bad)
	ts := (&Service{TemplatesDir: dir}).Templates()
	if ts.Go.OK || !ts.Go.Present || len(ts.Go.Files) != 1 || ts.Go.Files[0].Match {
		t.Fatalf("bad manifest accepted: %+v", ts.Go)
	}

	writeManifest(good)
	ts = (&Service{TemplatesDir: dir}).Templates()
	if !ts.Go.OK || ts.Go.Git != "abc123" {
		t.Fatalf("good manifest rejected: %+v", ts.Go)
	}
	if ts.RSAvailable {
		t.Fatal("rs reported available without rs templates")
	}

	// RS trio + matching manifest.
	for _, f := range rsFiles {
		synthTemplate(t, dir, f)
	}
	var rs manifest
	rs.Kind = "rs"
	for _, f := range rsFiles {
		b, _ := os.ReadFile(filepath.Join(dir, f))
		h := sha256.Sum256(b)
		rs.Files = append(rs.Files, manifestFile{Name: f, SHA256: hex.EncodeToString(h[:]), Size: int64(len(b))})
	}
	b, _ := json.Marshal(rs)
	if err := os.WriteFile(filepath.Join(dir, "rs_manifest.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	ts = (&Service{TemplatesDir: dir}).Templates()
	if !ts.RSAvailable || !ts.RS.OK {
		t.Fatalf("rs templates rejected: %+v", ts.RS)
	}
}

func TestCreateBakesProfile(t *testing.T) {
	svc := p1Service(t)
	github := protocol.BuiltinProfiles()[1]
	svc.Profiles = func(name string) (*protocol.Profile, error) {
		if name == "github-api" {
			cp := *github
			return &cp, nil
		}
		return nil, fmt.Errorf("unknown profile %q", name)
	}
	if _, err := svc.Create(Spec{OS: "windows", Arch: "amd64", Agent: AgentGo, Profile: "nope"}); err == nil ||
		!strings.Contains(err.Error(), "unknown profile") {
		t.Fatalf("unknown profile: %v", err)
	}
	m, err := svc.Create(Spec{OS: "windows", Arch: "amd64", Agent: AgentGo, Profile: "github-api"})
	if err != nil {
		t.Fatal(err)
	}
	if m.Profile != "github-api" {
		t.Fatalf("meta profile: %q", m.Profile)
	}
	img, err := os.ReadFile(m.Path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, ok, err := protocol.FindCfgSlot(img)
	if !ok || err != nil || cfg.Profile == nil {
		t.Fatalf("cfg profile: %+v ok=%v err=%v", cfg.Profile, ok, err)
	}
	if cfg.Profile.Name != "github-api" || cfg.Profile.Data != "header:X-GitHub-Request-Id" ||
		!cfg.Profile.Accepts(mustReq(t, cfg.Profile)) {
		t.Fatalf("baked profile: %+v", cfg.Profile)
	}
}

func mustReq(t *testing.T, p *protocol.Profile) *http.Request {
	t.Helper()
	req, err := p.ApplyAgentRequest("http://127.0.0.1:9000", p.PickUA(), []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func TestCreatePolyShellcode(t *testing.T) {
	dir := t.TempDir()
	bootText := make([]byte, 0x2000)
	copy(bootText[0x40:], "SRDICFG\x01")
	binary.LittleEndian.PutUint32(bootText[0x48:], 1)
	dllText := make([]byte, 0x2000)
	copy(dllText[0x100:], protocol.SentinelSlot[:])
	decText := make([]byte, 0x2000)
	copy(decText[0x40:], "POLYCFG\x01")
	binary.LittleEndian.PutUint32(decText[0x48:], 1)
	for name, section := range map[string][]byte{
		SRDIBootstrapName:            synthPE(false, bootText...),
		"rs_agent_windows_amd64.dll": synthPE(true, dllText...),
		PolyDecoderName:              synthPE(false, decText...),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), section, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	svc := &Service{
		TemplatesDir: dir,
		PayloadsDir:  filepath.Join(t.TempDir(), "out"),
		Defaults: func(string) ([]string, string, string, error) {
			return []string{"http://127.0.0.1:9000"}, "/submit", "psk-x", nil
		},
	}
	plain, err := svc.Create(Spec{OS: "windows", Arch: "amd64", Agent: AgentRust, Format: FormatShellcode})
	if err != nil {
		t.Fatal(err)
	}
	enc, err := svc.Create(Spec{OS: "windows", Arch: "amd64", Agent: AgentRust, Format: FormatShellcode,
		Poly: &PolySpec{Enabled: true, Passes: 2, Seed: "unit"}})
	if err != nil {
		t.Fatal(err)
	}
	if !enc.Poly || enc.SHA256 == plain.SHA256 {
		t.Fatalf("poly shellcode meta: %+v", enc)
	}
	encImg, err := os.ReadFile(enc.Path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encImg, []byte("SRDICFG\x01\x0c")) {
		// sRDI magic may occur; instead rely on the explicit round trip below
		_ = encImg
	}
	got, ops, keys, err := poly.ExtractForTest(encImg)
	if err != nil {
		t.Fatal(err)
	}
	decoded := poly.DecodePayload(got, ops, keys, 2)
	plainImg, err := os.ReadFile(plain.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, plainImg) {
		t.Fatalf("decoded payload != plain sRDI shellcode (%d vs %d)", len(decoded), len(plainImg))
	}
	if _, err := svc.Create(Spec{OS: "windows", Arch: "amd64", Agent: AgentRust, Format: FormatShellcode,
		Poly: &PolySpec{Enabled: true, Passes: 9}}); err == nil {
		t.Fatal("bad pass count accepted")
	}
}

func TestCreatePolyPEAndFooter(t *testing.T) {
	realLoader, err := os.ReadFile(filepath.Join("..", "..", "templates", CLoaderName))
	if err != nil {
		t.Skip("real C loader template not built")
	}
	dir := t.TempDir()
	// direct agent = a real PE carrying the config slot
	if err := os.WriteFile(filepath.Join(dir, "agent_windows_amd64.exe"), realLoader, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "agent_dll_windows_amd64.dll"), synthPE(true, append(make([]byte, 0x100), protocol.SentinelSlot[:]...)...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, CLoaderName), realLoader, 0o600); err != nil {
		t.Fatal(err)
	}
	svc := &Service{
		TemplatesDir: dir,
		PayloadsDir:  filepath.Join(t.TempDir(), "out"),
		Defaults: func(string) ([]string, string, string, error) {
			return []string{"http://127.0.0.1:9000"}, "/submit", "psk-x", nil
		},
	}
	plain, err := svc.Create(Spec{OS: "windows", Arch: "amd64", Agent: AgentGo})
	if err != nil {
		t.Fatal(err)
	}
	morph, err := svc.Create(Spec{OS: "windows", Arch: "amd64", Agent: AgentGo,
		Poly: &PolySpec{Enabled: true, Seed: "pe"}})
	if err != nil {
		t.Fatal(err)
	}
	if morph.SHA256 == plain.SHA256 {
		t.Fatal("poly PE build is not unique")
	}
	if morph.Size <= plain.Size {
		t.Fatalf("overlay missing: %d <= %d", morph.Size, plain.Size)
	}
	assertPatched(t, morph.Path)

	// subprocess artifact keeps the WISPEMB footer as the last 24 bytes
	sub, err := svc.Create(Spec{OS: "windows", Arch: "amd64", Agent: AgentGo,
		Format: FormatDLL, Delivery: DeliverySubprocess, Loader: LoaderC,
		Poly: &PolySpec{Enabled: true, Seed: "sub"}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(sub.Path)
	if err != nil {
		t.Fatal(err)
	}
	if got := raw[len(raw)-8:]; string(got) != "WISPEMB\x01" {
		t.Fatalf("subprocess footer moved: %q", got)
	}
}
