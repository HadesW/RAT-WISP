package payload

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Spec v2 vocabulary. The console sends these fields; the legacy Staged and
// RSStaged booleans remain accepted and are normalized into Delivery/Loader.
const (
	AgentGo   = "go"
	AgentRust = "rust"

	FormatEXE       = "exe"
	FormatDLL       = "dll"
	FormatSvc       = "svc"
	FormatShellcode = "shellcode"
	FormatScript    = "script"

	DeliveryDirect     = "direct"
	DeliverySubprocess = "subprocess"
	DeliveryStaged     = "staged"

	LoaderNone = "none"
	LoaderGo   = "go"
	LoaderRust = "rust"
	LoaderC    = "c"
	LoaderCPP  = "cpp"

	SourceTemplate = "template"
	SourceBuild    = "source"

	// CLoaderName is the prebuilt pure-C stager image. It carries only the
	// stage URL; Go EXE stage2 runs from %TEMP%, Rust DLL stage2 is mapped
	// into the loader process instead.
	CLoaderName   = "loader_c_windows_amd64.exe"
	CLoaderBudget = 50 * 1024

	// CPPLoaderName is the C++23 reference loader: same two stage2 modes as
	// the C loader, with std::expected/std::span and delay-import/CFG handling.
	CPPLoaderName   = "loader_cpp_windows_amd64.exe"
	CPPLoaderBudget = 250 * 1024

	// SRDIBootstrapName is the import-free PE image that server/internal/srdi
	// turns into position-independent shellcode around a DLL.
	SRDIBootstrapName   = "srdi_bootstrap_windows_amd64.exe"
	SRDIBootstrapBudget = 64 * 1024

	// PolyDecoderName is the import-free decoder image used to wrap encoded
	// shellcode artifacts (plan P5).
	PolyDecoderName   = "poly_decoder_windows_amd64.exe"
	PolyDecoderBudget = 32 * 1024

	// Embedded DLL container appended to a native loader for subprocess
	// delivery; shared with loaders/c and loaders/cpp.
	EmbeddedFooterSize = 24
	EmbeddedMagic      = "WISPEMB\x01"
	EmbeddedFlagRundll = 1
)

// PolySpec is reserved for P5 (SGN-style encoding). It is modeled now so the
// console and persisted metadata have a stable shape.
type PolySpec struct {
	Enabled bool   `json:"enabled"`
	Passes  int    `json:"passes,omitempty"`
	Seed    string `json:"seed,omitempty"`
}

// Combo is one currently available generation combination.
type Combo struct {
	Agent    string `json:"agent"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Format   string `json:"format"`
	Delivery string `json:"delivery"`
	Loader   string `json:"loader"`
}

// PlannedOption explains why an option is visible but unavailable.
type PlannedOption struct {
	Kind  string `json:"kind"` // format | delivery | loader | feature
	ID    string `json:"id"`
	Phase string `json:"phase"`
}

// KnownOptions lists every option the console may render, including options
// that are still planned.
type KnownOptions struct {
	Agents     []string `json:"agents"`
	Formats    []string `json:"formats"`
	Deliveries []string `json:"deliveries"`
	Loaders    []string `json:"loaders"`
}

// Capabilities is the builder projection served by /api/payloads/capabilities.
// Combos are authoritative; the console filters selections against them.
type Capabilities struct {
	Schema   int             `json:"schema"`
	Combos   []Combo         `json:"combos"`
	Known    KnownOptions    `json:"known"`
	Planned  []PlannedOption `json:"planned"`
	Features map[string]bool `json:"features"`
}

// Capabilities reports what can actually be generated. Template presence is
// checked on disk so the console never offers a combination that will fail
// halfway through generation.
func (s *Service) Capabilities() Capabilities {
	c := Capabilities{
		Schema: 2,
		Known: KnownOptions{
			Agents:     []string{AgentGo, AgentRust},
			Formats:    []string{FormatEXE, FormatDLL, FormatSvc, FormatShellcode, FormatScript},
			Deliveries: []string{DeliveryDirect, DeliverySubprocess, DeliveryStaged},
			Loaders:    []string{LoaderNone, LoaderGo, LoaderRust, LoaderC, LoaderCPP},
		},
		Planned: []PlannedOption{
			{Kind: "feature", ID: "source_build", Phase: "P1 (offline script)"},
			{Kind: "feature", ID: "native_plugin", Phase: "P5"},
		},
		Features: map[string]bool{
			"profile":       true,
			"poly":          false, // filled from the decoder template below
			"source_build":  false,
			"native_plugin": false,
			"quic":          true, // Go agent + quic listener (rust quinn pending)
		},
	}
	for _, platform := range s.Platforms() {
		osName, arch, ok := strings.Cut(platform, "_")
		if !ok {
			continue
		}
		add := func(format, delivery, loader string) {
			c.Combos = append(c.Combos, Combo{
				Agent: AgentGo, OS: osName, Arch: arch,
				Format: format, Delivery: delivery, Loader: loader,
			})
		}
		add(FormatEXE, DeliveryDirect, LoaderNone)
		if s.hasTemplate("stage", platform) {
			add(FormatEXE, DeliveryStaged, LoaderGo)
		}
		if osName == "windows" && arch == "amd64" && s.cLoaderReady(platform) {
			add(FormatEXE, DeliveryStaged, LoaderC)
		}
		if osName == "windows" && arch == "amd64" && s.cppLoaderReady(platform) {
			add(FormatEXE, DeliveryStaged, LoaderCPP)
		}
		add(FormatScript, DeliveryStaged, LoaderNone)
		if osName == "windows" {
			add(FormatSvc, DeliveryDirect, LoaderNone)
			if s.goDLLAvailable(platform) {
				add(FormatDLL, DeliveryDirect, LoaderNone)
				if s.nativeLoaderPresent(LoaderC) {
					add(FormatDLL, DeliverySubprocess, LoaderC)
				}
				if s.nativeLoaderPresent(LoaderCPP) {
					add(FormatDLL, DeliverySubprocess, LoaderCPP)
				}
			}
		}
	}
	if s.rsAvailable() {
		c.Combos = append(c.Combos, Combo{
			Agent: AgentRust, OS: "windows", Arch: "amd64",
			Format: FormatEXE, Delivery: DeliveryStaged, Loader: LoaderRust,
		})
	}
	if s.cLoaderRustReady("windows_amd64") {
		c.Combos = append(c.Combos, Combo{
			Agent: AgentRust, OS: "windows", Arch: "amd64",
			Format: FormatEXE, Delivery: DeliveryStaged, Loader: LoaderC,
		})
	}
	if s.cppLoaderRustReady("windows_amd64") {
		c.Combos = append(c.Combos, Combo{
			Agent: AgentRust, OS: "windows", Arch: "amd64",
			Format: FormatEXE, Delivery: DeliveryStaged, Loader: LoaderCPP,
		})
	}
	if s.srdiReady("windows_amd64") {
		c.Combos = append(c.Combos, Combo{
			Agent: AgentRust, OS: "windows", Arch: "amd64",
			Format: FormatShellcode, Delivery: DeliveryDirect, Loader: LoaderCPP,
		})
	}
	for _, platform := range rsPlatforms() {
		osName, arch, ok := strings.Cut(platform, "_")
		if !ok {
			continue
		}
		if s.rsDirectAvailable(platform) {
			c.Combos = append(c.Combos, Combo{
				Agent: AgentRust, OS: osName, Arch: arch,
				Format: FormatEXE, Delivery: DeliveryDirect, Loader: LoaderNone,
			})
		}
		if osName == "windows" && s.rsDLLAvailable(platform) {
			c.Combos = append(c.Combos, Combo{
				Agent: AgentRust, OS: osName, Arch: arch,
				Format: FormatDLL, Delivery: DeliveryDirect, Loader: LoaderNone,
			})
			if s.nativeLoaderPresent(LoaderC) {
				c.Combos = append(c.Combos, Combo{
					Agent: AgentRust, OS: osName, Arch: arch,
					Format: FormatDLL, Delivery: DeliverySubprocess, Loader: LoaderC,
				})
			}
			if s.nativeLoaderPresent(LoaderCPP) {
				c.Combos = append(c.Combos, Combo{
					Agent: AgentRust, OS: osName, Arch: arch,
					Format: FormatDLL, Delivery: DeliverySubprocess, Loader: LoaderCPP,
				})
			}
		}
	}
	// "poly" feature follows the decoder template (PE morphing needs no template).
	c.Features["poly"] = s.polyDecoderPresent()
	return c
}

func (s *Service) hasFile(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (s *Service) hasTemplate(kind, platform string) bool {
	return s.hasFile(s.templatePath(kind, platform))
}

func (s *Service) goDLLAvailable(platform string) bool {
	return s.hasFile(filepath.Join(s.TemplatesDir, "agent_dll_"+platform+".dll"))
}

func (s *Service) cLoaderPath() string {
	return filepath.Join(s.TemplatesDir, CLoaderName)
}

func (s *Service) cppLoaderPath() string {
	return filepath.Join(s.TemplatesDir, CPPLoaderName)
}

func (s *Service) loaderPath(loader string) string {
	if loader == LoaderCPP {
		return s.cppLoaderPath()
	}
	return s.cLoaderPath()
}

func (s *Service) nativeLoaderPresent(loader string) bool {
	st, err := os.Stat(s.loaderPath(loader))
	if err != nil {
		return false
	}
	budget := int64(CLoaderBudget)
	if loader == LoaderCPP {
		budget = CPPLoaderBudget
	}
	return st.Size() <= budget
}

func (s *Service) cLoaderPresent() bool { return s.nativeLoaderPresent(LoaderC) }

// nativeLoaderReady reports whether a native loader plus the Go stage2 pair
// exist. C++23 and C share the same delivery contract.
func (s *Service) nativeLoaderReady(loader, platform string) bool {
	return s.nativeLoaderPresent(loader) && s.hasTemplate("agent", platform) && s.hasTemplate("stage", platform)
}

func (s *Service) cLoaderReady(platform string) bool { return s.nativeLoaderReady(LoaderC, platform) }
func (s *Service) cppLoaderReady(platform string) bool {
	return s.nativeLoaderReady(LoaderCPP, platform)
}

// nativeLoaderRustReady covers the memory-map mode: the loader maps the Rust
// agent DLL and calls WispStartEx, so only the DLL template is needed.
func (s *Service) nativeLoaderRustReady(loader, platform string) bool {
	return platform == "windows_amd64" && s.nativeLoaderPresent(loader) && s.rsDLLAvailable(platform)
}

func (s *Service) cLoaderRustReady(platform string) bool {
	return s.nativeLoaderRustReady(LoaderC, platform)
}

func (s *Service) cppLoaderRustReady(platform string) bool {
	return s.nativeLoaderRustReady(LoaderCPP, platform)
}

func (s *Service) srdiBootstrapPath() string {
	return filepath.Join(s.TemplatesDir, SRDIBootstrapName)
}

func (s *Service) srdiBootstrapPresent() bool {
	st, err := os.Stat(s.srdiBootstrapPath())
	return err == nil && st.Size() <= SRDIBootstrapBudget
}

// srdiReady reports whether a bootstrap plus the Rust agent DLL exist. The
// shellcode embeds the config-patched DLL, so no stage templates are needed.
func (s *Service) srdiReady(platform string) bool {
	return platform == "windows_amd64" && s.srdiBootstrapPresent() && s.rsDLLAvailable(platform)
}

func (s *Service) polyDecoderPath() string {
	return filepath.Join(s.TemplatesDir, PolyDecoderName)
}

// polyDecoderPresent gates encoded shellcode builds (PE morphing needs no
// template).
func (s *Service) polyDecoderPresent() bool {
	st, err := os.Stat(s.polyDecoderPath())
	return err == nil && st.Size() <= PolyDecoderBudget
}

func (s *Service) rsDirectAvailable(platform string) bool {
	return s.hasFile(filepath.Join(s.TemplatesDir, rsAgentName(platform)))
}

func (s *Service) rsDLLAvailable(platform string) bool {
	return s.hasFile(filepath.Join(s.TemplatesDir, "rs_agent_"+platform+".dll"))
}

func (s *Service) rsAvailable() bool {
	for _, name := range rsFiles {
		if !s.hasFile(filepath.Join(s.TemplatesDir, name)) {
			return false
		}
	}
	return true
}

func rsAgentName(platform string) string {
	name := "rs_agent_" + platform
	if strings.HasPrefix(platform, "windows") {
		name += ".exe"
	}
	return name
}

func rsPlatforms() []string {
	return []string{
		"windows_amd64", "windows_arm64",
		"linux_amd64", "linux_arm64",
		"darwin_amd64", "darwin_arm64",
	}
}

// normalize validates a v2 or legacy request and fills defaults. Planned
// options fail with a phase-specific error; unavailable template combinations
// name the template the operator has to build.
func (s *Service) normalize(spec Spec) (Spec, error) {
	if spec.OS == "" || spec.Arch == "" {
		return spec, errors.New("payload: os and arch are required")
	}
	if spec.Staged && spec.RSStaged {
		return spec, errors.New("payload: staged and rs_staged are mutually exclusive")
	}
	if spec.Agent == "" {
		if spec.RSStaged {
			spec.Agent = AgentRust
		} else {
			spec.Agent = AgentGo
		}
	}
	if spec.Agent != AgentGo && spec.Agent != AgentRust {
		return spec, fmt.Errorf("payload: unknown agent %q (want go or rust)", spec.Agent)
	}
	if spec.Agent == AgentRust && spec.Staged && spec.Loader != LoaderC && spec.Loader != LoaderCPP {
		return spec, errors.New("payload: rust staged payloads use delivery=staged (rs_staged), not staged")
	}
	if spec.Agent == AgentGo && spec.RSStaged {
		return spec, errors.New("payload: rs_staged requires agent=rust")
	}

	if spec.Format == "" {
		spec.Format = FormatEXE
	}
	switch spec.Format {
	case FormatEXE, FormatDLL, FormatSvc, FormatScript, FormatShellcode:
	default:
		return spec, fmt.Errorf("payload: unknown format %q", spec.Format)
	}

	if spec.Delivery == "" {
		switch {
		case spec.Staged || spec.RSStaged || spec.Format == FormatScript:
			spec.Delivery = DeliveryStaged
		default:
			spec.Delivery = DeliveryDirect
		}
	}
	switch spec.Delivery {
	case DeliveryDirect, DeliveryStaged, DeliverySubprocess:
	default:
		return spec, fmt.Errorf("payload: unknown delivery %q", spec.Delivery)
	}
	if spec.Staged && spec.Delivery != DeliveryStaged {
		return spec, errors.New("payload: staged=true conflicts with delivery=" + spec.Delivery)
	}
	if spec.RSStaged && spec.Delivery != DeliveryStaged {
		return spec, errors.New("payload: rs_staged requires delivery=staged")
	}

	if spec.Loader == "" {
		switch {
		case spec.Format == FormatShellcode:
			spec.Loader = LoaderCPP
		case spec.Format == FormatDLL && spec.Delivery == DeliverySubprocess:
			spec.Loader = LoaderC
			if spec.Agent == AgentRust {
				spec.Loader = LoaderCPP
			}
		case spec.Delivery == DeliveryDirect:
			spec.Loader = LoaderNone
		case spec.Format == FormatScript:
			spec.Loader = LoaderNone
		case spec.Agent == AgentRust:
			spec.Loader = LoaderRust
		default:
			spec.Loader = LoaderGo
		}
	}
	switch spec.Loader {
	case LoaderNone, LoaderGo, LoaderRust:
	case LoaderC, LoaderCPP:
		label := "C"
		if spec.Loader == LoaderCPP {
			label = "C++"
		}
		if spec.OS != "windows" || spec.Arch != "amd64" {
			return spec, fmt.Errorf("payload: %s loader is windows_amd64 only", label)
		}
		if spec.Format == FormatShellcode {
			if spec.Loader != LoaderCPP {
				return spec, errors.New("payload: shellcode requires loader=cpp (sRDI bootstrap)")
			}
		} else if spec.Format == FormatDLL {
			if spec.Delivery != DeliverySubprocess {
				return spec, fmt.Errorf("payload: dll with %s loader requires delivery=subprocess", label)
			}
		} else if spec.Format != FormatEXE || spec.Delivery != DeliveryStaged {
			return spec, fmt.Errorf("payload: %s loader requires exe format and staged delivery", label)
		}
	default:
		return spec, fmt.Errorf("payload: unknown loader %q", spec.Loader)
	}

	platform := spec.OS + "_" + spec.Arch
	switch spec.Format {
	case FormatShellcode:
		if spec.Agent != AgentRust {
			return spec, errors.New("payload: shellcode format is only available for the Rust agent")
		}
		if spec.OS != "windows" || spec.Arch != "amd64" {
			return spec, errors.New("payload: shellcode is windows_amd64 only")
		}
		if spec.Delivery != DeliveryDirect || spec.Loader != LoaderCPP {
			return spec, errors.New("payload: shellcode requires delivery=direct and loader=cpp")
		}
	case FormatDLL:
		if spec.OS != "windows" {
			return spec, errors.New("payload: dll format is windows only")
		}
		switch spec.Delivery {
		case DeliveryDirect:
			if spec.Loader != LoaderNone {
				return spec, errors.New("payload: dll direct delivery requires loader=none")
			}
		case DeliverySubprocess:
			if spec.Loader != LoaderC && spec.Loader != LoaderCPP {
				return spec, errors.New("payload: dll subprocess delivery requires loader=c or cpp")
			}
		default:
			return spec, errors.New("payload: dll format requires delivery=direct or subprocess")
		}
	case FormatSvc:
		if spec.OS != "windows" {
			return spec, errors.New("payload: svc format is windows only")
		}
		if spec.Agent != AgentGo {
			return spec, errors.New("payload: svc format is only available for the Go agent")
		}
		if spec.Delivery != DeliveryDirect || spec.Loader != LoaderNone {
			return spec, errors.New("payload: svc format requires delivery=direct and loader=none")
		}
	case FormatScript:
		if spec.Agent != AgentGo {
			return spec, errors.New("payload: script format is only available for the Go agent")
		}
		if spec.Delivery != DeliveryStaged || spec.Loader != LoaderNone {
			return spec, errors.New("payload: script format requires delivery=staged and loader=none")
		}
	case FormatEXE:
		if spec.Delivery == DeliverySubprocess {
			return spec, errors.New("payload: exe delivery=subprocess is not supported; use format=dll")
		}
		if spec.Delivery == DeliveryDirect && spec.Loader != LoaderNone {
			return spec, errors.New("payload: direct delivery requires loader=none")
		}
		if spec.Delivery == DeliveryStaged && spec.Loader != LoaderC && spec.Loader != LoaderCPP {
			want := LoaderGo
			if spec.Agent == AgentRust {
				want = LoaderRust
			}
			if spec.Loader != want {
				return spec, fmt.Errorf("payload: %s staged delivery requires loader=%s", spec.Agent, want)
			}
		}
	}

	switch {
	case spec.Format == FormatShellcode:
		if !s.srdiBootstrapPresent() {
			return spec, fmt.Errorf("payload: no sRDI bootstrap template (build with loaders/srdi/build.sh --install)")
		}
		if !s.rsDLLAvailable(platform) {
			return spec, fmt.Errorf("payload: no Rust DLL template for %s (run scripts/build-rs-templates.sh)", platform)
		}
		if spec.Poly != nil && spec.Poly.Enabled && !s.polyDecoderPresent() {
			return spec, fmt.Errorf("payload: no poly decoder template (build with loaders/poly/build.sh --install)")
		}
	case spec.Format == FormatDLL && spec.Delivery == DeliverySubprocess:
		label := "C"
		if spec.Loader == LoaderCPP {
			label = "C++"
		}
		if !s.nativeLoaderPresent(spec.Loader) {
			return spec, fmt.Errorf("payload: no %s loader template (build with loaders/%s/build.sh --install)",
				label, map[string]string{LoaderC: "c", LoaderCPP: "cpp"}[spec.Loader])
		}
		if spec.Agent == AgentGo && !s.goDLLAvailable(platform) {
			return spec, fmt.Errorf("payload: no Go DLL template for %s (build with scripts/build-agent.sh -format dll)", platform)
		}
		if spec.Agent == AgentRust && !s.rsDLLAvailable(platform) {
			return spec, fmt.Errorf("payload: no Rust DLL template for %s (run scripts/build-rs-templates.sh)", platform)
		}
	case spec.Format == FormatDLL && spec.Agent == AgentGo:
		if !s.goDLLAvailable(platform) {
			return spec, fmt.Errorf("payload: no Go DLL template for %s (build with scripts/build-agent.sh -format dll)", platform)
		}
	case spec.Format == FormatDLL && spec.Agent == AgentRust:
		if !s.rsDLLAvailable(platform) {
			return spec, fmt.Errorf("payload: no Rust DLL template for %s (run scripts/build-rs-templates.sh)", platform)
		}
	case spec.Format == FormatSvc, spec.Format == FormatScript:
		if !s.hasTemplate("agent", platform) {
			return spec, fmt.Errorf("payload: no agent template for %s (run build_templates)", platform)
		}
	case spec.Loader == LoaderC || spec.Loader == LoaderCPP:
		loaderPath := s.loaderPath(spec.Loader)
		budget := int64(CLoaderBudget)
		label, script := "C", "loaders/c/build.sh"
		if spec.Loader == LoaderCPP {
			budget, label, script = CPPLoaderBudget, "C++", "loaders/cpp/build.sh"
		}
		if !s.hasFile(loaderPath) {
			return spec, fmt.Errorf("payload: no %s loader template (build with %s --install)", label, script)
		}
		if st, err := os.Stat(loaderPath); err == nil && st.Size() > budget {
			return spec, fmt.Errorf("payload: %s loader template is %d bytes, budget is %d", label, st.Size(), budget)
		}
		if spec.Agent == AgentRust {
			if !s.rsDLLAvailable(platform) {
				return spec, fmt.Errorf("payload: no Rust DLL template for %s (run scripts/build-rs-templates.sh)", platform)
			}
		} else if !s.hasTemplate("agent", platform) || !s.hasTemplate("stage", platform) {
			return spec, fmt.Errorf("payload: no agent/stage template for %s (run build_templates)", platform)
		}
	case spec.Agent == AgentGo && spec.Delivery == DeliveryDirect:
		if !s.hasTemplate("agent", platform) {
			return spec, fmt.Errorf("payload: no agent template for %s (run build_templates)", platform)
		}
	case spec.Agent == AgentGo && spec.Delivery == DeliveryStaged:
		if !s.hasTemplate("agent", platform) || !s.hasTemplate("stage", platform) {
			return spec, fmt.Errorf("payload: no agent/stage template for %s (run build_templates)", platform)
		}
	case spec.Agent == AgentRust && spec.Delivery == DeliveryDirect:
		if !s.rsDirectAvailable(platform) {
			return spec, fmt.Errorf("payload: no Rust agent template for %s (run scripts/build-rs-templates.sh)", platform)
		}
	case spec.Agent == AgentRust && spec.Delivery == DeliveryStaged:
		if spec.Format != FormatEXE {
			return spec, errors.New("payload: rust staged delivery is only available as exe")
		}
		if platform != "windows_amd64" {
			return spec, errors.New("payload: layered rust payload is windows_amd64 only")
		}
		if !s.rsAvailable() {
			return spec, errors.New("payload: rs templates missing (run scripts/build-rs-templates.sh)")
		}
	}

	if spec.Source == "" {
		spec.Source = SourceTemplate
	}
	if spec.Source != SourceTemplate {
		return spec, errors.New("payload: runtime source builds are not enabled; build templates offline with scripts/build-agent.sh")
	}
	if spec.Profile != "" && s.Profiles == nil {
		return spec, errors.New("payload: profile binding requires the teamserver profile resolver")
	}
	if spec.Poly != nil && spec.Poly.Enabled {
		if spec.Poly.Passes < 0 || spec.Poly.Passes > 4 {
			return spec, errors.New("payload: poly passes must be 1..4")
		}
		if len(spec.Poly.Seed) > 64 {
			return spec, errors.New("payload: poly seed too long (max 64 bytes)")
		}
	}

	// Keep the legacy booleans coherent for the existing generation paths.
	spec.Staged = spec.Delivery == DeliveryStaged && spec.Agent == AgentGo
	spec.RSStaged = spec.Delivery == DeliveryStaged && spec.Agent == AgentRust &&
		spec.Format == FormatEXE && spec.Loader == LoaderRust
	return spec, nil
}
