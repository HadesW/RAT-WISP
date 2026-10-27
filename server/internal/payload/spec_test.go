package payload

import (
	"strings"
	"testing"
)

func comboExists(c Capabilities, agent, osName, arch, format, delivery, loader string) bool {
	for _, x := range c.Combos {
		if x.Agent == agent && x.OS == osName && x.Arch == arch && x.Format == format &&
			x.Delivery == delivery && x.Loader == loader {
			return true
		}
	}
	return false
}

func TestCapabilitiesReflectTemplates(t *testing.T) {
	dir := t.TempDir()
	synthTemplate(t, dir, "agent_darwin_arm64")
	synthTemplate(t, dir, "stage_darwin_arm64")
	svc := &Service{TemplatesDir: dir}

	c := svc.Capabilities()
	if c.Schema != 2 {
		t.Fatalf("schema: %d", c.Schema)
	}
	if !comboExists(c, AgentGo, "darwin", "arm64", FormatEXE, DeliveryDirect, LoaderNone) {
		t.Fatalf("go direct combo missing: %+v", c.Combos)
	}
	if !comboExists(c, AgentGo, "darwin", "arm64", FormatEXE, DeliveryStaged, LoaderGo) {
		t.Fatalf("go staged combo missing: %+v", c.Combos)
	}
	if !comboExists(c, AgentGo, "darwin", "arm64", FormatScript, DeliveryStaged, LoaderNone) {
		t.Fatalf("go script combo missing: %+v", c.Combos)
	}
	if comboExists(c, AgentGo, "darwin", "arm64", FormatDLL, DeliveryDirect, LoaderNone) {
		t.Fatal("non-windows dll combo offered")
	}
	if comboExists(c, AgentRust, "windows", "amd64", FormatEXE, DeliveryStaged, LoaderRust) {
		t.Fatal("rust combo offered without rs templates")
	}
	if len(c.Planned) == 0 {
		t.Fatalf("planned/features: %+v %+v", c.Planned, c.Features)
	}

	// Agent templates only: direct is available, staged is not.
	onlyDirect := &Service{TemplatesDir: t.TempDir()}
	synthTemplate(t, onlyDirect.TemplatesDir, "agent_linux_amd64")
	c = onlyDirect.Capabilities()
	if !comboExists(c, AgentGo, "linux", "amd64", FormatEXE, DeliveryDirect, LoaderNone) {
		t.Fatal("direct combo missing")
	}
	if comboExists(c, AgentGo, "linux", "amd64", FormatEXE, DeliveryStaged, LoaderGo) {
		t.Fatal("staged combo offered without a stage template")
	}

	for _, f := range rsFiles {
		synthTemplate(t, dir, f)
	}
	c = svc.Capabilities()
	if !comboExists(c, AgentRust, "windows", "amd64", FormatEXE, DeliveryStaged, LoaderRust) {
		t.Fatalf("rust combo missing with rs templates: %+v", c.Combos)
	}

	// P1 formats: Go DLL/svc on Windows and direct Rust binaries.
	synthTemplate(t, dir, "agent_windows_amd64.exe")
	synthTemplate(t, dir, "stage_windows_amd64.exe")
	synthTemplate(t, dir, "agent_dll_windows_amd64.dll")
	synthTemplate(t, dir, "rs_agent_windows_amd64.exe")
	synthTemplate(t, dir, "rs_agent_windows_amd64.dll")
	synthTemplate(t, dir, "rs_agent_linux_amd64")
	c = svc.Capabilities()
	for _, want := range []struct{ agent, osName, arch, format, delivery, loader string }{
		{AgentGo, "windows", "amd64", FormatSvc, DeliveryDirect, LoaderNone},
		{AgentGo, "windows", "amd64", FormatDLL, DeliveryDirect, LoaderNone},
		{AgentRust, "windows", "amd64", FormatEXE, DeliveryDirect, LoaderNone},
		{AgentRust, "windows", "amd64", FormatDLL, DeliveryDirect, LoaderNone},
		{AgentRust, "linux", "amd64", FormatEXE, DeliveryDirect, LoaderNone},
	} {
		if !comboExists(c, want.agent, want.osName, want.arch, want.format, want.delivery, want.loader) {
			t.Fatalf("missing combo %+v in %+v", want, c.Combos)
		}
	}
	if comboExists(c, AgentGo, "windows", "amd64", FormatEXE, DeliveryStaged, LoaderC) {
		t.Fatal("C loader combo offered without its template")
	}
	if comboExists(c, AgentGo, "windows", "amd64", FormatEXE, DeliveryStaged, LoaderCPP) {
		t.Fatal("C++ loader combo offered without its template")
	}
	if comboExists(c, AgentGo, "windows", "amd64", FormatDLL, DeliverySubprocess, LoaderC) {
		t.Fatal("DLL subprocess combo offered without a loader template")
	}

	// Native loader combos appear only once their template is installed.
	if comboExists(c, AgentRust, "windows", "amd64", FormatEXE, DeliveryStaged, LoaderC) {
		t.Fatal("C loader Rust combo offered without its template")
	}
	synthTemplate(t, dir, CLoaderName)
	c = svc.Capabilities()
	if !comboExists(c, AgentGo, "windows", "amd64", FormatEXE, DeliveryStaged, LoaderC) {
		t.Fatalf("C loader combo missing: %+v", c.Combos)
	}
	if !comboExists(c, AgentRust, "windows", "amd64", FormatEXE, DeliveryStaged, LoaderC) {
		t.Fatalf("C loader Rust combo missing: %+v", c.Combos)
	}
	for _, agent := range []string{AgentGo, AgentRust} {
		if !comboExists(c, agent, "windows", "amd64", FormatDLL, DeliverySubprocess, LoaderC) {
			t.Fatalf("%s DLL subprocess combo missing: %+v", agent, c.Combos)
		}
	}
	if comboExists(c, AgentRust, "windows", "amd64", FormatEXE, DeliveryStaged, LoaderCPP) {
		t.Fatal("C++ loader Rust combo offered without its template")
	}
	synthTemplate(t, dir, CPPLoaderName)
	c = svc.Capabilities()
	if !comboExists(c, AgentGo, "windows", "amd64", FormatEXE, DeliveryStaged, LoaderCPP) {
		t.Fatalf("C++ loader combo missing: %+v", c.Combos)
	}
	if !comboExists(c, AgentRust, "windows", "amd64", FormatEXE, DeliveryStaged, LoaderCPP) {
		t.Fatalf("C++ loader Rust combo missing: %+v", c.Combos)
	}
	for _, agent := range []string{AgentGo, AgentRust} {
		if !comboExists(c, agent, "windows", "amd64", FormatDLL, DeliverySubprocess, LoaderCPP) {
			t.Fatalf("%s DLL subprocess C++ combo missing: %+v", agent, c.Combos)
		}
	}
	if comboExists(c, AgentRust, "windows", "amd64", FormatShellcode, DeliveryDirect, LoaderCPP) {
		t.Fatal("shellcode combo offered without the sRDI bootstrap")
	}
	synthTemplate(t, dir, SRDIBootstrapName)
	c = svc.Capabilities()
	if !comboExists(c, AgentRust, "windows", "amd64", FormatShellcode, DeliveryDirect, LoaderCPP) {
		t.Fatalf("shellcode combo missing: %+v", c.Combos)
	}
}

func TestNormalizeLegacyAndV2(t *testing.T) {
	dir := t.TempDir()
	synthTemplate(t, dir, "agent_darwin_arm64")
	synthTemplate(t, dir, "stage_darwin_arm64")
	synthTemplate(t, dir, "agent_windows_amd64.exe")
	synthTemplate(t, dir, "stage_windows_amd64.exe")
	synthTemplate(t, dir, "agent_dll_windows_amd64.dll")
	synthTemplate(t, dir, CLoaderName)
	synthTemplate(t, dir, CPPLoaderName)
	synthTemplate(t, dir, SRDIBootstrapName)
	synthTemplate(t, dir, "rs_agent_windows_amd64.dll")
	svc := &Service{TemplatesDir: dir}

	spec, err := svc.normalize(Spec{OS: "darwin", Arch: "arm64"})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Agent != AgentGo || spec.Format != FormatEXE || spec.Delivery != DeliveryDirect ||
		spec.Loader != LoaderNone || spec.Source != SourceTemplate || spec.Staged || spec.RSStaged {
		t.Fatalf("direct defaults: %+v", spec)
	}

	spec, err = svc.normalize(Spec{OS: "darwin", Arch: "arm64", Staged: true})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Delivery != DeliveryStaged || spec.Loader != LoaderGo || !spec.Staged || spec.RSStaged {
		t.Fatalf("legacy staged: %+v", spec)
	}

	// V2 fields alone must select the same path without the legacy booleans.
	spec, err = svc.normalize(Spec{OS: "darwin", Arch: "arm64", Agent: AgentGo,
		Format: FormatEXE, Delivery: DeliveryStaged, Loader: LoaderGo})
	if err != nil {
		t.Fatal(err)
	}
	if !spec.Staged || spec.Delivery != DeliveryStaged {
		t.Fatalf("v2 staged: %+v", spec)
	}

	spec, err = svc.normalize(Spec{OS: "windows", Arch: "amd64", Agent: AgentGo,
		Format: FormatEXE, Delivery: DeliveryStaged, Loader: LoaderC})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Loader != LoaderC || spec.Delivery != DeliveryStaged || !spec.Staged {
		t.Fatalf("c loader staged: %+v", spec)
	}

	// loader=c with the Rust agent is the memory-map path: not Go-staged and
	// not the layered-RS builder path.
	spec, err = svc.normalize(Spec{OS: "windows", Arch: "amd64", Agent: AgentRust,
		Format: FormatEXE, Delivery: DeliveryStaged, Loader: LoaderC, Staged: true})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Loader != LoaderC || spec.Agent != AgentRust || spec.Staged || spec.RSStaged {
		t.Fatalf("c loader rust staged: %+v", spec)
	}

	spec, err = svc.normalize(Spec{OS: "windows", Arch: "amd64", Agent: AgentRust,
		Format: FormatEXE, Delivery: DeliveryStaged, Loader: LoaderCPP, Staged: true})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Loader != LoaderCPP || spec.Agent != AgentRust || spec.Staged || spec.RSStaged {
		t.Fatalf("c++ loader rust staged: %+v", spec)
	}

	spec, err = svc.normalize(Spec{OS: "windows", Arch: "amd64", Agent: AgentGo,
		Format: FormatEXE, Delivery: DeliveryStaged, Loader: LoaderCPP})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Loader != LoaderCPP || !spec.Staged {
		t.Fatalf("c++ loader go staged: %+v", spec)
	}

	spec, err = svc.normalize(Spec{OS: "windows", Arch: "amd64", Agent: AgentRust,
		Format: FormatShellcode})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Delivery != DeliveryDirect || spec.Loader != LoaderCPP || spec.Staged || spec.RSStaged {
		t.Fatalf("shellcode defaults: %+v", spec)
	}

	spec, err = svc.normalize(Spec{OS: "windows", Arch: "amd64", Agent: AgentGo,
		Format: FormatDLL, Delivery: DeliverySubprocess})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Loader != LoaderC || spec.Delivery != DeliverySubprocess || spec.Staged {
		t.Fatalf("go dll subprocess: %+v", spec)
	}
	spec, err = svc.normalize(Spec{OS: "windows", Arch: "amd64", Agent: AgentRust,
		Format: FormatDLL, Delivery: DeliverySubprocess})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Loader != LoaderCPP || spec.Delivery != DeliverySubprocess {
		t.Fatalf("rust dll subprocess: %+v", spec)
	}

	// P1 formats normalize to the direct/staged paths they need.
	for _, tc := range []struct {
		name         string
		spec         Spec
		wantFormat   string
		wantDelivery string
		wantLoader   string
		wantStaged   bool
	}{
		{"go dll", Spec{OS: "windows", Arch: "amd64", Format: FormatDLL}, FormatDLL, DeliveryDirect, LoaderNone, false},
		{"go svc", Spec{OS: "windows", Arch: "amd64", Format: FormatSvc}, FormatSvc, DeliveryDirect, LoaderNone, false},
		{"go script", Spec{OS: "windows", Arch: "amd64", Format: FormatScript}, FormatScript, DeliveryStaged, LoaderNone, true},
	} {
		got, err := svc.normalize(tc.spec)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got.Agent != AgentGo || got.Format != tc.wantFormat || got.Delivery != tc.wantDelivery ||
			got.Loader != tc.wantLoader || got.Staged != tc.wantStaged {
			t.Fatalf("%s: %+v", tc.name, got)
		}
	}

	cases := []struct {
		name string
		spec Spec
		want string
	}{
		{"shellcode go", Spec{OS: "windows", Arch: "amd64", Agent: AgentGo,
			Format: FormatShellcode}, "only available for the Rust agent"},
		{"shellcode staged", Spec{OS: "windows", Arch: "amd64", Agent: AgentRust,
			Format: FormatShellcode, Delivery: DeliveryStaged}, "requires delivery=direct"},
		{"shellcode c loader", Spec{OS: "windows", Arch: "amd64", Agent: AgentRust,
			Format: FormatShellcode, Loader: LoaderC}, "shellcode requires loader=cpp"},
		{"exe subprocess", Spec{OS: "windows", Arch: "amd64", Agent: AgentGo,
			Delivery: DeliverySubprocess}, "not supported; use format=dll"},
		{"dll subprocess rust loader", Spec{OS: "windows", Arch: "amd64", Agent: AgentGo,
			Format: FormatDLL, Delivery: DeliverySubprocess, Loader: LoaderRust}, "requires loader=c or cpp"},
		{"dll staged", Spec{OS: "windows", Arch: "amd64", Agent: AgentGo,
			Format: FormatDLL, Delivery: DeliveryStaged}, "requires delivery=direct or subprocess"},
		{"c loader non-windows", Spec{OS: "darwin", Arch: "arm64", Agent: AgentGo,
			Delivery: DeliveryStaged, Loader: LoaderC}, "windows_amd64 only"},
		{"c++ loader non-windows", Spec{OS: "darwin", Arch: "arm64", Agent: AgentGo,
			Delivery: DeliveryStaged, Loader: LoaderCPP}, "windows_amd64 only"},
		{"c++ loader direct", Spec{OS: "windows", Arch: "amd64", Agent: AgentGo,
			Delivery: DeliveryDirect, Loader: LoaderCPP}, "requires exe format and staged delivery"},
		{"c loader direct", Spec{OS: "windows", Arch: "amd64", Agent: AgentGo,
			Delivery: DeliveryDirect, Loader: LoaderC}, "requires exe format and staged delivery"},
		{"c loader rust cross platform", Spec{OS: "linux", Arch: "amd64", Agent: AgentRust,
			Delivery: DeliveryStaged, Loader: LoaderC}, "windows_amd64 only"},
		{"source build", Spec{OS: "darwin", Arch: "arm64", Source: SourceBuild}, "build templates offline"},
		{"profile", Spec{OS: "darwin", Arch: "arm64", Profile: "cdn"}, "profile resolver"},
		{"poly passes", Spec{OS: "darwin", Arch: "arm64", Poly: &PolySpec{Enabled: true, Passes: 9}}, "poly passes must be 1..4"},
		{"direct loader", Spec{OS: "darwin", Arch: "arm64", Agent: AgentGo,
			Delivery: DeliveryDirect, Loader: LoaderGo}, "direct delivery requires loader=none"},
		{"dll non-windows", Spec{OS: "darwin", Arch: "arm64", Format: FormatDLL}, "windows only"},
		{"dll loader", Spec{OS: "windows", Arch: "amd64", Format: FormatDLL, Loader: LoaderGo}, "direct delivery requires loader=none"},
		{"svc rust", Spec{OS: "windows", Arch: "amd64", Agent: AgentRust, Format: FormatSvc}, "only available for the Go agent"},
		{"script direct", Spec{OS: "windows", Arch: "amd64", Format: FormatScript,
			Delivery: DeliveryDirect}, "requires delivery=staged"},
		{"missing template", Spec{OS: "plan9", Arch: "riscv"}, "no agent template"},
		{"rust cross platform", Spec{OS: "linux", Arch: "amd64", Agent: AgentRust,
			Delivery: DeliveryStaged, Loader: LoaderRust}, "windows_amd64 only"},
		{"missing go dll", Spec{OS: "windows", Arch: "arm64", Format: FormatDLL}, "no Go DLL template"},
	}
	for _, tc := range cases {
		if _, err := svc.normalize(tc.spec); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: err=%v want %q", tc.name, err, tc.want)
		}
	}

	noC := &Service{TemplatesDir: t.TempDir()}
	if _, err := noC.normalize(Spec{OS: "windows", Arch: "amd64", Agent: AgentGo,
		Delivery: DeliveryStaged, Loader: LoaderC}); err == nil ||
		!strings.Contains(err.Error(), "no C loader template") {
		t.Fatalf("missing C loader template: %v", err)
	}
	if _, err := noC.normalize(Spec{OS: "windows", Arch: "amd64", Agent: AgentGo,
		Delivery: DeliveryStaged, Loader: LoaderCPP}); err == nil ||
		!strings.Contains(err.Error(), "no C++ loader template") {
		t.Fatalf("missing C++ loader template: %v", err)
	}
	if _, err := noC.normalize(Spec{OS: "windows", Arch: "amd64", Agent: AgentGo,
		Format: FormatDLL, Delivery: DeliverySubprocess}); err == nil ||
		!strings.Contains(err.Error(), "no C loader template") {
		t.Fatalf("missing subprocess loader template: %v", err)
	}
}
