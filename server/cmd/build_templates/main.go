// build_templates cross-compiles the Go agent, stager and DLL into the template
// pool consumed by the payload service (plan §4: templates are the source,
// generation only patches the sentinel slot — no compiler at runtime).
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type manifestFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type manifest struct {
	Schema    int            `json:"schema"`
	Kind      string         `json:"kind"`
	Agent     string         `json:"agent"`
	Toolchain string         `json:"toolchain"`
	Features  []string       `json:"features"`
	Source    string         `json:"source"`
	Git       string         `json:"git"`
	Dirty     bool           `json:"dirty"`
	BuiltAt   time.Time      `json:"built_at"`
	Files     []manifestFile `json:"files"`
}

func main() {
	agentKind := flag.String("agent", "go", "agent family to build (go)")
	agentDir := flag.String("agent-dir", "", "path to agent-go module (default: auto from repo layout)")
	platforms := flag.String("platforms",
		"darwin_amd64 darwin_arm64 linux_amd64 linux_arm64 linux_386 windows_amd64 windows_arm64 windows_386",
		"space/comma-separated os_arch list")
	targets := flag.String("targets", "", "alias for -platforms")
	formats := flag.String("formats", "exe,stage", "comma-separated artifacts: exe,stage,dll,svc,script (svc/script reuse the exe)")
	outDir := flag.String("out", "./templates", "templates output dir")
	manifestPath := flag.String("manifest", "", "manifest path (default: <out>/go_manifest.json)")
	allowDirty := flag.Bool("allow-dirty", false, "allow building from a dirty worktree")
	flag.Parse()

	if *agentKind != "go" {
		log.Fatalf("build_templates only builds the Go agent (got -agent %q)", *agentKind)
	}
	if *targets != "" {
		*platforms = *targets
	}
	platformsList := splitList(*platforms)
	formatsSet := map[string]bool{}
	for _, f := range splitList(*formats) {
		switch f {
		case "exe", "stage", "dll", "svc", "script":
			formatsSet[f] = true
		default:
			log.Fatalf("unknown -formats entry %q", f)
		}
	}
	if formatsSet["svc"] || formatsSet["script"] {
		formatsSet["exe"] = true // svc/script reuse the exe
	}

	if *agentDir == "" {
		*agentDir = filepath.Join("..", "agent", "agent-go")
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		log.Fatal(err)
	}
	abs, err := filepath.Abs(*outDir) // -o is resolved relative to cmd.Dir
	if err != nil {
		log.Fatal(err)
	}
	*outDir = abs
	if *manifestPath == "" {
		*manifestPath = filepath.Join(*outDir, "go_manifest.json")
	}

	dirty := worktreeDirty(*agentDir)
	if dirty && !*allowDirty {
		log.Fatalf("build_templates: worktree is dirty; pass -allow-dirty to build test templates")
	}

	cgo := false
	n := 0
	for _, p := range platformsList {
		goos, goarch, ok := strings.Cut(p, "_")
		if !ok {
			log.Fatalf("bad platform %q (want os_arch)", p)
		}
		if formatsSet["exe"] {
			out := filepath.Join(*outDir, "agent_"+goos+"_"+goarch)
			if goos == "windows" {
				out += ".exe"
			}
			buildGo(*agentDir, goos, goarch, false, ".", out)
			n++
		}
		if formatsSet["stage"] {
			out := filepath.Join(*outDir, "stage_"+goos+"_"+goarch)
			if goos == "windows" {
				out += ".exe"
			}
			buildGo(*agentDir, goos, goarch, false, "./cmd/stager", out)
			n++
		}
		if formatsSet["dll"] && goos == "windows" && goarch == "amd64" {
			out := filepath.Join(*outDir, "agent_dll_windows_amd64.dll")
			buildGo(*agentDir, goos, goarch, true, ".", out)
			cgo = true
			n++
		}
		fmt.Printf("built %s\n", p)
	}

	// Manifest: the console verifies each template against these hashes and
	// shows the commit the artifacts were built from.
	mf := manifest{
		Schema: 2, Kind: "go", Agent: "go", Toolchain: "go",
		Features: []string{"rcp", "view", "file", "plugin-wasm", "quic"},
		Source:   "prebuilt", Git: gitRev(*agentDir), Dirty: dirty,
		BuiltAt: time.Now().UTC(), Files: make([]manifestFile, 0, n),
	}
	if cgo {
		mf.Toolchain = "go+cgo(mingw-w64)"
		mf.Features = append(mf.Features, "dll")
	}
	if formatsSet["svc"] {
		mf.Features = append(mf.Features, "svc")
	}
	if formatsSet["script"] {
		mf.Features = append(mf.Features, "script-stager")
	}
	entries, err := os.ReadDir(*outDir)
	if err != nil {
		log.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || strings.Contains(name, "manifest") {
			continue
		}
		if !strings.HasPrefix(name, "agent_") && !strings.HasPrefix(name, "stage_") {
			continue // leave rs_* to the layered template manifest
		}
		path := filepath.Join(*outDir, name)
		f, err := os.Open(path)
		if err != nil {
			log.Fatal(err)
		}
		h := sha256.New()
		size, err := io.Copy(h, f)
		f.Close()
		if err != nil {
			log.Fatal(err)
		}
		mf.Files = append(mf.Files, manifestFile{Name: name, SHA256: hex.EncodeToString(h.Sum(nil)), Size: size})
	}
	raw, err := json.MarshalIndent(mf, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*manifestPath, raw, 0o644); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("done: %d templates in %s (manifest %s)\n", n, *outDir, *manifestPath)
}

func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' })
}

func buildGo(agentDir, goos, goarch string, cgo bool, pkg, out string) {
	args := []string{"build", "-trimpath", "-buildvcs=false", "-ldflags", "-s -w", "-o", out}
	if cgo {
		args = append(args, "-buildmode=c-shared")
	}
	args = append(args, pkg)
	cmd := exec.Command("go", args...)
	cmd.Dir = agentDir
	env := append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch)
	if cgo {
		if _, err := exec.LookPath(cc()); err != nil {
			log.Fatalf("dll build needs a C compiler (%s not found); install mingw-w64 or set CC", cc())
		}
		env = append(env, "CGO_ENABLED=1")
	} else {
		env = append(env, "CGO_ENABLED=0")
	}
	cmd.Env = env
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("build %s %s/%s: %v", pkg, goos, goarch, err)
	}
	if cgo { // c-shared also emits a C header next to the output
		_ = os.Remove(strings.TrimSuffix(out, filepath.Ext(out)) + ".h")
	}
}

func cc() string {
	if v := os.Getenv("CC"); v != "" {
		return v
	}
	return "gcc"
}

func gitRev(dir string) string {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "--short=12", "HEAD").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func worktreeDirty(dir string) bool {
	out, err := exec.Command("git", "-C", dir, "status", "--porcelain").Output()
	if err != nil {
		return false
	}
	return len(strings.TrimSpace(string(out))) > 0
}
