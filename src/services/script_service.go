package services

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ScriptService exposes the gopher-lua scripting environment to the frontend.
type ScriptService struct {
	engine *ScriptEngine
}

// NewScriptService wires the script engine to the server events and installs
// the command-alias resolver so scripts can rewrite commands (Aggressor-style
// pre-hooks: e.g. `shell` → `ps run -o cmd.exe /c …`).
func NewScriptService(svc *ServerService) *ScriptService {
	ss := &ScriptService{engine: NewScriptEngine(svc)}
	if svc != nil {
		svc.SetCommandResolver(func(cmd, args string) (string, string, bool) {
			return ss.engine.ResolveCommand(cmd, args)
		})
	}
	return ss
}

// RunScript compiles and executes a Lua script, returning captured output.
func (ss *ScriptService) RunScript(source string) (string, error) {
	return ss.engine.RunScript(source)
}

// scriptsDir returns the persistence directory for operator scripts.
func (ss *ScriptService) scriptsDir() string {
	return filepath.Join(exeDir(), "scripts")
}

// SaveScript persists a named script to disk.
func (ss *ScriptService) SaveScript(name, source string) error {
	name = sanitizeName(name)
	if name == "" {
		return os.ErrInvalid
	}
	dir := ss.scriptsDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name+".lua"), []byte(source), 0644)
}

// GetScript returns a saved script's source.
func (ss *ScriptService) GetScript(name string) (string, error) {
	name = sanitizeName(name)
	b, err := os.ReadFile(filepath.Join(ss.scriptsDir(), name+".lua"))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// DeleteScript removes a saved script.
func (ss *ScriptService) DeleteScript(name string) error {
	name = sanitizeName(name)
	return os.Remove(filepath.Join(ss.scriptsDir(), name+".lua"))
}

// ListScripts returns the names of saved scripts.
func (ss *ScriptService) ListScripts() ([]string, error) {
	entries, err := os.ReadDir(ss.scriptsDir())
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".lua") {
			continue
		}
		out = append(out, strings.TrimSuffix(e.Name(), ".lua"))
	}
	sort.Strings(out)
	return out, nil
}

// ListNotes returns operator notes recorded by scripts.
func (ss *ScriptService) ListNotes() []string {
	ss.engine.mu.Lock()
	defer ss.engine.mu.Unlock()
	out := make([]string, len(ss.engine.notes))
	copy(out, ss.engine.notes)
	return out
}

// AliasSummary describes a registered command alias for the UI.
type AliasSummary struct {
	Name    string `json:"name"`
	Command string `json:"command"`
	Args    string `json:"args"`
	Help    string `json:"help"`
}

// ListAliases returns all registered command aliases (from scripts).
func (ss *ScriptService) ListAliases() []AliasSummary {
	ss.engine.mu.Lock()
	names := make([]string, 0, len(ss.engine.aliases))
	for n := range ss.engine.aliases {
		names = append(names, n)
	}
	ss.engine.mu.Unlock()
	sort.Strings(names)
	out := make([]AliasSummary, 0, len(names))
	for _, n := range names {
		ss.engine.mu.Lock()
		a := ss.engine.aliases[n]
		ss.engine.mu.Unlock()
		out = append(out, AliasSummary{Name: n, Command: a.Command, Args: a.Args, Help: a.Help})
	}
	return out
}

// ResolveCommand applies script-registered alias rewriting. Returns the real
// command/args and whether an alias matched.
func (ss *ScriptService) ResolveCommand(command, args string) (string, string, bool) {
	return ss.engine.ResolveCommand(command, args)
}

// LoadWasmModule loads an additional Rust/WASM hook module.
func (ss *ScriptService) LoadWasmModule(path string) error {
	return ss.engine.LoadWasmModule(path)
}

// SetHookLogPath configures the local file that hook print() output is
// appended to (empty disables).
func (ss *ScriptService) SetHookLogPath(path string) {
	ss.engine.SetHookLogPath(path)
}

// sanitizeName keeps script names filesystem-safe.
func sanitizeName(name string) string {
	name = strings.TrimSpace(name)
	for _, r := range name {
		switch r {
		case '/', '\\', ':', '*', '?', '"', '<', '>', '|', '.', ' ', '\t':
			name = strings.ReplaceAll(name, string(r), "_")
		}
	}
	return name
}
