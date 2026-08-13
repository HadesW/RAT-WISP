// Package plugin — server-side plugin registry + manifest model (M5).
//
// Mirrors the platform plugin model from PLUGIN_PLATFORM_PLAN §2.1:
//   Plugin { id, kind, lang, commands, events, deps, platform }
//
// The registry is process-wide; agent plugins advertise their capability
// manifest on registration (or are declared by the builder), server-side
// extensions register their event hooks. The registry powers the GUI plugin
// manager and lets tooling query which agent capability (command) belongs to
// which plugin.

package plugin

import (
	"sort"
	"sync"
)

// Kind is where the plugin runs.
type Kind string

const (
	KindAgent  Kind = "agent"
	KindServer Kind = "server"
	KindBoth   Kind = "both"
)

// Lang is the implementation language.
type Lang string

const (
	LangRust Lang = "rust"
	LangGo   Lang = "go"
	LangC    Lang = "c"
	LangLua  Lang = "lua"
	LangWasm Lang = "wasm"
)

// Plugin is the manifest of a single capability module.
type Plugin struct {
	ID       string   `json:"id"`       // globally unique, e.g. "screenshot"
	Kind     Kind     `json:"kind"`     // agent | server | both
	Lang     Lang     `json:"lang"`     // implementation language
	Commands []uint32 `json:"commands"` // command IDs it registers (agent kind)
	Events   []string `json:"events"`   // event names it subscribes (server kind)
	Platform string   `json:"platform"` // "windows" | "linux" | "any"
	Deps     []string `json:"deps,omitempty"`
	Loaded   bool     `json:"loaded"` // currently registered / active
}

// Registry tracks all known plugins and which are currently loaded.
type Registry struct {
	mu      sync.RWMutex
	plugins map[string]*Plugin
	order   []string // insertion order (stable listing)
}

// NewRegistry creates an empty plugin registry.
func NewRegistry() *Registry {
	return &Registry{plugins: map[string]*Plugin{}}
}

// Declare registers a plugin's manifest (not necessarily loaded yet).
func (r *Registry) Declare(p *Plugin) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.plugins[p.ID]; !ok {
		r.order = append(r.order, p.ID)
	}
	cp := *p
	r.plugins[p.ID] = &cp
}

// Load marks a declared plugin as loaded (active).
func (r *Registry) Load(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.plugins[id]
	if !ok {
		return false
	}
	p.Loaded = true
	return true
}

// Unload marks a plugin as not loaded.
func (r *Registry) Unload(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.plugins[id]
	if !ok {
		return false
	}
	p.Loaded = false
	return true
}

// Get returns a copy of a plugin manifest.
func (r *Registry) Get(id string) (*Plugin, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.plugins[id]
	if !ok {
		return nil, false
	}
	cp := *p
	return &cp, true
}

// List returns all plugin manifests (sorted by ID).
func (r *Registry) List() []Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Plugin, 0, len(r.plugins))
	for _, id := range r.order {
		if p, ok := r.plugins[id]; ok {
			out = append(out, *p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Loaded returns the set of loaded plugin IDs.
func (r *Registry) Loaded() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []string
	for _, id := range r.order {
		if p, ok := r.plugins[id]; ok && p.Loaded {
			out = append(out, id)
		}
	}
	return out
}

// CommandOwner maps a command ID to its owning plugin ID (agent side).
func (r *Registry) CommandOwner(cmd uint32) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, id := range r.order {
		if p, ok := r.plugins[id]; ok {
			for _, c := range p.Commands {
				if c == cmd {
					return p.ID, true
				}
			}
		}
	}
	return "", false
}

// ---- process-wide default registry ----

var (
	defaultOnce sync.Once
	defaultReg  *Registry
)

// Default returns the process-wide plugin registry.
func Default() *Registry {
	defaultOnce.Do(func() {
		defaultReg = NewRegistry()
	})
	return defaultReg
}

// Seed declares the built-in Rust agent plugins so the server knows which
// command → plugin mapping exists even before any agent checks in.
func Seed() {
	d := Default()
	d.Declare(&Plugin{ID: "core", Kind: KindAgent, Lang: LangRust, Platform: "any",
		Commands: []uint32{1, 2, 3, 4, 7, 8, 9, 10, 11, 13, 14, 15, 26}})
	d.Declare(&Plugin{ID: "screenshot", Kind: KindAgent, Lang: LangRust, Platform: "windows",
		Commands: []uint32{25}})
	d.Declare(&Plugin{ID: "keylog", Kind: KindAgent, Lang: LangRust, Platform: "windows",
		Commands: []uint32{43, 44}})
	d.Declare(&Plugin{ID: "memload", Kind: KindAgent, Lang: LangRust, Platform: "windows",
		Commands: []uint32{32, 33, 34, 35, 36, 37, 38, 39}})
	d.Declare(&Plugin{ID: "evasion", Kind: KindAgent, Lang: LangRust, Platform: "windows",
		Commands: []uint32{60, 61}})
}
