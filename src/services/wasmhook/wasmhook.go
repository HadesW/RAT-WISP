// Package wasmhook loads WebAssembly hook modules (Rust/WASI) and dispatches
// unified C2 hook contexts to them, alongside the gopher-lua engine.
//
// ABI (module exports):
//
//	wisp_alloc(size:i32)->i32     allocate `size` bytes, return linear-memory ptr
//	wisp_handle(ptr:i32, len:i32)->i32
//	                              input JSON at ptr; returns ptr to output JSON
//	wisp_handle_len()->i32        length of the output JSON returned by handle
//
// Input/Output JSON shape:
//
//	{ "event": "...", "phase": "pre|post",
//	  "abort": false,
//	  "input": { ... }, "output": { ... } }
//
// The module returns the same shape after applying its transformation; the Go
// side merges input/output/abort back into the HookContext.
package wasmhook

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// HookContext mirrors server.HookContext (duplicated to avoid an import cycle).
type HookContext struct {
	Event  string         `json:"event"`
	Phase  string         `json:"phase"`
	Input  map[string]any `json:"input"`
	Output map[string]any `json:"output"`
	Abort  bool           `json:"abort"`
}

// Module is one loaded .wasm hook module.
type Module struct {
	name   string
	mod    api.Module
	alloc  api.Function
	handle api.Function
	hlen   api.Function
	ctx    context.Context
}

// Runtime manages all loaded WASM hook modules.
type Runtime struct {
	mu      sync.Mutex
	modules []*Module
	ctx     context.Context
}

// NewRuntime creates an empty runtime.
func NewRuntime() *Runtime {
	return &Runtime{ctx: context.Background()}
}

// LoadDir loads every *.wasm file in dir as a hook module.
func (r *Runtime) LoadDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".wasm") {
			continue
		}
		if err := r.LoadFile(filepath.Join(dir, e.Name())); err != nil {
			// A bad module must not take the server down.
			return fmt.Errorf("wasmhook: load %s: %w", e.Name(), err)
		}
	}
	return nil
}

// LoadFile loads a single .wasm module.
func (r *Runtime) LoadFile(path string) error {
	wasmBytes, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	cfg := wazero.NewRuntimeConfig().WithCloseOnContextDone(true)
	rt := wazero.NewRuntimeWithConfig(r.ctx, cfg)
	if _, err := wasi_snapshot_preview1.Instantiate(r.ctx, rt); err != nil {
		return fmt.Errorf("wasi: %w", err)
	}
	compiled, err := rt.CompileModule(r.ctx, wasmBytes)
	if err != nil {
		return fmt.Errorf("compile: %w", err)
	}
	mod, err := rt.InstantiateModule(r.ctx, compiled, wazero.NewModuleConfig().WithName("hook_"+filepath.Base(path)))
	if err != nil {
		return fmt.Errorf("instantiate: %w", err)
	}

	alloc := mod.ExportedFunction("wisp_alloc")
	handle := mod.ExportedFunction("wisp_handle")
	hlen := mod.ExportedFunction("wisp_handle_len")
	if alloc == nil || handle == nil || hlen == nil {
		_ = mod.Close(r.ctx)
		return fmt.Errorf("module %s missing wisp_alloc/wisp_handle/wisp_handle_len", filepath.Base(path))
	}

	r.mu.Lock()
	r.modules = append(r.modules, &Module{name: filepath.Base(path), mod: mod, alloc: alloc, handle: handle, hlen: hlen, ctx: r.ctx})
	r.mu.Unlock()
	return nil
}

// Hook dispatches a hook context to every loaded WASM module that wants it.
// Returns the merged context (input/output/abort possibly modified).
func (r *Runtime) Hook(hc *HookContext) {
	r.mu.Lock()
	mods := make([]*Module, len(r.modules))
	copy(mods, r.modules)
	r.mu.Unlock()

	for _, m := range mods {
		if err := m.invoke(hc); err != nil {
			// Log the failure but keep the server alive.
			fmt.Fprintf(os.Stderr, "wasmhook %s: %v\n", m.name, err)
		}
	}
}

// invoke calls wisp_handle on one module and merges the returned JSON.
func (m *Module) invoke(hc *HookContext) error {
	in, err := json.Marshal(hc)
	if err != nil {
		return err
	}
	// Allocate input in module memory and write it.
	ptr, err := m.callAlloc(len(in))
	if err != nil {
		return fmt.Errorf("alloc: %w", err)
	}
	if !m.mod.Memory().Write(uint32(ptr), in) {
		return fmt.Errorf("write input memory")
	}

	resPtr, err := m.callHandle(uint32(ptr), uint32(len(in)))
	if err != nil {
		return fmt.Errorf("handle: %w", err)
	}
	resLen, err := m.callLen()
	if err != nil {
		return fmt.Errorf("handle_len: %w", err)
	}
	out, ok := m.mod.Memory().Read(uint32(resPtr), uint32(resLen))
	if !ok {
		return fmt.Errorf("read output memory")
	}

	var res HookContext
	if err := json.Unmarshal(out, &res); err != nil {
		return fmt.Errorf("decode output: %w", err)
	}
	// Merge back into the caller's context.
	if res.Input != nil {
		hc.Input = res.Input
	}
	if res.Output != nil {
		hc.Output = res.Output
	}
	hc.Abort = res.Abort
	return nil
}

func (m *Module) callAlloc(size int) (uint32, error) {
	res, err := m.alloc.Call(m.ctx, uint64(size))
	if err != nil {
		return 0, err
	}
	return uint32(res[0]), nil
}

func (m *Module) callHandle(ptr, length uint32) (uint32, error) {
	res, err := m.handle.Call(m.ctx, uint64(ptr), uint64(length))
	if err != nil {
		return 0, err
	}
	return uint32(res[0]), nil
}

func (m *Module) callLen() (uint32, error) {
	res, err := m.hlen.Call(m.ctx)
	if err != nil {
		return 0, err
	}
	return uint32(res[0]), nil
}

// Close closes all modules.
func (r *Runtime) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, m := range r.modules {
		_ = m.mod.Close(r.ctx)
	}
	r.modules = nil
}
