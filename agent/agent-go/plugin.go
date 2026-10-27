package main

import (
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"

	"wispp/protocol"
)

// Plugin host (plan §5.4): dynamic WASM modules, Ed25519-verified against the
// baked-in plugin_pubkey, executed in a wazero sandbox (64MB memory cap, 5s
// wall clock, crash = capability unload, never the agent process).
// ABI v0: export `exec(a i32, b i32) i32`.

type loadedPlugin struct {
	rt   wazero.Runtime
	mod  api.Module
	caps []string
	abi  int
}

var (
	pluginsMu sync.Mutex
	plugins   = map[string]*loadedPlugin{}
)

func pluginPubkey() (ed25519.PublicKey, error) {
	hexKey := embeddedPluginPubkey()
	if hexKey == "" {
		return nil, errors.New("plugin: no plugin_pubkey in config — dynamic plugins disabled")
	}
	b, err := hex.DecodeString(hexKey)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("plugin: bad plugin_pubkey")
	}
	return b, nil
}

// embeddedPluginPubkey reads the key from the patched config (file or slot).
func embeddedPluginPubkey() string { return agentPluginPubkey }

var agentPluginPubkey string // set from config at startup

func pluginLoad(a *protocol.PluginLoadArgs) (string, error) {
	if a.Kind == "native-dll" || a.StageURL != "" {
		return "", errors.New("native-dll plugins require the Rust agent (windows native host)")
	}
	pub, err := pluginPubkey()
	if err != nil {
		return "", err
	}
	module, err := base64.StdEncoding.DecodeString(a.ModuleB64)
	if err != nil {
		return "", fmt.Errorf("module b64: %w", err)
	}
	sig, err := hex.DecodeString(a.Sig)
	if err != nil {
		sig, err = base64.StdEncoding.DecodeString(a.Sig)
		if err != nil {
			return "", errors.New("sig encoding")
		}
	}
	msg := append(append([]byte(nil), []byte(a.Manifest)...), module...)
	if !ed25519.Verify(pub, msg, sig) {
		// tamper attempt: loud, auditable refusal
		return "", fmt.Errorf("plugin %s: SIGNATURE VERIFY FAILED — refusing to load", a.ID)
	}
	var man protocol.ManifestLite
	_ = json.Unmarshal([]byte(a.Manifest), &man)

	ctx := context.Background()
	rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().
		WithMemoryLimitPages(pluginMemPages(man.ABI)).
		WithCloseOnContextDone(true))
	if man.ABI >= 1 {
		if err := pluginHostModule(ctx, rt, a.ID, man.Capabilities); err != nil {
			_ = rt.Close(ctx)
			return "", err
		}
	}
	mod, err := rt.Instantiate(ctx, module)
	if err != nil {
		_ = rt.Close(ctx)
		return "", fmt.Errorf("compile/instantiate: %w", err)
	}
	if man.ABI >= 1 {
		if mod.ExportedFunction("alloc") == nil || mod.ExportedFunction("exec_json") == nil {
			_ = rt.Close(ctx)
			return "", errors.New("ABI v1 plugin must export alloc(i32)->i32 and exec_json(i32,i32)->i64")
		}
	} else if mod.ExportedFunction("exec") == nil {
		_ = rt.Close(ctx)
		return "", errors.New("plugin missing export exec(i32,i32)->i32")
	}
	pluginsMu.Lock()
	if old, ok := plugins[a.ID]; ok {
		_ = old.rt.Close(ctx)
	}
	plugins[a.ID] = &loadedPlugin{rt: rt, mod: mod, caps: man.Capabilities, abi: man.ABI}
	pluginsMu.Unlock()
	b, _ := json.Marshal(map[string]any{"loaded": a.ID, "version": a.Version, "capabilities": man.Capabilities})
	return string(b), nil
}

func pluginExec(a *protocol.PluginExecArgs) (string, error) {
	pluginsMu.Lock()
	p := plugins[a.ID]
	pluginsMu.Unlock()
	if p == nil {
		return "", fmt.Errorf("plugin %s not loaded", a.ID)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	defer func() { // sandbox crash must not kill the agent
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "plugin %s panic: %v\n", a.ID, r)
		}
	}()
	if p.abi >= 1 {
		return pluginExecV1(ctx, p, a)
	}
	res, err := p.mod.ExportedFunction("exec").Call(ctx, uint64(uint32(a.A)), uint64(uint32(a.B)))
	if err != nil {
		pluginsMu.Lock()
		delete(plugins, a.ID) // unload capability on fault
		pluginsMu.Unlock()
		return "", fmt.Errorf("exec: %w", err)
	}
	out := map[string]any{"plugin": a.ID, "entry": a.Entry, "result": int32(res[0])}
	b, _ := json.Marshal(out)
	return string(b), nil
}

func pluginCaps() []string {
	pluginsMu.Lock()
	defer pluginsMu.Unlock()
	var out []string
	for id, p := range plugins {
		for _, c := range p.caps {
			out = append(out, id+":"+c)
		}
	}
	return out
}

// ---- ABI v1: JSON-in/JSON-out over linear memory + host env imports (docs/PLUGIN_SDK.md) ----

func pluginMemPages(abi int) uint32 {
	if abi >= 1 {
		return 64 // 4MB: JSON payloads + base64 screenshots
	}
	return 16
}

func hasCap(caps []string, want string) bool {
	for _, c := range caps {
		if c == want || c == "host.*" {
			return true
		}
	}
	return false
}

// pluginHostModule registers env.* imports bound to one plugin's identity and
// capability set. host_exec is the pivoting point: it runs a built-in command
// ONLY if the signed manifest granted "host.<cmd>".
func pluginHostModule(ctx context.Context, rt wazero.Runtime, id string, caps []string) error {
	mb := rt.NewHostModuleBuilder("env")
	mb.NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, ptr, l uint32) {
		if l > 4096 {
			return
		}
		if b, ok := m.Memory().Read(ptr, l); ok {
			log.Printf("plugin[%s]> %s", id, string(b))
		}
	}).Export("host_log")
	mb.NewFunctionBuilder().WithFunc(func() int64 { return time.Now().Unix() }).Export("host_now")
	mb.NewFunctionBuilder().WithFunc(func(_ context.Context, m api.Module, ptr, l uint32) {
		if l > 4096 {
			return
		}
		b := make([]byte, l)
		if _, err := crand.Read(b); err == nil {
			_ = m.Memory().Write(ptr, b)
		}
	}).Export("host_rand")
	mb.NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, ptr, l uint32) int64 {
		if l == 0 || l > 64*1024 {
			return 0
		}
		req, ok := m.Memory().Read(ptr, l)
		if !ok {
			return 0
		}
		var a struct {
			Cmd     string `json:"cmd"`
			Command string `json:"command"`
			Path    string `json:"path"`
		}
		_ = json.Unmarshal(req, &a)
		out := hostDispatch(&a, caps)
		if out == nil {
			return 0
		}
		dst, err := m.ExportedFunction("alloc").Call(ctx, uint64(len(out)))
		if err != nil || dst[0] == 0 {
			return 0
		}
		if !m.Memory().Write(uint32(dst[0]), out) {
			return 0
		}
		return int64(dst[0])<<32 | int64(uint32(len(out)))
	}).Export("host_exec")
	_, err := mb.Instantiate(ctx)
	return err
}

// hostDispatch executes a gated built-in and returns JSON {ok,output,exit}.
func hostDispatch(a *struct {
	Cmd     string `json:"cmd"`
	Command string `json:"command"`
	Path    string `json:"path"`
}, caps []string) []byte {
	fail := func(msg string) []byte {
		b, _ := json.Marshal(map[string]any{"ok": false, "output": msg, "exit": -1})
		return b
	}
	if !hasCap(caps, "host."+a.Cmd) {
		return fail("capability host." + a.Cmd + " not granted by manifest")
	}
	var r protocol.TaskResult
	switch a.Cmd {
	case "sysinfo":
		b, _ := json.Marshal(sysinfo())
		r = protocol.TaskResult{OK: true, Output: string(b)}
	case "pwd":
		r = cmdPwd()
	case "ls":
		args, _ := json.Marshal(map[string]string{"path": a.Path})
		r = cmdLs(args)
	case "screenshot":
		r = cmdScreenshot()
	case "shell":
		if a.Command == "" {
			return fail("shell: command required")
		}
		out, exit, err := runShell(protocol.ShellArgs{Command: a.Command, TimeoutMS: 10000})
		if err != nil {
			return fail("shell: " + err.Error())
		}
		r = protocol.TaskResult{OK: err == nil, Output: out, Exit: exit}
	default:
		return fail("unknown cmd " + a.Cmd)
	}
	b, _ := json.Marshal(map[string]any{"ok": r.OK, "output": r.Output, "exit": r.Exit})
	return b
}

// pluginExecV1: alloc → write args → exec_json → unpack (ptr<<32|len).
func pluginExecV1(ctx context.Context, p *loadedPlugin, a *protocol.PluginExecArgs) (string, error) {
	args := a.Args
	if len(args) == 0 {
		args = []byte("{}")
	}
	dst, err := p.mod.ExportedFunction("alloc").Call(ctx, uint64(len(args)))
	if err != nil {
		return "", fmt.Errorf("alloc: %w", err)
	}
	if !p.mod.Memory().Write(uint32(dst[0]), args) {
		return "", errors.New("args write out of bounds")
	}
	res, err := p.mod.ExportedFunction("exec_json").Call(ctx, dst[0], uint64(len(args)))
	if err != nil {
		p.unload(a.ID)
		return "", fmt.Errorf("exec_json: %w", err)
	}
	packed := res[0]
	if packed == 0 {
		return `{"ok":true}`, nil
	}
	ptr, l := uint32(packed>>32), uint32(packed&0xffffffff)
	if l == 0 || l > 4*1024*1024 {
		return "", errors.New("exec_json: bad result length")
	}
	out, ok := p.mod.Memory().Read(ptr, l)
	if !ok {
		return "", errors.New("exec_json: result out of bounds")
	}
	b, _ := json.Marshal(map[string]any{"plugin": a.ID, "entry": a.Entry, "result": json.RawMessage(append([]byte(nil), out...))})
	return string(b), nil
}

func (p *loadedPlugin) unload(id string) {
	pluginsMu.Lock()
	delete(plugins, id)
	pluginsMu.Unlock()
}
