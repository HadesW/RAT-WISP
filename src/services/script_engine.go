package services

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/user/wisp/internal/server"
	"github.com/user/wisp/services/wasmhook"
	lua "github.com/yuin/gopher-lua"
)

// ScriptEngine is the gopher-lua based operator scripting environment
// (Aggressor / AxScript analogue). Scripts run in an isolated VM but can
// register event hooks, lifecycle hooks and command aliases that survive
// across executions.
type ScriptEngine struct {
	svc     *ServerService
	mu      sync.Mutex
	hooks   map[string][]*lua.LFunction // event name → callbacks (persistent)
	aliases map[string]commandAlias      // alias name → target command (persistent)
	notes   []string                    // operator notes collected by scripts

	// lifecycleHooks maps "phase:event" → Lua callbacks registered via
	// wisp.hook(phase, event, fn). These implement the unified pre/post hook
	// framework (server.HookRouter).
	lifecycleHooks map[string][]*lua.LFunction

	// wasm is the optional Rust/WASM hook runtime loaded from <exeDir>/hooks/.
	wasm *wasmhook.Runtime

	// hookLogPath is an optional local file that hook print() output is
	// appended to, so operators can inspect traffic without the frontend.
	hookLogPath string
}

// commandAlias rewrites an operator-typed command into a real agent command.
// ArgsTemplate may contain $1..$N placeholders substituted from the typed
// argument string (Aggressor-style pre-hook / alias).
type commandAlias struct {
	Command string `json:"command"`
	Args    string `json:"args"`
	Help    string `json:"help,omitempty"`
}

// Name implements server.EventBackend.
func (se *ScriptEngine) Name() string { return "lua" }

// NewScriptEngine creates the engine and wires it to the server event stream.
func NewScriptEngine(svc *ServerService) *ScriptEngine {
	se := &ScriptEngine{
		svc:            svc,
		hooks:          map[string][]*lua.LFunction{},
		aliases:        map[string]commandAlias{},
		lifecycleHooks: map[string][]*lua.LFunction{},
	}
	if svc == nil {
		return se
	}
	// Load Rust/WASM hook modules from <exeDir>/hooks/ (best-effort; a missing
	// dir or a broken module must not stop the server).
	se.wasm = wasmhook.NewRuntime()
	if err := se.wasm.LoadDir(filepath.Join(exeDir(), "hooks")); err != nil {
		fmt.Fprintf(os.Stderr, "wasmhook: %v\n", err)
	}
	// Register this engine on the process-wide EventBus so server/HTTP hook
	// points (listener:checkin, session:output, task:dispatch, ...) reach
	// Lua + WASM. The bus is already installed as the hookRouter, so
	// server.TriggerHook fans out through it.
	server.GetEventBus().Register(se, 10)
	svc.AddEventListener("session:output", func(name string, data ...any) {
		if len(data) == 0 {
			return
		}
		se.dispatchHook("output", data[0])
	})
	svc.AddEventListener("session:new", func(name string, data ...any) {
		if len(data) == 0 {
			return
		}
		se.dispatchHook("new_agent", data[0])
	})
	svc.AddEventListener("session:dead", func(name string, data ...any) {
		if len(data) == 0 {
			return
		}
		se.dispatchHook("agent_dead", data[0])
	})
	return se
}

// RunScript executes Lua source in a fresh VM with the wisp API table.
func (se *ScriptEngine) RunScript(source string) (string, error) {
	L := lua.NewState(lua.Options{SkipOpenLibs: true})
	defer L.Close()

	var buf strings.Builder

	for _, pair := range []struct{ n string; f lua.LGFunction }{
		{lua.LoadLibName, lua.OpenPackage},
		{lua.BaseLibName, lua.OpenBase},
		{lua.TabLibName, lua.OpenTable},
		{lua.StringLibName, lua.OpenString},
		{lua.MathLibName, lua.OpenMath},
		{lua.OsLibName, se.openOsLimited},
	} {
		L.Push(L.NewFunction(pair.f))
		L.Push(lua.LString(pair.n))
		L.Call(1, 0)
	}
	// Override the base lib's print (which writes to stdout) to capture output.
	L.SetGlobal("print", L.NewFunction(func(L *lua.LState) int {
		top := L.GetTop()
		for i := 1; i <= top; i++ {
			buf.WriteString(L.ToStringMeta(L.Get(i)).String())
			if i != top {
				buf.WriteByte('\t')
			}
		}
		buf.WriteByte('\n')
		return 0
	}))
	se.registerAPI(L)

	if err := L.DoString(source); err != nil {
		return buf.String(), err
	}
	return buf.String(), nil
}

// openOsLimited exposes os.getenv only (no exec/io from scripts).
func (se *ScriptEngine) openOsLimited(L *lua.LState) int {
	mod := L.RegisterModule("os", map[string]lua.LGFunction{
		"getenv": func(L *lua.LState) int {
			L.Push(lua.LString(se.lookupEnv(L.CheckString(1))))
			return 1
		},
		"exit": func(L *lua.LState) int {
			L.RaiseError("os.exit disabled")
			return 0
		},
	})
	L.Push(mod)
	return 1
}

func (se *ScriptEngine) lookupEnv(k string) string {
	return se.envGet(k)
}

// envGet is overridable in tests; production reads the process env.
func (se *ScriptEngine) envGet(k string) string {
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, k+"=") {
			return strings.TrimPrefix(e, k+"=")
		}
	}
	return ""
}

// registerAPI installs the wisp.* table into the VM.
func (se *ScriptEngine) registerAPI(L *lua.LState) {
	api := L.NewTable()
	L.SetFuncs(api, map[string]lua.LGFunction{
		"agents":      se.luaAgents,
		"sessions":    se.luaAgents,
		"task":        se.luaTask,
		"get_task":    se.luaGetTask,
		"on_output":   se.luaOnOutput,
		"on_agent":    se.luaOnAgent,
		"on_dead":     se.luaOnDead,
		"note":        se.luaNote,
		"json":        se.luaJSON,
		"alias":       se.luaAlias,
		"alias_clear": se.luaAliasClear,
		"aliases":     se.luaAliases,
		"hook":        se.luaHook,
		"hooks":       se.luaHooks,
		"dump":        se.luaDump,
	})
	L.SetGlobal("wisp", api)
}

// LoadWasmModule loads an additional WASM hook module (used by tests and for
// runtime module injection).
func (se *ScriptEngine) LoadWasmModule(path string) error {
	if se.wasm == nil {
		se.wasm = wasmhook.NewRuntime()
	}
	return se.wasm.LoadFile(path)
}

// SetHookLogPath configures a local file that hook print() output is appended
// to. Empty disables the file log.
func (se *ScriptEngine) SetHookLogPath(path string) {
	se.mu.Lock()
	se.hookLogPath = path
	se.mu.Unlock()
}

// appendHookLog writes hook output to the configured local log file (if any).
// Safe for concurrent hook dispatch; failures are ignored (logging must never
// break the C2).
func (se *ScriptEngine) appendHookLog(ctx *server.HookContext, text string) {
	se.mu.Lock()
	path := se.hookLogPath
	se.mu.Unlock()
	if path == "" || text == "" {
		return
	}
	line := fmt.Sprintf("[%s] [%s:%s] %s\n",
		time.Now().Format(time.RFC3339), ctx.Event, ctx.Phase, strings.TrimRight(text, "\n"))
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	_, _ = f.WriteString(line)
	_ = f.Close()
}

// luaHooks lists registered lifecycle hooks as {phase:event} strings.
func (se *ScriptEngine) luaHooks(L *lua.LState) int {	se.mu.Lock()
	keys := make([]string, 0, len(se.lifecycleHooks))
	for k := range se.lifecycleHooks {
		keys = append(keys, k)
	}
	se.mu.Unlock()
	sort.Strings(keys)
	t := L.NewTable()
	for i, k := range keys {
		t.RawSetInt(i+1, lua.LString(k))
	}
	L.Push(t)
	return 1
}

// luaDump pretty-prints a Lua value as JSON (for inspecting ctx.input/output
// traffic payloads in hook scripts).
func (se *ScriptEngine) luaDump(L *lua.LState) int {
	val := L.CheckAny(1)
	L.Push(lua.LString(luaToJSON(val)))
	return 1
}

// luaHook registers a lifecycle hook: wisp.hook("pre"|"post", event, fn).
// The callback receives a table `ctx` with .input, .output, .abort fields that
// it may mutate; changes are written back to the Go hook context.
func (se *ScriptEngine) luaHook(L *lua.LState) int {
	phase := L.CheckString(1)
	event := L.CheckString(2)
	fn := L.CheckFunction(3)
	if phase != string(server.HookPre) && phase != string(server.HookPost) {
		L.RaiseError("hook: phase must be 'pre' or 'post'")
		return 0
	}
	key := phase + ":" + event
	se.mu.Lock()
	se.lifecycleHooks[key] = append(se.lifecycleHooks[key], fn)
	se.mu.Unlock()
	L.Push(lua.LTrue)
	return 1
}

// Hook implements server.HookRouter: dispatched by the server layer for every
// hook point. Runs each registered Lua callback in a fresh VM with the ctx
// available as a mutable table, then writes changes back.
func (se *ScriptEngine) Hook(ctx *server.HookContext) {
	if ctx == nil {
		return
	}
	// Rust/WASM hook modules run first (if any are loaded); they may mutate
	// input/output/abort before the Lua callbacks see the context.
	if se.wasm != nil {
		wh := &wasmhook.HookContext{
			Event:  ctx.Event,
			Phase:  string(ctx.Phase),
			Input:  ctx.Input,
			Output: ctx.Output,
			Abort:  ctx.Abort,
		}
		se.wasm.Hook(wh)
		// The wasm layer may have replaced input/output maps and flipped abort.
		ctx.Input = wh.Input
		ctx.Output = wh.Output
		ctx.Abort = wh.Abort
	}
	key := string(ctx.Phase) + ":" + ctx.Event
	se.mu.Lock()
	fns := make([]*lua.LFunction, len(se.lifecycleHooks[key]))
	copy(fns, se.lifecycleHooks[key])
	se.mu.Unlock()
	if len(fns) == 0 {
		return
	}

	L := lua.NewState(lua.Options{SkipOpenLibs: true})
	defer L.Close()
	// Minimal environment so hooks can do string/table work.
	for _, pair := range []struct{ n string; f lua.LGFunction }{
		{lua.BaseLibName, lua.OpenBase},
		{lua.TabLibName, lua.OpenTable},
		{lua.StringLibName, lua.OpenString},
	} {
		L.Push(L.NewFunction(pair.f))
		L.Push(lua.LString(pair.n))
		L.Call(1, 0)
	}
	// Capture print() output so hook authors can inspect the traffic flowing
	// through each point. The captured text is emitted as a "hook:log" event
	// (frontend console + script engine hooks).
	var hookBuf strings.Builder
	L.SetGlobal("print", L.NewFunction(func(L *lua.LState) int {
		top := L.GetTop()
		for i := 1; i <= top; i++ {
			hookBuf.WriteString(L.ToStringMeta(L.Get(i)).String())
			if i != top {
				hookBuf.WriteByte('\t')
			}
		}
		hookBuf.WriteByte('\n')
		return 0
	}))
	se.registerAPI(L)

	// Build the ctx table: {event, phase, input={}, output={}, abort=false}
	ctxTbl := L.NewTable()
	ctxTbl.RawSetString("event", lua.LString(ctx.Event))
	ctxTbl.RawSetString("phase", lua.LString(string(ctx.Phase)))
	ctxTbl.RawSetString("abort", lua.LBool(ctx.Abort))
	inTbl := anyToLua(L, ctx.Input)
	if inTbl == nil {
		inTbl = L.NewTable()
	}
	ctxTbl.RawSetString("input", inTbl)
	outTbl := anyToLua(L, ctx.Output)
	if outTbl == nil {
		outTbl = L.NewTable()
	}
	ctxTbl.RawSetString("output", outTbl)
	L.SetGlobal("ctx", ctxTbl)

	for _, fn := range fns {
		// Point the callback at this VM's environment so its global lookups
		// (print, string.*, wisp.*) resolve here — not in the discarded VM that
		// registered it. This is what makes hook print() output land in
		// hookBuf.
		fn.Env = L.Env
		L.Push(fn)
		L.Push(ctxTbl)
		if err := L.PCall(1, 0, nil); err != nil {
			// Log hook errors so a buggy hook is visible instead of silent.
			hookBuf.WriteString("hook error: " + err.Error() + "\n")
		}
	}

	// Surface any print() output from the hooks to the operator (frontend +
	// script event hooks) so traffic can be inspected while writing hooks.
	if hookBuf.Len() > 0 {
		if se.svc != nil {
			se.svc.EmitEvent("hook:log", map[string]any{
				"event": ctx.Event,
				"phase": string(ctx.Phase),
				"text":  hookBuf.String(),
			})
			// Persist as a console log for the affected session (if known) so
			// the operator can review hook traffic in the session console.
			if se.svc.GetDB() != nil {
				if sid, ok := ctx.Input["session_id"].(string); ok && sid != "" {
					_ = se.svc.GetDB().InsertConsoleLog(sid, "hook", hookBuf.String())
				}
			}
		}
		// Headless / CLI fallback: no frontend to deliver to, so log it so the
		// operator can still see hook traffic on the console.
		log.Printf("[hook:%s:%s] %s", ctx.Event, ctx.Phase, strings.TrimRight(hookBuf.String(), "\n"))
		// Local file log: append hook output to the configured file so traffic
		// can be inspected offline / with tail -f.
		se.appendHookLog(ctx, hookBuf.String())
	}

	// Write changes back: input/output (recursively converting nested tables)
	// and abort.
	readBack := func(name string, dst map[string]any) {
		if dst == nil {
			return
		}
		tbl := L.GetField(ctxTbl, name)
		if ltab, ok := tbl.(*lua.LTable); ok {
			ltab.ForEach(func(k, v lua.LValue) {
				ks := k.String()
				if ks == "" {
					return
				}
				if val := luaTableToAny(v); val != nil {
					dst[ks] = val
				}
			})
		}
	}
	readBack("input", ctx.Input)
	readBack("output", ctx.Output)
	if ab, ok := L.GetField(ctxTbl, "abort").(lua.LBool); ok {
		ctx.Abort = bool(ab)
	}
}

// luaTableToAny converts a Lua value into a Go value (recursively for tables).
func luaTableToAny(v lua.LValue) any {
	switch tv := v.(type) {
	case lua.LString:
		return string(tv)
	case lua.LNumber:
		return float64(tv)
	case lua.LBool:
		return bool(tv)
	case *lua.LTable:
		m := map[string]any{}
		tv.ForEach(func(k, vv lua.LValue) {
			m[k.String()] = luaTableToAny(vv)
		})
		return m
	default:
		return nil
	}
}

// luaAlias registers (or overwrites) a command alias. The alias rewrites an
// operator-typed command into a real agent command. `args` may reference
// $1..$N (positional) and $* (all) placeholders from the typed argument line,
// and $0 for the alias name. ArgsTemplate may also be nil to pass through.
func (se *ScriptEngine) luaAlias(L *lua.LState) int {
	name := L.CheckString(1)
	command := L.CheckString(2)
	args := L.OptString(3, "")
	help := L.OptString(4, "")
	if name == "" || command == "" {
		L.RaiseError("alias: name and command required")
		return 0
	}
	se.mu.Lock()
	se.aliases[name] = commandAlias{Command: command, Args: args, Help: help}
	se.mu.Unlock()
	L.Push(lua.LTrue)
	return 1
}

// luaAliasClear removes a registered alias.
func (se *ScriptEngine) luaAliasClear(L *lua.LState) int {
	name := L.CheckString(1)
	se.mu.Lock()
	delete(se.aliases, name)
	se.mu.Unlock()
	L.Push(lua.LTrue)
	return 1
}

// luaAliases returns a table of registered aliases (name → {command,args}).
func (se *ScriptEngine) luaAliases(L *lua.LState) int {
	t := L.NewTable()
	se.mu.Lock()
	names := make([]string, 0, len(se.aliases))
	for n := range se.aliases {
		names = append(names, n)
	}
	se.mu.Unlock()
	sort.Strings(names)
	for _, n := range names {
		se.mu.Lock()
		a := se.aliases[n]
		se.mu.Unlock()
		row := L.NewTable()
		row.RawSetString("command", lua.LString(a.Command))
		row.RawSetString("args", lua.LString(a.Args))
		row.RawSetString("help", lua.LString(a.Help))
		t.RawSetString(n, row)
	}
	L.Push(t)
	return 1
}

// ResolveCommand applies alias rewriting to a typed command. Returns the real
// command + args and whether an alias matched. If no alias matches, the input
// is returned unchanged.
func (se *ScriptEngine) ResolveCommand(command, args string) (string, string, bool) {
	if command == "" {
		return command, args, false
	}
	se.mu.Lock()
	a, ok := se.aliases[command]
	se.mu.Unlock()
	if !ok {
		return command, args, false
	}
	return a.Command, expandAliasArgs(a.Args, command, args), true
}

// expandAliasArgs substitutes $0 (alias name), $1..$N (positional) and $*
// (all remaining) into the alias args template.
func expandAliasArgs(template, aliasName, typed string) string {
	if template == "" {
		return typed
	}
	parts := strings.Fields(typed)
	out := template
	out = strings.ReplaceAll(out, "$*", typed)
	out = strings.ReplaceAll(out, "$0", aliasName)
	for i := len(parts); i >= 1; i-- {
		ph := "$" + strconv.Itoa(i)
		if strings.Contains(out, ph) {
			out = strings.ReplaceAll(out, ph, strings.Join(parts[:i], " "))
		}
	}
	return out
}

// luaAgents returns a table of agent records.
func (se *ScriptEngine) luaAgents(L *lua.LState) int {
	sessions, err := se.svc.GetSessionService().List()
	t := L.NewTable()
	if err != nil {
		L.Push(t)
		return 1
	}
	for i, s := range sessions {
		row := L.NewTable()
		row.RawSetString("id", lua.LString(s.ID))
		row.RawSetString("hostname", lua.LString(s.Hostname))
		row.RawSetString("username", lua.LString(s.Username))
		row.RawSetString("ip", lua.LString(s.InternalIP))
		row.RawSetString("os", lua.LString(s.OS))
		row.RawSetString("status", lua.LString(s.Status))
		row.RawSetString("seq", lua.LNumber(s.Seq))
		t.RawSetInt(i+1, row)
	}
	L.Push(t)
	return 1
}

// luaTask sends a command to an agent and returns the task id.
func (se *ScriptEngine) luaTask(L *lua.LState) int {
	agent := L.CheckString(1)
	command := L.CheckString(2)
	args := L.OptString(3, "")
	if err := se.svc.GetSessionService().SendCommand(agent, command, args); err != nil {
		L.RaiseError("task failed: %v", err)
		return 0
	}
	L.Push(lua.LString("queued"))
	return 1
}

// luaGetTask fetches a task's current status/result.
func (se *ScriptEngine) luaGetTask(L *lua.LState) int {
	taskID := L.CheckString(1)
	task, err := se.svc.GetSessionService().GetTask(taskID)
	t := L.NewTable()
	if err != nil {
		L.Push(t)
		return 1
	}
	t.RawSetString("id", lua.LString(task.ID))
	t.RawSetString("status", lua.LString(task.Status))
	t.RawSetString("result", lua.LString(task.Result))
	t.RawSetString("command_id", lua.LNumber(task.CommandID))
	L.Push(t)
	return 1
}

// luaOnOutput registers a hook invoked with {session_id, task_id, result, status}.
func (se *ScriptEngine) luaOnOutput(L *lua.LState) int {
	return se.registerHook(L, "output")
}

// luaOnAgent registers a hook invoked with the new session record.
func (se *ScriptEngine) luaOnAgent(L *lua.LState) int {
	return se.registerHook(L, "new_agent")
}

// luaOnDead registers a hook invoked with the dead session id.
func (se *ScriptEngine) luaOnDead(L *lua.LState) int {
	return se.registerHook(L, "agent_dead")
}

// registerHook stores the Lua callback for a hook name in the persistent table.
func (se *ScriptEngine) registerHook(L *lua.LState, name string) int {
	fn := L.CheckFunction(1)
	se.mu.Lock()
	se.hooks[name] = append(se.hooks[name], fn)
	se.mu.Unlock()
	L.Push(lua.LTrue)
	return 1
}

// luaNote stores an operator note (returns it for chaining).
func (se *ScriptEngine) luaNote(L *lua.LState) int {
	msg := L.CheckString(1)
	se.notes = append(se.notes, msg)
	L.Push(lua.LString("ok"))
	return 1
}

// luaJSON marshals a Lua value to JSON text.
func (se *ScriptEngine) luaJSON(L *lua.LState) int {
	val := L.CheckAny(1)
	L.Push(lua.LString(luaToJSON(val)))
	return 1
}

// dispatchHook invokes all registered callbacks for a hook name. Runs each
// callback in its own fresh VM with the payload available as `data`.
func (se *ScriptEngine) dispatchHook(name string, payload any) {
	se.mu.Lock()
	fns := make([]*lua.LFunction, len(se.hooks[name]))
	copy(fns, se.hooks[name])
	se.mu.Unlock()
	for _, fn := range fns {
		L := lua.NewState(lua.Options{SkipOpenLibs: true})
		se.registerAPI(L)
		L.SetGlobal("data", anyToLua(L, payload))
		L.Push(fn)
		L.PCall(0, 0, nil)
		L.Close()
	}
}

// notes accumulates operator notes across scripts.

// envSnapshot returns the process environment.
func envSnapshot() []string { return os.Environ() }
