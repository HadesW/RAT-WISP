package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/user/wisp/internal/server"
)

// TestLuaHookDispatch verifies wisp.hook("pre", event, fn) registers a
// lifecycle hook that mutates ctx.input and ctx.abort, and that those changes
// round-trip back into the Go hook context.
func TestLuaHookDispatch(t *testing.T) {
	database, err := openTestDB(t)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewServerService()
	svc.db = database
	ss := NewScriptService(svc)

	// Register a pre-hook that rewrites the checkin response headers and aborts
	// agents from a specific IP.
	src := `
wisp.hook("pre", "listener:checkin", function(ctx)
  ctx.input["user_agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
  ctx.output["response_headers"] = { ["X-Powered-By"] = "nginx", ["Server"] = "nginx" }
  if ctx.input["ip"] == "10.0.0.66" then
    ctx.abort = true
  end
end)
`
	if _, err := ss.RunScript(src); err != nil {
		t.Fatalf("register hook: %v", err)
	}

	// Normal checkin: header rewritten, not aborted.
	in := map[string]any{"ip": "10.0.0.5", "user_agent": "old"}
	out := map[string]any{}
	ctx := server.TriggerHook("listener:checkin", server.HookPre, in, out)
	if ctx.Abort {
		t.Fatal("normal checkin should not abort")
	}
	if in["user_agent"] != "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" {
		t.Fatalf("user_agent not rewritten: %v", in["user_agent"])
	}
	hdrs, ok := out["response_headers"].(map[string]any)
	if !ok || hdrs["X-Powered-By"] != "nginx" {
		t.Fatalf("response_headers not set: %v", out)
	}

	// Specific IP aborts.
	in2 := map[string]any{"ip": "10.0.0.66"}
	ctx2 := server.TriggerHook("listener:checkin", server.HookPre, in2, map[string]any{})
	if !ctx2.Abort {
		t.Fatal("10.0.0.66 should be aborted")
	}
}

// TestLuaTaskDispatchHook verifies the task:dispatch hook rewrites commands
// (the unified replacement for the legacy alias resolver).
func TestLuaTaskDispatchHook(t *testing.T) {
	database, err := openTestDB(t)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewServerService()
	svc.db = database
	_ = NewScriptService(svc)

	src := `
wisp.hook("pre", "task:dispatch", function(ctx)
  if ctx.input["command"] == "shell" then
    ctx.input["command"] = "ps"
    ctx.input["args"] = '{"cmd":"cmd.exe /c ' .. ctx.input["args"] .. '"}'
  end
end)
`
	_ = NewScriptService(svc)
	if _, err := NewScriptService(svc).RunScript(src); err != nil {
		t.Fatalf("register: %v", err)
	}

	in := map[string]any{"session_id": "s1", "command": "shell", "args": "whoami"}
	ctx := server.TriggerHook("task:dispatch", server.HookPre, in, nil)
	if ctx.Abort {
		t.Fatal("should not abort")
	}
	if in["command"] != "ps" {
		t.Fatalf("command not rewritten: %v", in["command"])
	}
	args, ok := in["args"].(string)
	if !ok || args != `{"cmd":"cmd.exe /c whoami"}` {
		t.Fatalf("args not rewritten: %v", in["args"])
	}
}

// TestLuaHookMultipleVMs verifies each hook invocation runs in an isolated VM
// and state does not leak between invocations.
func TestLuaHookMultipleVMs(t *testing.T) {
	database, err := openTestDB(t)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewServerService()
	svc.db = database
	_ = NewScriptService(svc)

	src := `wisp.hook("pre", "session:output", function(ctx)
  ctx.input["result"] = "redacted:" .. ctx.input["result"]
end)`
	if _, err := NewScriptService(svc).RunScript(src); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		in := map[string]any{"result": "line" + string(rune('0'+i))}
		server.TriggerHook("session:output", server.HookPre, in, nil)
		if in["result"] != "redacted:line"+string(rune('0'+i)) {
			t.Fatalf("iteration %d: %v", i, in["result"])
		}
	}
}

// TestExampleHooksLoads verifies the shipped example_hooks.lua parses and
// registers all five hook points without error.
func TestExampleHooksLoads(t *testing.T) {
	database, err := openTestDB(t)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewServerService()
	svc.db = database
	_ = NewScriptService(svc)

	src, err := os.ReadFile(filepath.Join("..", "bin", "scripts", "example_hooks.lua"))
	if err != nil {
		t.Skipf("example script not present: %v", err)
	}
	if _, err := NewScriptService(svc).RunScript(string(src)); err != nil {
		t.Fatalf("load example_hooks.lua: %v", err)
	}
}

// TestHookPrintCapture verifies a hook's print() output is captured and
// emitted as a hook:log event so operators can inspect traffic.
func TestHookPrintCapture(t *testing.T) {
	database, err := openTestDB(t)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewServerService()
	svc.db = database
	ss := NewScriptService(svc)

	var got string
	svc.AddEventListener("hook:log", func(name string, data ...any) {
		if len(data) > 0 {
			if m, ok := data[0].(map[string]any); ok {
				if s, ok := m["text"].(string); ok {
					got = s
				}
			}
		}
	})

	src := `wisp.hook("pre", "listener:checkin", function(ctx)
  print("ip=" .. ctx.input["ip"], "path=" .. ctx.input["path"])
end)`
	if _, err := ss.RunScript(src); err != nil {
		t.Fatal(err)
	}

	server.TriggerHook("listener:checkin", server.HookPre,
		map[string]any{"ip": "10.0.0.5", "path": "/api/v1/checkin"},
		map[string]any{})

	if got == "" || !containsStr(got, "10.0.0.5") || !containsStr(got, "/api/v1/checkin") {
		t.Fatalf("hook print not captured: %q", got)
	}
}

// TestHookLogFile verifies hook print() output is appended to a configured
// local file (headless / offline inspection).
func TestHookLogFile(t *testing.T) {
	database, err := openTestDB(t)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewServerService()
	svc.db = database
	ss := NewScriptService(svc)

	logPath := filepath.Join(t.TempDir(), "hooks.log")
	ss.SetHookLogPath(logPath)

	src := `wisp.hook("pre", "listener:checkin", function(ctx)
  print("ip=" .. ctx.input["ip"], "path=" .. ctx.input["path"])
end)`
	if _, err := ss.RunScript(src); err != nil {
		t.Fatal(err)
	}

	server.TriggerHook("listener:checkin", server.HookPre,
		map[string]any{"ip": "10.0.0.5", "path": "/api/v1/checkin"},
		map[string]any{})

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read hook log: %v", err)
	}
	s := string(data)
	if !strings.Contains(s, "10.0.0.5") || !strings.Contains(s, "/api/v1/checkin") {
		t.Fatalf("hook log missing traffic: %q", s)
	}
	t.Logf("hook log wrote: %s", strings.TrimSpace(s))
}

// TestStageHook verifies the listener:stage hook fires on staged downloads.
func TestStageHook(t *testing.T) {
	database, err := openTestDB(t)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewServerService()
	svc.db = database
	ss := NewScriptService(svc)

	var got []string
	svc.AddEventListener("hook:log", func(name string, data ...any) {
		if m, ok := data[0].(map[string]any); ok {
			if txt, ok := m["text"].(string); ok {
				got = append(got, txt)
			}
		}
	})

	src := `wisp.hook("pre", "listener:stage", function(ctx)
  print("stage", ctx.input["token"], "raw=" .. tostring(ctx.input["raw"]))
end)`
	if _, err := ss.RunScript(src); err != nil {
		t.Fatal(err)
	}

	server.TriggerHook("listener:stage", server.HookPre, map[string]any{
		"ip": "1.2.3.4", "token": "tok999", "raw": true,
	}, map[string]any{})

	if len(got) != 1 || !strings.Contains(got[0], "tok999") {
		t.Fatalf("stage hook not captured: %v", got)
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

// TestWasmHookDispatch verifies a WASM hook module loaded from testdata runs
// through the unified dispatch and its abort flag flows into the context.
func TestWasmHookDispatch(t *testing.T) {
	database, err := openTestDB(t)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewServerService()
	svc.db = database
	ss := NewScriptService(svc)
	if err := ss.LoadWasmModule(filepath.Join("wasmhook", "testdata", "hookmod.wasm")); err != nil {
		t.Fatalf("LoadWasmModule: %v", err)
	}
	// Restore a clean router when done so the aggressive test module does not
	// leak into other tests (its scan aborts any event whose input has a '1').
	defer server.SetHookRouter(NewScriptEngine(nil))

	// IP containing '1' → WASM module sets abort.
	in := map[string]any{"ip": "192.168.1.9"}
	ctx := server.TriggerHook("listener:checkin", server.HookPre, in, map[string]any{})
	if !ctx.Abort {
		t.Fatal("WASM hook should have aborted for IP containing '1'")
	}

	// IP without '1' → no abort.
	in2 := map[string]any{"ip": "9.9.9.9"}
	ctx2 := server.TriggerHook("listener:checkin", server.HookPre, in2, map[string]any{})
	if ctx2.Abort {
		t.Fatal("WASM hook should not abort for 9.9.9.9")
	}
}

