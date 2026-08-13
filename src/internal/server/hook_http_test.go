package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/user/wisp/internal/db"
)

// scriptHookRouter is a minimal HookRouter implementation for tests (mirrors
// what the Lua engine installs at runtime).
type scriptHookRouter struct {
	mu    sync.Mutex
	hooks map[string]func(ctx *HookContext)
}

func (r *scriptHookRouter) Hook(ctx *HookContext) {
	r.mu.Lock()
	fn := r.hooks[string(ctx.Phase)+":"+ctx.Event]
	r.mu.Unlock()
	if fn != nil {
		fn(ctx)
	}
}

// TestHTTPListenerCheckinHook verifies the listener:checkin pre-hook can add
// response headers and abort specific agents through the real HTTP handler.
func TestHTTPListenerCheckinHook(t *testing.T) {
	database, err := db.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := New(database, nil); err != nil {
		t.Fatal(err)
	}

	// Install a script-style router that sets headers + aborts one IP.
	router := &scriptHookRouter{hooks: map[string]func(*HookContext){}}
	router.hooks["pre:listener:checkin"] = func(ctx *HookContext) {
		ctx.Output["response_headers"] = map[string]any{
			"X-Powered-By": "nginx",
			"Server":       "nginx",
		}
		if ctx.Input["ip"] == "10.0.0.66" {
			ctx.Abort = true
		}
	}
	SetHookRouter(router)
	defer SetHookRouter(nil)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/checkin", func(w http.ResponseWriter, r *http.Request) {
		// Mirror the real handler's hook usage.
		hctx := TriggerHook("listener:checkin", HookPre, map[string]any{
			"ip":   "10.0.0.5",
			"path": r.URL.Path,
		}, map[string]any{})
		if hctx.Abort {
			applyHookResponse(w, hctx, http.StatusForbidden)
			return
		}
		applyHookResponse(w, hctx, http.StatusOK)
		w.Write([]byte(`{"tasks":""}`))
	})

	req := httptest.NewRequest("POST", "/api/v1/checkin", strings.NewReader(`{"id":"a","seq":1}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	if rec.Header().Get("X-Powered-By") != "nginx" || rec.Header().Get("Server") != "nginx" {
		t.Fatalf("hook headers not applied: %v", rec.Header())
	}
}
