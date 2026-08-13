package server

import (
	"sync"
	"testing"
)

// testBackend is a simple backend that records hook calls and can mutate.
type testBackend struct {
	name     string
	priority int
	mu       sync.Mutex
	calls    []string
	abort    bool
	append   string // appended to Output["order"] on each call
}

func (t *testBackend) Name() string { return t.name }

func (t *testBackend) Hook(ctx *HookContext) {
	t.mu.Lock()
	t.calls = append(t.calls, ctx.Event+":"+string(ctx.Phase))
	t.mu.Unlock()
	if t.append != "" {
		ctx.Output["order"] = ctx.Output["order"].(string) + t.append
	}
	if t.abort {
		ctx.Abort = true
	}
}

func newBackend(name, append string, priority int) *testBackend {
	return &testBackend{name: name, append: append, priority: priority}
}

func TestEventBusPriorityOrder(t *testing.T) {
	b := NewEventBus()
	a := newBackend("a", "A", 20)
	bb := newBackend("b", "B", 10) // lower priority runs first
	c := newBackend("c", "C", 30)
	b.Register(a, a.priority)
	b.Register(bb, bb.priority)
	b.Register(c, c.priority)

	ctx := &HookContext{
		Event:  "test:event",
		Phase:  HookPre,
		Input:  map[string]any{},
		Output: map[string]any{"order": ""},
	}
	b.Hook(ctx)

	// b (10) → a (20) → c (30), so order = "BAC"
	if got := ctx.Output["order"]; got != "BAC" {
		t.Fatalf("expected order BAC, got %v", got)
	}
}

func TestEventBusAbort(t *testing.T) {
	b := NewEventBus()
	first := newBackend("first", "1", 10)
	first.abort = true
	second := newBackend("second", "2", 20)
	b.Register(first, 10)
	b.Register(second, 20)

	ctx := &HookContext{Event: "e", Phase: HookPre, Input: map[string]any{}, Output: map[string]any{"order": ""}}
	b.Hook(ctx)
	if !ctx.Abort {
		t.Fatal("expected Abort set")
	}
	// Abort is a semantic veto flag: all backends still run (later ones may
	// observe it), priority order preserved. Output order = "12".
	if got := ctx.Output["order"]; got != "12" {
		t.Fatalf("expected both backends to run in order, got %v", got)
	}
}

func TestEventBusRegisterReplace(t *testing.T) {
	b := NewEventBus()
	b.Register(newBackend("x", "1", 10), 10)
	b.Register(newBackend("x", "2", 10), 10) // replace
	ctx := &HookContext{Event: "e", Phase: HookPost, Input: map[string]any{}, Output: map[string]any{"order": ""}}
	b.Hook(ctx)
	if got := ctx.Output["order"]; got != "2" {
		t.Fatalf("expected replaced backend output, got %v", got)
	}
	if names := b.Backends(); len(names) != 1 || names[0] != "x" {
		t.Fatalf("expected 1 backend x, got %v", names)
	}
}

func TestEventBusUnregister(t *testing.T) {
	b := NewEventBus()
	b.Register(newBackend("keep", "K", 10), 10)
	b.Register(newBackend("drop", "D", 20), 20)
	b.Unregister("drop")
	ctx := &HookContext{Event: "e", Phase: HookPre, Input: map[string]any{}, Output: map[string]any{"order": ""}}
	b.Hook(ctx)
	if got := ctx.Output["order"]; got != "K" {
		t.Fatalf("expected only K, got %v", got)
	}
}
