package server

import (
	"encoding/json"
	"sync"
)

// HookPhase is the lifecycle phase of a hook point.
type HookPhase string

const (
	// HookPre fires before an action; hooks may rewrite Input or set Abort.
	HookPre HookPhase = "pre"
	// HookPost fires after an action; hooks may observe/rewrite Output.
	HookPost HookPhase = "post"
)

// HookContext is the payload handed to a hook. Input holds mutable pre-action
// data (e.g. the request headers / task command), Output holds the produced
// result for post hooks. Hooks may set Abort to veto the action; the caller
// decides what "abort" means for each point.
type HookContext struct {
	Event string   `json:"event"`
	Phase HookPhase `json:"phase"`
	// Input is free-form pre-action data. Values must be JSON-encodable so the
	// script layer can read/write them through the wisp.hook API.
	Input map[string]any `json:"input"`
	// Output is post-action data (may also be written by pre hooks to seed it).
	Output map[string]any `json:"output"`
	// Abort, when set by a pre hook, vetoes the action (e.g. reject a checkin).
	Abort bool `json:"abort"`
}

// HookFunc is a server-side hook callback.
type HookFunc func(ctx *HookContext)

// hookRouter is the injected implementation that dispatches a hook context to
// registered callbacks (the script engine wires it in via SetHookRouter).
type hookRouter interface {
	// Hook fires a hook; returns the possibly-modified context (or nil if the
	// hook chain vetoed everything).
	Hook(ctx *HookContext)
}

// hookMu guards hookRouterRef.
var (
	hookMu        sync.RWMutex
	hookRouterRef hookRouter
)

// SetHookRouter installs the global hook dispatcher (set by the services layer
// on startup). Safe to call multiple times; the last registration wins.
func SetHookRouter(r hookRouter) {
	hookMu.Lock()
	defer hookMu.Unlock()
	hookRouterRef = r
}

// TriggerHook fires a hook point if a router is installed. Returns the context
// after all hooks ran (callers read Input/Output/Abort). If no router is
// installed the context is returned unchanged (zero cost when scripting is
// unused).
func TriggerHook(event string, phase HookPhase, input, output map[string]any) *HookContext {
	hookMu.RLock()
	r := hookRouterRef
	hookMu.RUnlock()
	ctx := &HookContext{
		Event:  event,
		Phase:  phase,
		Input:  input,
		Output: output,
	}
	if r == nil {
		return ctx
	}
	r.Hook(ctx)
	return ctx
}

// MarshalJSON is a debug helper for logging hook payloads.
func (h *HookContext) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Event  string         `json:"event"`
		Phase  HookPhase      `json:"phase"`
		Input  map[string]any `json:"input"`
		Output map[string]any `json:"output"`
		Abort  bool           `json:"abort"`
	}{h.Event, h.Phase, h.Input, h.Output, h.Abort})
}
