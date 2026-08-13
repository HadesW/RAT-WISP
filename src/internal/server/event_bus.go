// EventBus — the unified server event dispatch layer (M5).
//
// Replaces the single-router model (hooks.go's hookRouterRef) with a bus that
// can hold multiple backends (Go plugins, Lua scripts, WASM modules). Each
// backend implements hookRouter; the bus fans a HookContext out to every
// backend in priority order, letting later backends observe/mutate what
// earlier ones produced. Backends register/unregister at runtime.
//
// hooks.go remains source-compatible: TriggerHook still works (it is the bus's
// synchronous "pre/post" path). New capabilities:
//   - multiple simultaneous backends (no single-winner)
//   - priority ordering
//   - async publish (fire-and-forget for telemetry-style events)
//   - subscriber lifecycle (Register/Unregister per backend)

package server

import (
	"sync"
)

// EventBackend is a named hook backend (Go plugin, Lua engine, WASM runtime).
type EventBackend interface {
	hookRouter // Hook(ctx)
	// Name identifies the backend (for logs/UI).
	Name() string
}

// BackendEntry holds a registered backend with its dispatch priority.
// Lower priority values run first; later backends see earlier mutations.
type BackendEntry struct {
	Backend  EventBackend
	Priority int
}

// EventBus dispatches hook contexts to all registered backends.
type EventBus struct {
	mu       sync.RWMutex
	backends []BackendEntry
}

// NewEventBus creates an empty bus.
func NewEventBus() *EventBus {
	return &EventBus{}
}

// Register adds a backend. Re-registering the same Name replaces it.
func (b *EventBus) Register(be EventBackend, priority int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, e := range b.backends {
		if e.Backend.Name() == be.Name() {
			b.backends[i] = BackendEntry{Backend: be, Priority: priority}
			b.sortLocked()
			return
		}
	}
	b.backends = append(b.backends, BackendEntry{Backend: be, Priority: priority})
	b.sortLocked()
}

// Unregister removes a backend by name.
func (b *EventBus) Unregister(name string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := b.backends[:0]
	for _, e := range b.backends {
		if e.Backend.Name() != name {
			out = append(out, e)
		}
	}
	b.backends = out
}

// Backends returns a snapshot of registered backend names (for UI/status).
func (b *EventBus) Backends() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	names := make([]string, 0, len(b.backends))
	for _, e := range b.backends {
		names = append(names, e.Backend.Name())
	}
	return names
}

// Hook fans a context out to every backend, in priority order. Each backend
// may mutate ctx (Input/Output/Abort); later backends see those mutations.
func (b *EventBus) Hook(ctx *HookContext) {
	if ctx == nil {
		return
	}
	b.mu.RLock()
	entries := make([]BackendEntry, len(b.backends))
	copy(entries, b.backends)
	b.mu.RUnlock()
	for _, e := range entries {
		e.Backend.Hook(ctx)
	}
}

// PublishAsync fires an event on a background goroutine (telemetry / logging
// events that must not block the hot path). The context is snapshotted first.
func (b *EventBus) PublishAsync(ctx *HookContext) {
	if ctx == nil {
		return
	}
	cp := *ctx
	go b.Hook(&cp)
}

func (b *EventBus) sortLocked() {
	// simple insertion sort by Priority
	for i := 1; i < len(b.backends); i++ {
		for j := i; j > 0 && b.backends[j-1].Priority > b.backends[j].Priority; j-- {
			b.backends[j-1], b.backends[j] = b.backends[j], b.backends[j-1]
		}
	}
}

// ---- global default bus (compatible with the old single-router semantics) ----

var (
	defaultBusOnce sync.Once
	defaultBus     *EventBus
)

// GetEventBus returns the process-wide default event bus.
func GetEventBus() *EventBus {
	defaultBusOnce.Do(func() {
		defaultBus = NewEventBus()
	})
	return defaultBus
}

// installBusAsRouter wires the default bus as the hookRouter so TriggerHook
// (hooks.go) fans out through the bus instead of the old single router.
func init() {
	// Deferred: SetHookRouter is called by the services layer at startup; we
	// simply ensure the default bus is the router. Because hooks.go's
	// SetHookRouter takes a hookRouter, we adapt the bus.
	SetHookRouter(&busRouter{bus: GetEventBus()})
}

// busRouter adapts EventBus to the hookRouter interface.
type busRouter struct {
	bus *EventBus
}

func (r *busRouter) Hook(ctx *HookContext) {
	r.bus.Hook(ctx)
}
