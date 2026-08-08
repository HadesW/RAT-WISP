package server

import (
	"sync"
	"time"
)

// Default limiter parameters: per-IP window of 1000 connections / 10s and a
// global cap of 5000 concurrent connections. Agents use short-lived connections
// (one exchange per dial, random source ports) and may re-register in bursts
// after a server restart, so the window is a flood safety net, not an active
// cap on legitimate agents.
const (
	defaultMaxPerIP  = 1000
	defaultWindow    = 10 * time.Second
	defaultGlobalMax = 5000
)

type ipWindow struct {
	count       int
	windowStart time.Time
}

// rateLimiter enforces per-IP connection frequency and a global concurrency
// cap to protect the server from connection floods and replay abuse.
type rateLimiter struct {
	mu        sync.Mutex
	maxPerIP  int
	window    time.Duration
	globalMax int
	active    int
	hits      map[string]*ipWindow
}

func newRateLimiter(maxPerIP int, window time.Duration, globalMax int) *rateLimiter {
	return &rateLimiter{
		maxPerIP:  maxPerIP,
		window:    window,
		globalMax: globalMax,
		hits:      make(map[string]*ipWindow),
	}
}

// allow checks whether a new connection from ip is permitted.
func (r *rateLimiter) allow(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.active >= r.globalMax {
		return false
	}

	now := time.Now()
	w, ok := r.hits[ip]
	if !ok || now.Sub(w.windowStart) >= r.window {
		r.hits[ip] = &ipWindow{count: 1, windowStart: now}
		r.active++
		return true
	}

	if w.count >= r.maxPerIP {
		return false
	}
	w.count++
	r.active++
	return true
}

// release decrements the global active counter.
func (r *rateLimiter) release() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active > 0 {
		r.active--
	}
}
