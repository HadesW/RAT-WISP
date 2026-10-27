// Package guard protects the teamserver itself (plan §2.6): registration
// failure banning and constant-time operator token checks.
package guard

import (
	"crypto/subtle"
	"net"
	"sync"
	"time"
)

// Ban tracks repeated auth failures per source IP.
type Ban struct {
	mu     sync.Mutex
	fails  map[string][]time.Time
	banned map[string]time.Time
	Window time.Duration
	Max    int
	MaxAge time.Duration
}

// NewBan allows max failures inside window before banning for dur.
func NewBan(window time.Duration, max int, dur time.Duration) *Ban {
	return &Ban{
		fails:  make(map[string][]time.Time),
		banned: make(map[string]time.Time),
		Window: window, Max: max, MaxAge: 24 * time.Hour,
	}
}

// Blocked reports whether ip is currently banned (expired bans are GC'd).
func (b *Ban) Blocked(ip string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	until, ok := b.banned[ip]
	if !ok {
		return false
	}
	if time.Now().After(until) {
		delete(b.banned, ip)
		return false
	}
	return true
}

// Fail records one auth failure; returns true if it just triggered a ban.
func (b *Ban) Fail(ip string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	list := append(b.fails[ip], now)
	keep := list[:0]
	for _, t := range list {
		if now.Sub(t) <= b.Window {
			keep = append(keep, t)
		}
	}
	if len(keep) >= b.Max {
		b.banned[ip] = now.Add(b.Window * 10) // ban 10x the detection window
		delete(b.fails, ip)
		if len(b.banned) > 1024 { // bounded memory
			for k, until := range b.banned {
				if now.Sub(until) > b.MaxAge {
					delete(b.banned, k)
				}
			}
		}
		return true
	}
	b.fails[ip] = keep
	return false
}

// CheckToken compares an operator token in constant time.
func CheckToken(got, want string) bool {
	if want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// IPFromRemoteAddr strips the port from "1.2.3.4:5678" / "[::1]:5678".
func IPFromRemoteAddr(ra string) string {
	host, _, err := net.SplitHostPort(ra)
	if err != nil {
		return ra
	}
	return host
}
