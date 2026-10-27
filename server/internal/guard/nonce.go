package guard

import (
	"sync"
	"time"
)

// Nonces remembers recently seen registration nonces inside a TTL window so a
// captured RegisterInfo cannot be replayed (plan P6).
type Nonces struct {
	mu   sync.Mutex
	seen map[string]time.Time
	ttl  time.Duration
}

func NewNonces(ttl time.Duration) *Nonces {
	return &Nonces{seen: make(map[string]time.Time), ttl: ttl}
}

// CheckAndAdd reports whether the nonce is fresh; fresh nonces are recorded.
func (n *Nonces) CheckAndAdd(nonce string) bool {
	if nonce == "" {
		return false
	}
	now := time.Now()
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.seen == nil {
		n.seen = make(map[string]time.Time)
	}
	if until, ok := n.seen[nonce]; ok && now.Before(until) {
		return false
	}
	if len(n.seen) > 1024 {
		for k, until := range n.seen {
			if !now.Before(until) {
				delete(n.seen, k)
			}
		}
	}
	n.seen[nonce] = now.Add(n.ttl)
	return true
}

// registerNonces is process-wide so a replay cannot hop listeners.
var registerNonces = NewNonces(10 * time.Minute)

// CheckRegisterNonce consumes a registration nonce (false = replay).
func CheckRegisterNonce(nonce string) bool { return registerNonces.CheckAndAdd(nonce) }
