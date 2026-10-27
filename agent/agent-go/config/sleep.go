package config

import (
	"math/rand"

	"wispp/protocol"
)

// EffectiveSleep returns base ± jitter% uniformly sampled, in ms.
// Shared by the beacon loop and (later) the payload builder so both agree on
// the sleep semantics (plan §2.2).
func EffectiveSleep(baseMS, jitterPct int) int64 {
	if jitterPct <= 0 {
		return int64(baseMS)
	}
	delta := float64(baseMS) * float64(jitterPct) / 100.0
	v := float64(baseMS) + (rand.Float64()*2-1)*delta
	if v < protocol.MinSleepMS {
		v = protocol.MinSleepMS
	}
	return int64(v)
}
