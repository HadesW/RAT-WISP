package main

import "testing"

// TestJitterOffsetDoesNotPanic covers the crash seen when a freshly generated
// payload had a jitter range that rounds to zero (crypto/rand.Int panics on
// arguments <= 0). All of these must return without panicking.
func TestJitterOffsetDoesNotPanic(t *testing.T) {
	cases := []struct {
		sleep int
		jit   int
	}{
		{5000, 20}, // normal
		{50, 1},    // rounds to zero -> clamped
		{100, 1},   // rounds to zero -> clamped
		{1, 100},   // tiny sleep, large jitter
		{5000, 0},  // jitter disabled
		{0, 20},    // sleep zero
		{-100, 10}, // negative
	}
	for _, c := range cases {
		// must not panic
		_ = jitterOffset(c.sleep, c.jit)
	}
}
