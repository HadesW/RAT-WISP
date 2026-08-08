package server

import "testing"

// TestParseSleepResult verifies the server can read the agent's sleep
// acknowledgment and mirror the new interval into the session record.
func TestParseSleepResult(t *testing.T) {
	tests := []struct {
		result     string
		wantSleep  int
		wantJitter int
		wantOK     bool
	}{
		{"sleep=10ms (0.01s) jitter=20%", 10, 20, true},
		{"sleep=10000ms (10.00s) jitter=0%", 10000, 0, true},
		{"echo hello", 0, 0, false},
		{"", 0, 0, false},
	}
	for _, tc := range tests {
		sleep, jitter, ok := parseSleepResult(tc.result)
		if ok != tc.wantOK {
			t.Errorf("parseSleepResult(%q) ok = %v, want %v", tc.result, ok, tc.wantOK)
			continue
		}
		if !tc.wantOK {
			continue
		}
		if sleep != tc.wantSleep || jitter != tc.wantJitter {
			t.Errorf("parseSleepResult(%q) = (%d, %d), want (%d, %d)", tc.result, sleep, jitter, tc.wantSleep, tc.wantJitter)
		}
	}
}
