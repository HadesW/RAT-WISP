package commands

import (
	"strings"
	"testing"
)

// TestExecSleepJSONInput verifies the sleep command handles the JSON argument
// form `{"sleep":"100","jitter":"20"}` correctly. This was a real bug: JSON
// input silently fell back to the default interval, making the command look
// like it did nothing.
func TestExecSleepJSONInput(t *testing.T) {
	d := NewDispatcher(nil, nil)
	var gotSleep, gotJitter int
	d.OnSleep = func(s, j int) { gotSleep = s; gotJitter = j }

	out := d.execSleep(`{"sleep":"100","jitter":"20"}`)
	if !strings.Contains(out, "sleep=100ms") {
		t.Errorf("output = %q, want sleep=100ms", out)
	}
	if gotSleep != 100 || gotJitter != 20 {
		t.Errorf("callback got (%d, %d), want (100, 20)", gotSleep, gotJitter)
	}
}

// TestExecSleepBoundaries verifies the enforced limits:
//
//	sleep:  minimum 10ms, no upper limit (a 0ms sleep would busy-loop the agent)
//	jitter: 0% .. 100% (over 100% would make the interval negative)
func TestExecSleepBoundaries(t *testing.T) {
	d := NewDispatcher(nil, nil)
	onSleepCalled := false
	d.OnSleep = func(_, _ int) { onSleepCalled = true }

	// Below-minimum sleep and out-of-range jitter are rejected.
	for _, bad := range []string{
		`{"sleep":"0","jitter":"10"}`,
		`{"sleep":"9","jitter":"10"}`,
		`{"sleep":"100","jitter":"101"}`,
		`{"sleep":"100","jitter":"-1"}`,
	} {
		out := d.execSleep(bad)
		if !strings.HasPrefix(out, "error:") {
			t.Errorf("execSleep(%s) = %q, want an error", bad, out)
		}
		if onSleepCalled {
			t.Fatal("OnSleep must not fire for out-of-range values")
		}
	}

	// The exact minimum (10ms) is accepted; a very large sleep is too (no cap).
	onSleepCalled = false
	d.OnSleep = func(s, j int) { onSleepCalled = true }

	out := d.execSleep(`{"sleep":"10","jitter":"0"}`)
	if !strings.Contains(out, "sleep=10ms") {
		t.Errorf("execSleep(min) = %q, want sleep=10ms", out)
	}
	if !onSleepCalled {
		t.Fatal("OnSleep must fire for the minimum sleep")
	}

	out = d.execSleep(`{"sleep":"86400001","jitter":"0"}`)
	if strings.HasPrefix(out, "error:") {
		t.Errorf("execSleep(large) = %q, want accepted (no upper limit)", out)
	}
	if !onSleepCalled {
		t.Fatal("OnSleep must fire for a very large sleep")
	}
}

// TestExecSleepMalformedJSONRejected reproduces the old frontend bug: a JSON
// object was nested inside the sleep field (`{"sleep":"{\"sleep\":...}"}`).
// The agent must reject it with an explicit error instead of silently keeping
// the default interval (which made the command look like it did nothing).
func TestExecSleepMalformedJSONRejected(t *testing.T) {
	d := NewDispatcher(nil, nil)
	onSleepCalled := false
	d.OnSleep = func(_, _ int) { onSleepCalled = true }

	out := d.execSleep(`{"sleep":"{\"sleep\":\"10\",\"jitter\":\"20\"}","jitter":"0"}`)
	if !strings.HasPrefix(out, "error:") {
		t.Errorf("output = %q, want an explicit error", out)
	}
	if onSleepCalled {
		t.Error("OnSleep must not fire for malformed values")
	}
}

// TestExecSleepInvalidValue returns an explicit error instead of silently
// keeping the default interval (the "did nothing" trap).
func TestExecSleepInvalidValue(t *testing.T) {
	d := NewDispatcher(nil, nil)
	onSleepCalled := false
	d.OnSleep = func(_, _ int) { onSleepCalled = true }

	out := d.execSleep(`{"sleep":"abc","jitter":"20"}`)
	if !strings.HasPrefix(out, "error:") {
		t.Errorf("output = %q, want an error", out)
	}
	if onSleepCalled {
		t.Error("OnSleep must not fire for invalid values")
	}
}
