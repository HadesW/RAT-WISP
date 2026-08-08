//go:build windows

package commands

import (
	"testing"
	"time"
)

// TestRDPStartStopSleepJitter verifies the remote desktop stream manages the
// agent's sleep/jitter: starting tightens the interval with the stream jitter,
// stopping restores the previous sleep and jitter exactly.
func TestRDPStartStopSleepJitter(t *testing.T) {
	d := NewDispatcher(nil, nil)
	var gotSleep, gotJitter int
	d.OnSleep = func(s, j int) { gotSleep, gotJitter = s, j }

	oldCapture := CaptureScreen
	CaptureScreen = mockCapture
	defer func() { CaptureScreen = oldCapture }()

	// Start: should tighten sleep to the interval and apply the stream jitter.
	out := d.execRDPStart(`{"frame_task_id":"rdp:test","interval":500,"quality":50,"jitter":15,"restore_sleep":10000,"restore_jitter":20}`)
	if out == "" || out[0:5] == "error" {
		t.Fatalf("execRDPStart = %q, want success", out)
	}
	if gotSleep != 500 || gotJitter != 15 {
		t.Errorf("OnSleep after start = (%d, %d), want (500, 15)", gotSleep, gotJitter)
	}
	// The capture loop runs async; wait for the first frame to appear.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if f := d.RDPFrame(); f != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no frame produced after start")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Stop: should restore the original sleep AND jitter.
	out = d.execRDPStop()
	if out == "" || out[0:5] == "error" {
		t.Fatalf("execRDPStop = %q, want success", out)
	}
	if gotSleep != 10000 || gotJitter != 20 {
		t.Errorf("OnSleep after stop = (%d, %d), want (10000, 20)", gotSleep, gotJitter)
	}
	if f := d.RDPFrame(); f != nil {
		t.Error("RDPFrame must return nil after stop")
	}
	// Stop again is a no-op that must not clobber the restored values.
	d.execRDPStop()
	if gotSleep != 10000 || gotJitter != 20 {
		t.Errorf("OnSleep clobbered by second stop = (%d, %d)", gotSleep, gotJitter)
	}
}

// TestRDPStartClampsValues verifies jitter is clamped to 0-100 and that a
// missing restore defaults are applied.
func TestRDPStartClampsValues(t *testing.T) {
	d := NewDispatcher(nil, nil)
	var gotSleep, gotJitter int
	d.OnSleep = func(s, j int) { gotSleep, gotJitter = s, j }

	oldCapture := CaptureScreen
	CaptureScreen = mockCapture
	defer func() { CaptureScreen = oldCapture }()

	d.execRDPStart(`{"frame_task_id":"rdp:test","interval":500,"quality":50,"jitter":250,"restore_sleep":0,"restore_jitter":0}`)
	if gotJitter != 100 {
		t.Errorf("jitter not clamped to 100: got %d", gotJitter)
	}
	// A zero restore sleep must be clamped to the safe minimum (busy-loop guard).
	d.execRDPStop()
	if gotSleep != 10 || gotJitter != 0 {
		t.Errorf("stop restore = (%d, %d), want clamped (10, 0)", gotSleep, gotJitter)
	}
}
