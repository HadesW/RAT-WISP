package commands

import (
	"runtime"
	"strings"
	"testing"
)

// TestClientKillGraceful verifies CmdClientKill stops the loop via OnExit and
// returns a confirmation without hard-exiting (forceExit is off in tests).
func TestClientKillGraceful(t *testing.T) {
	d := NewDispatcher(nil, nil)
	exited := false
	d.OnExit = func() { exited = true }

	out := d.Execute(&Task{ID: "t1", CommandID: CmdClientKill})
	if out.Status != "completed" {
		t.Fatalf("status = %q, want completed", out.Status)
	}
	if !strings.Contains(out.Output, "agent terminated") {
		t.Errorf("output = %q, want it to mention termination", out.Output)
	}
	if !exited {
		t.Error("OnExit was not called")
	}
}

// TestHostLockUnsupportedOnUnix verifies the Unix lock command reports an
// explicit error instead of silently doing nothing.
func TestHostLockUnsupportedOnUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows has a real lock command")
	}
	if out := execHostLock(); !strings.Contains(out, "not supported") {
		t.Errorf("execHostLock = %q, want an explicit 'not supported' error", out)
	}
}
