package commands

import (
	"runtime"
	"strings"
	"testing"
)

func isWindows() bool {
	return runtime.GOOS == "windows"
}

func TestIshellLifecycle(t *testing.T) {
	d := NewDispatcher(nil, nil)

	if isWindows() {
		// Windows: cmd session mode (parameter execution + tracked cwd)
		out := d.execIshellOpen(jsonArgs(t, map[string]string{"shell": "cmd"}))
		if !strings.Contains(out, "interactive shell started") {
			t.Fatalf("open output = %q", out)
		}

		out = d.execIshellRun(jsonArgs(t, map[string]string{"input": "echo ISHELL-OK"}))
		if !strings.Contains(out, "ISHELL-OK") {
			t.Errorf("run output = %q, want ISHELL-OK", out)
		}

		// Second command keeps working (cwd maintained)
		out = d.execIshellRun(jsonArgs(t, map[string]string{"input": "echo SECOND-RUN"}))
		if !strings.Contains(out, "SECOND-RUN") {
			t.Errorf("second run output = %q", out)
		}
	} else {
		// Unix: persistent sh process
		out := d.execIshellOpen(jsonArgs(t, map[string]string{"shell": "sh"}))
		if !strings.Contains(out, "interactive shell started") {
			t.Fatalf("open output = %q", out)
		}
		out = d.execIshellRun(jsonArgs(t, map[string]string{"input": "echo ISHELL-OK"}))
		if !strings.Contains(out, "ISHELL-OK") {
			t.Errorf("run output = %q", out)
		}
	}

	// Close
	out := d.execIshellClose()
	if !strings.Contains(out, "closed") {
		t.Errorf("close output = %q", out)
	}

	// Running after close fails
	out = d.execIshellRun(jsonArgs(t, map[string]string{"input": "echo x"}))
	if !strings.Contains(out, "no interactive shell") {
		t.Errorf("run after close = %q, want error", out)
	}
}

// TestCmdSessionCwd verifies the cmd session keeps its working directory.
func TestCmdSessionCwd(t *testing.T) {
	if !isWindows() {
		t.Skip("windows only")
	}
	d := NewDispatcher(nil, nil)
	base := t.TempDir()

	d.execIshellOpen(jsonArgs(t, map[string]string{"shell": "cmd"}))

	// cd into a temp dir
	out := d.execIshellRun(jsonArgs(t, map[string]string{"input": "cd " + base}))
	if !strings.Contains(out, base) {
		t.Fatalf("cd output = %q, want %q", out, base)
	}

	// `cd` alone prints the current directory
	out = d.execIshellRun(jsonArgs(t, map[string]string{"input": "cd"}))
	if !strings.Contains(out, base) {
		t.Errorf("cd print = %q, want %q", out, base)
	}

	// Command runs inside the new cwd
	out = d.execIshellRun(jsonArgs(t, map[string]string{"input": "echo %CD%"}))
	if !strings.Contains(out, base) {
		t.Errorf("%%CD%% = %q, want %q", out, base)
	}
}

func TestIshellOpenReplacesExisting(t *testing.T) {
	d := NewDispatcher(nil, nil)
	shell := "cmd"
	if !isWindows() {
		shell = "sh"
	}

	// Opening twice should not leak: the first session is closed first
	if out := d.execIshellOpen(jsonArgs(t, map[string]string{"shell": shell})); !strings.Contains(out, "started") {
		t.Fatalf("first open = %q", out)
	}
	if out := d.execIshellOpen(jsonArgs(t, map[string]string{"shell": shell})); !strings.Contains(out, "started") {
		t.Fatalf("second open = %q", out)
	}
}

func TestIshellRunWithoutOpen(t *testing.T) {
	d := NewDispatcher(nil, nil)
	out := d.execIshellRun(jsonArgs(t, map[string]string{"input": "echo x"}))
	if !strings.Contains(out, "no interactive shell") {
		t.Errorf("expected error, got %q", out)
	}
}
