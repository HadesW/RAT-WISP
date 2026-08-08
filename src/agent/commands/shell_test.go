package commands

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"
	"time"
)

func shellArgs(t *testing.T, cmd string) string {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"cmd": cmd})
	return string(b)
}

func TestExecShellBasic(t *testing.T) {
	d := NewDispatcher(nil, nil)
	cmd := "echo hello-wisp"
	out := d.execShell(shellArgs(t, cmd))
	if !strings.Contains(out, "hello-wisp") {
		t.Errorf("shell output = %q, want it to contain %q", out, "hello-wisp")
	}
}

func TestExecShellTimeout(t *testing.T) {
	d := NewDispatcher(nil, nil)
	d.shellTimeout = 300 * time.Millisecond

	longCmd := "sleep 60"
	if runtime.GOOS == "windows" {
		longCmd = "ping -n 60 127.0.0.1"
	}

	start := time.Now()
	out := d.execShell(shellArgs(t, longCmd))
	elapsed := time.Since(start)

	if !strings.Contains(out, "timeout") {
		t.Errorf("expected timeout message, got %q", out)
	}
	if elapsed > 10*time.Second {
		t.Errorf("timeout took too long: %v", elapsed)
	}
}

func TestExecShellNoCommand(t *testing.T) {
	d := NewDispatcher(nil, nil)
	out := d.execShell(shellArgs(t, ""))
	if !strings.Contains(out, "no command") {
		t.Errorf("expected 'no command' error, got %q", out)
	}
}
