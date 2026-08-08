package server

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestZZProbeAgentBuild(t *testing.T) {
	agentBin := filepath.Join(t.TempDir(), "agent-e2e")
	build := exec.Command("go", "build", "-o", agentBin, ".")
	build.Dir = filepath.Join("..", "..", "agent")
	out, err := build.CombinedOutput()
	t.Logf("build err=%v out=%q", err, out)
	t.Logf("cwd of go test process: %s", mustCwd())
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Dir(agentBin))
	for _, e := range entries {
		t.Logf("dir entry: %s", e.Name())
	}
	info, statErr := os.Stat(agentBin)
	t.Logf("stat %s: err=%v exists=%v", agentBin, statErr, info != nil)

	// Simulate the real test: run the built binary with -h (prints usage, exits).
	cmd := exec.CommandContext(context.Background(), agentBin, "-h")
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	if err := cmd.Start(); err != nil {
		t.Logf("START FAILED: %v", err)
	} else {
		_ = cmd.Wait()
		t.Logf("start ok, stderr=%q", errBuf.String())
	}
}

func mustCwd() string {
	d, err := os.Getwd()
	if err != nil {
		return fmt.Sprintf("getwd err: %v", err)
	}
	return d
}
