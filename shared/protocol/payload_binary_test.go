package protocol

import (
	"bytes"
	"context"
	"debug/pe"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// Exercise a real optimized executable: marker bytes can occur in machine code,
// something the synthetic slot tests cannot model on their own.
func TestPatchCompiledExecutable(t *testing.T) {
	targets := [][2]string{{runtime.GOOS, runtime.GOARCH}}
	if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
		targets = append(targets, [2]string{"windows", "amd64"})
	}
	for _, target := range targets {
		t.Run(target[0]+"_"+target[1], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			path := filepath.Join(t.TempDir(), "cfgslotprobe")
			if target[0] == "windows" {
				path += ".exe"
			}
			build := exec.CommandContext(ctx, "go", "build", "-trimpath", "-ldflags", "-s -w", "-o", path, "./testdata/cfgslotprobe")
			build.Env = append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0", "GOOS="+target[0], "GOARCH="+target[1])
			if out, err := build.CombinedOutput(); err != nil {
				t.Fatalf("build fixture: %v\n%s", err, out)
			}
			template, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			patched, err := PatchBinary(template, PayloadCfg{PSK: "fixture-only", SleepMS: 5000})
			if err != nil {
				t.Fatal(err)
			}
			off := bytes.Index(template, SentinelSlot[:])
			if off < 0 {
				t.Fatal("compiled fixture has no complete sentinel slot")
			}
			if len(patched) != len(template) || !bytes.Equal(template[:off], patched[:off]) ||
				!bytes.Equal(template[off+CfgSlotSize:], patched[off+CfgSlotSize:]) {
				t.Fatal("patch changed compiled bytes outside the reserved slot")
			}
			if target[0] == "windows" {
				image, err := pe.NewFile(bytes.NewReader(template))
				if err != nil {
					t.Fatal(err)
				}
				defer image.Close()
				for _, section := range image.Sections {
					if section.Characteristics&pe.IMAGE_SCN_MEM_EXECUTE == 0 {
						continue
					}
					start, end := int(section.Offset), int(section.Offset+section.Size)
					if !bytes.Equal(template[start:end], patched[start:end]) {
						t.Fatalf("patch modified executable section %s", section.Name)
					}
				}
			}
			if cfg, ok, err := FindCfgSlot(patched); !ok || err != nil || cfg.PSK != "fixture-only" {
				t.Fatalf("decode compiled config: %+v, %v, %v", cfg, ok, err)
			}
			if target[0] != runtime.GOOS || target[1] != runtime.GOARCH {
				return // Cross-compiled PE is checked structurally, never executed.
			}
			if err := os.WriteFile(path, patched, 0o700); err != nil {
				t.Fatal(err)
			}
			run := exec.CommandContext(ctx, path)
			if out, err := run.CombinedOutput(); err != nil || string(out) != "fixture-only" {
				t.Fatalf("run patched fixture: %v, output %q", err, out)
			}
		})
	}
}
