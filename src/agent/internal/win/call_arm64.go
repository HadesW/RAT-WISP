//go:build windows && arm64

package win

import "syscall"

// ARM64 Windows does not expose the x64-style "syscall; ret" convention used
// by the amd64 stubs. These implementations gracefully fall back to the stdlib
// syscall.SyscallN trampoline (the L3 "ntdll 转发" path), which is still
// IAT-free: the callee address comes from PEB-walked exports.

// syscallN6 calls a resolved API pointer with 6 args (L1 direct API path).
func syscallN6(proc uintptr, a1, a2, a3, a4, a5, a6 uintptr) (uintptr, uintptr, syscallErr) {
	r1, r2, err := syscall.SyscallN(proc, a1, a2, a3, a4, a5, a6)
	return r1, r2, syscallErr(err)
}

// directSyscall5 is not available on ARM64; the caller should use the
// InvokeAPI path instead.
func directSyscall5(ssn, a1, a2, a3, a4, a5 uintptr) uintptr {
	_ = ssn
	return ^uintptr(0) // STATUS_UNSUCCESSFUL
}

// indirectSyscall5 is not available on ARM64; the caller should use the
// InvokeAPI path instead.
func indirectSyscall5(gadget, ssn, a1, a2, a3, a4, a5 uintptr) uintptr {
	_ = gadget
	_ = ssn
	return ^uintptr(0)
}

// spoofedSyscall5 is not available on ARM64; the caller should use the
// InvokeAPI path instead.
func spoofedSyscall5(stub, a1, a2, a3, a4, a5 uintptr) uintptr {
	_ = stub
	return ^uintptr(0)
}
