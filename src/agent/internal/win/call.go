//go:build windows

package win

// syscallN invokes a resolved function pointer with up to 6 arguments
// (call_type "api": the L1 path). Resolved addresses come from Resolve() so no
// import table entry is involved.
func syscallN(proc uintptr, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscallErr) {
	return syscallN6(proc, a1, a2, a3, a4, a5, a6)
}

// syscallErr carries a Windows error from an indirect call.
type syscallErr uintptr

func (e syscallErr) Error() string { return "winapi call failed" }

// ---- NT syscall invocation (L4 direct / L5 indirect) ----

// invokeDirect executes a raw syscall with the given SSN (call_type "syscall").
func invokeDirect(ssn uintptr, a1, a2, a3, a4, a5 uintptr) uintptr {
	return directSyscall5(ssn, a1, a2, a3, a4, a5)
}

// invokeIndirect jumps through the ntdll "syscall; ret" gadget so the call
// stack appears to originate inside ntdll (call_type "indirect").
func invokeIndirect(gadget, ssn uintptr, a1, a2, a3, a4, a5 uintptr) uintptr {
	return indirectSyscall5(gadget, ssn, a1, a2, a3, a4, a5)
}

// NtStatus is a syscall return code (NTSTATUS).
type NtStatus uintptr

// Success reports whether the status is a success code (NT_SUCCESS: the value
// is >= 0 when interpreted as a signed 32-bit NTSTATUS).
func (s NtStatus) Success() bool { return int32(s) >= 0 }
