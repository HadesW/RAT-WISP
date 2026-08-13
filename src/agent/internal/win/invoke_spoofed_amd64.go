//go:build windows && amd64

package win

// invokeSpoofed calls a runtime-built 110-byte stub that plants a fake
// "call rel32; ret" return address inside ntdll before the syscall (call_type
// "spoofed" / L7). Falls back to invokeDirect if the stub cannot be built.
func invokeSpoofed(ssn uintptr, a1, a2, a3, a4, a5 uintptr) uintptr {
	stub := MakeSpoofedStub(ssn)
	if stub == 0 {
		return invokeDirect(ssn, a1, a2, a3, a4, a5)
	}
	return spoofedSyscall5(stub, a1, a2, a3, a4, a5)
}
