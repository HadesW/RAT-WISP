//go:build windows && amd64

package win

// The syscall stub assembly (call_amd64.s) implements these primitives; they
// are only compiled for amd64, where the "mov r10, rcx; mov eax, SSN; syscall"
// convention applies.

// syscallN6 calls a resolved API pointer with 6 args (L1 direct API path).
func syscallN6(proc uintptr, a1, a2, a3, a4, a5, a6 uintptr) (uintptr, uintptr, syscallErr)

// directSyscall5 executes a raw syscall instruction (L4).
func directSyscall5(ssn, a1, a2, a3, a4, a5 uintptr) uintptr

// indirectSyscall5 jumps through the ntdll "syscall; ret" gadget (L5).
func indirectSyscall5(gadget, ssn, a1, a2, a3, a4, a5 uintptr) uintptr

// spoofedSyscall5 calls a runtime-built 110-byte spoofed stub (L7).
func spoofedSyscall5(stub, a1, a2, a3, a4, a5 uintptr) uintptr
