//go:build windows && amd64

#include "textflag.h"

// syscallN6 calls a resolved API pointer with 6 args (L1 direct API path).
//   func syscallN6(proc, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscallErr)
// MS x64 ABI: proc=RCX a1=RDX a2=R8 a3=R9, a5.. on the caller's stack above the
// callee's 32-byte shadow space (which maps onto this frame's low 32 bytes).
TEXT ·syscallN6(SB), NOSPLIT, $56-80
	MOVQ proc+0(FP), AX
	MOVQ a1+8(FP), CX
	MOVQ a2+16(FP), DX
	MOVQ a3+24(FP), R8
	MOVQ a4+32(FP), R9
	// a5, a6 arrive at FP+40/FP+48. Write a5/a6 to the candidate stack offsets
	// (0x18/0x20/0x28 relative to this frame) so whichever offset the kernel
	// uses for the 5th argument, it finds the value. The ntdll stub reads its
	// stack args at [stub_rsp+40]; stub_rsp = our RSP - 8.
	MOVQ a5+40(FP), BX
	MOVQ BX, 24(SP)
	MOVQ BX, 32(SP)
	MOVQ BX, 40(SP)
	MOVQ a6+48(FP), BX
	MOVQ BX, 48(SP)
	CALL AX
	MOVQ AX, ret+56(FP)
	MOVQ DX, ret1+64(FP)
	XORQ AX, AX
	MOVQ AX, ret2+72(FP)
	RET

// directSyscall5 executes a raw syscall instruction (L4).
//   func directSyscall5(ssn, a1, a2, a3, a4, a5 uintptr) uintptr
// Windows syscall ABI: r10=arg1 rdx=arg2 r8=arg3 r9=arg4, arg5 at [rsp+40]
// (the caller's shadow space above the return address). Frame $48 puts the
// syscall's rsp 48 bytes below entry, so arg5 written at 40(SP) lands at the
// kernel's expected [syscall_rsp+40].
TEXT ·directSyscall5(SB), NOSPLIT, $48-56
	MOVQ a5+40(FP), AX
	MOVQ AX, 40(SP)
	MOVQ a4+32(FP), R9
	MOVQ a3+24(FP), R8
	MOVQ a2+16(FP), DX
	MOVQ a1+8(FP), R10
	MOVQ ssn+0(FP), AX
	SYSCALL
	MOVQ AX, ret+48(FP)
	RET

// indirectSyscall5 jumps through the ntdll "syscall; ret" gadget (L5).
//   func indirectSyscall5(gadget, ssn, a1, a2, a3, a4, a5 uintptr) uintptr
// The CALL pushes a return address first (rsp -= 8), so arg5 must be at
// [syscall_rsp+40] = [rsp_after_frame + 32]; write it at 32(SP).
TEXT ·indirectSyscall5(SB), NOSPLIT, $48-64
	MOVQ a5+48(FP), AX
	MOVQ AX, 32(SP)
	MOVQ a4+40(FP), R9
	MOVQ a3+32(FP), R8
	MOVQ a2+24(FP), DX
	MOVQ a1+16(FP), R10
	MOVQ ssn+8(FP), AX
	MOVQ gadget+0(FP), R11
	CALL R11
	MOVQ AX, ret+56(FP)
	RET

// spoofedSyscall5 calls a runtime-built 110-byte spoofed stub (L7). The stub
// is a full Windows ABI function: it shifts stack args, plants the spoofed
// return address and jmps to the syscall gadget itself. So this wrapper is
// just an ordinary x64 call with the first 4 args in registers and arg5 on the
// stack (standard MS x64: 5th arg at [rsp+0x28] of the caller).
//   func spoofedSyscall5(stub, a1, a2, a3, a4, a5 uintptr) uintptr
TEXT ·spoofedSyscall5(SB), NOSPLIT, $56-56
	MOVQ a5+40(FP), AX
	MOVQ AX, 40(SP)
	MOVQ a4+32(FP), R9
	MOVQ a3+24(FP), R8
	MOVQ a2+16(FP), DX
	MOVQ a1+8(FP), CX
	MOVQ stub+0(FP), AX
	CALL AX
	MOVQ AX, ret+48(FP)
	RET
