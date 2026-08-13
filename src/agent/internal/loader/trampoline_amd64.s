//go:build windows && amd64

#include "textflag.h"

// func execCode(addr uintptr)
// Jumps to the shellcode at addr. The stack is aligned to 16 bytes before the
// call (required by the x64 ABI for the sRDI / stager payloads), then restored
// so the goroutine can return cleanly if the payload ever returns.
TEXT ·execCode(SB), NOSPLIT, $0-8
	MOVQ addr+0(FP), AX
	MOVQ SP, BX
	ANDQ $~15, SP
	CALL AX
	MOVQ BX, SP
	RET
