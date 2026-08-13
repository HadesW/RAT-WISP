//go:build windows && arm64

#include "textflag.h"

// func execCode(addr uintptr)
// The AAPCS keeps SP 16-byte aligned, so only the indirect call is required.
TEXT ·execCode(SB), NOSPLIT, $0-8
	MOVD addr+0(FP), R0
	CALL (R0)
	RET
