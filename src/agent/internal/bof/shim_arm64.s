//go:build windows && arm64

#include "textflag.h"

// Beacon API shims (Windows ARM64). Each trampoline RECORDS the C ABI
// arguments (X0-X7) into the shimRecs array and returns 1 — no Go calls while
// the BOF runs. run() formats the records afterwards.

// shimRec layout (see shim_windows.go):
//   kind 0  t 8  format 16  a1 24  a2 32  a3 40  a4 48  a5 56  a6 64
//   stack 72  data 80  length 88   (size 96)

TEXT ·shimBeaconOutputTramp(SB), NOSPLIT, $0-0
	MOVD $·shimRecs(SB), R9
	MOVD ·shimRecCnt(SB), R10
	CMP $512, R10
	BGE ret1
	MOVD $96, R11
	MUL R10, R11, R12       // R12 = index * 96
	ADD R12, R9, R13        // R13 = base + offset
	MOVD $1, R8
	MOVD R8, (R13)
	MOVD R0, 8(R13)
	MOVD R2, 80(R13)
	MOVD R3, 88(R13)
	MOVD ·shimRecCnt(SB), R14
	ADD $1, R14
	MOVD R14, ·shimRecCnt(SB)
ret1:
	MOVD $1, R0
	RET

TEXT ·shimBeaconPrintfTramp(SB), NOSPLIT, $0-0
	MOVD $·shimRecs(SB), R9
	MOVD ·shimRecCnt(SB), R10
	CMP $512, R10
	BGE ret1
	MOVD $96, R11
	MUL R10, R11, R12
	ADD R12, R9, R13
	MOVD $0, R8
	MOVD R8, (R13)
	MOVD R0, 8(R13)
	MOVD R1, 16(R13)
	MOVD R2, 24(R13)
	MOVD R3, 32(R13)
	MOVD R4, 40(R13)
	MOVD R5, 48(R13)
	MOVD R6, 56(R13)
	MOVD R7, 64(R13)
	MOVD RSP, R14
	MOVD R14, 72(R13)
	MOVD ·shimRecCnt(SB), R15
	ADD $1, R15
	MOVD R15, ·shimRecCnt(SB)
ret1:
	MOVD $1, R0
	RET

TEXT ·shimBeaconDataParseTramp(SB), NOSPLIT, $0-0
	MOVD $1, R0
	RET

TEXT ·shimBeaconDataIntTramp(SB), NOSPLIT, $0-0
	MOVD $0, R0
	RET

TEXT ·shimBeaconDataShortTramp(SB), NOSPLIT, $0-0
	MOVD $0, R0
	RET

TEXT ·shimBeaconDataLengthTramp(SB), NOSPLIT, $0-0
	MOVD $0, R0
	RET

TEXT ·shimBeaconDataExtractTramp(SB), NOSPLIT, $0-0
	MOVD $0, R0
	RET

// func callBof(entry, argPtr, argLen uintptr)
// Invokes entry(char* args, int length): X0 = args, X1 = length.
TEXT ·callBof(SB), NOSPLIT, $32-24
	MOVD entry+0(FP), R9
	MOVD argPtr+8(FP), R0
	MOVD argLen+16(FP), R1
	CALL (R9)
	RET
