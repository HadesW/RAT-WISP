//go:build windows && amd64

#include "textflag.h"

// Beacon API shims. Each trampoline RECORDS the C ABI arguments into the
// shimRecs array (pure assembly — no Go calls, which would corrupt the raw C
// frames the BOF leaves on the goroutine stack) and returns 1. run() formats
// the records after the BOF entry returns.
//
// shimRec layout (see shim_windows.go):
//   kind 0  t 8  format 16  a1 24  a2 32  a3 40  a4 48  a5 56  a6 64
//   stack 72  data 80  length 88   (size 96)
// shimRecs is a [512]shimRec; shimRecCnt is the write index.

TEXT ·shimBeaconOutputTramp(SB), NOSPLIT, $40-0
	LEAQ ·shimRecs(SB), AX
	MOVQ ·shimRecCnt(SB), BX
	CMPQ BX, $512
	JGE  ret1
	IMULQ $96, BX
	MOVQ $1, 0(AX)(BX*1)   // kind = output
	MOVQ CX, 8(AX)(BX*1)   // t
	MOVQ R8, 80(AX)(BX*1)  // data
	MOVQ R9, 88(AX)(BX*1)  // length
	MOVQ ·shimRecCnt(SB), CX
	INCQ CX
	MOVQ CX, ·shimRecCnt(SB)
ret1:
	MOVQ $1, AX
	RET

TEXT ·shimBeaconPrintfTramp(SB), NOSPLIT, $40-0
	LEAQ ·shimRecs(SB), AX
	MOVQ ·shimRecCnt(SB), BX
	CMPQ BX, $512
	JGE  ret1
	IMULQ $96, BX
	MOVQ $0, 0(AX)(BX*1)   // kind = printf
	MOVQ CX, 8(AX)(BX*1)   // t
	MOVQ DX, 16(AX)(BX*1)  // format
	MOVQ R8, 24(AX)(BX*1)  // a1
	MOVQ R9, 32(AX)(BX*1)  // a2
	MOVQ SP, DX
	ADDQ $40, DX           // entry SP
	MOVQ DX, 72(AX)(BX*1)  // stack
	MOVQ 40(SP), CX
	MOVQ CX, 40(AX)(BX*1)  // a3
	MOVQ 48(SP), CX
	MOVQ CX, 48(AX)(BX*1)  // a4
	MOVQ 56(SP), CX
	MOVQ CX, 56(AX)(BX*1)  // a5
	MOVQ 64(SP), CX
	MOVQ CX, 64(AX)(BX*1)  // a6
	MOVQ ·shimRecCnt(SB), CX
	INCQ CX
	MOVQ CX, ·shimRecCnt(SB)
ret1:
	MOVQ $1, AX
	RET

// BeaconData* shims are not yet routed through records (BOFs that need them
// use the standard parser flow); return 0 to indicate "no data".
TEXT ·shimBeaconDataParseTramp(SB), NOSPLIT, $40-0
	MOVQ $1, AX
	RET

TEXT ·shimBeaconDataIntTramp(SB), NOSPLIT, $40-0
	MOVQ $0, AX
	RET

TEXT ·shimBeaconDataShortTramp(SB), NOSPLIT, $40-0
	MOVQ $0, AX
	RET

TEXT ·shimBeaconDataLengthTramp(SB), NOSPLIT, $40-0
	MOVQ $0, AX
	RET

TEXT ·shimBeaconDataExtractTramp(SB), NOSPLIT, $40-0
	MOVQ $0, AX
	RET

// func callBof(entry, argPtr, argLen uintptr)
// Invokes the BOF entry function with the BOF calling convention:
//   void entry(char* args, int length)
TEXT ·callBof(SB), NOSPLIT, $32-24
	MOVQ entry+0(FP), AX
	MOVQ argPtr+8(FP), CX
	MOVQ argLen+16(FP), DX
	// The $32 frame doubles as the callee's shadow space.
	CALL AX
	RET
