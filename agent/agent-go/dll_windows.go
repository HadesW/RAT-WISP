//go:build windows && cgo

package main

/*
#include <windows.h>
*/
import "C"

import (
	"log"

	"wispp/agent/config"
)

// WispStart is the rundll32 entry point:
//
//	rundll32.exe agent.dll,WispStart
//
// The DLL carries the same WISPCFG sentinel as the exe, so no arguments are
// required. WISPCFG (path or inline JSON) overrides it for development.
func runDLL() C.int {
	cfg, err := config.LoadForAgent("")
	if err != nil {
		log.Printf("agent: dll: %v", err)
		return 1
	}
	if err := runAgent(cfg); err != nil {
		log.Printf("agent: dll: %v", err)
		return 1
	}
	return 0
}

//export WispStart
func WispStart(hwnd C.HWND, hinst C.HINSTANCE, cmd C.LPSTR, show C.int) C.int {
	return runDLL()
}

//export WispStartEx
func WispStartEx(hwnd C.HWND, hinst C.HINSTANCE, cmd C.LPSTR, show C.int) C.int {
	return runDLL()
}
