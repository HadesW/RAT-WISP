//go:build windows

// Command loadcheck verifies that the stage DLL (agent compiled with
// -buildmode=c-shared) can be loaded via LoadLibrary and exposes the Run
// export. It does not call Run (that would start a full agent).
package main

import (
	"fmt"
	"os"
	"syscall"
)

func main() {
	path := "test-agent.dll"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}

	dll, err := syscall.LoadDLL(path)
	if err != nil {
		fmt.Println("LoadLibrary failed:", err)
		os.Exit(1)
	}
	defer syscall.FreeLibrary(dll.Handle)

	p, err := dll.FindProc("Run")
	if err != nil {
		fmt.Println("FindProc('Run') failed:", err)
		os.Exit(1)
	}
	fmt.Printf("OK: loaded %s, Run export at 0x%x\n", path, p.Addr())
}
