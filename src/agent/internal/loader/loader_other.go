//go:build !windows

package loader

import "fmt"

func defaultProcess() string { return "notepad.exe" }

// exec is the non-Windows no-op: there is no portable way to execute raw
// shellcode in-process outside Windows without additional machinery.
func exec(shellcode []byte, c Config) (*Result, error) {
	return nil, fmt.Errorf("shellcode execution is only supported on Windows")
}

func inject(shellcode []byte, c Config) (*Result, error) {
	return nil, fmt.Errorf("process injection is only supported on Windows")
}

func spawn(shellcode []byte, c Config) (*Result, error) {
	return nil, fmt.Errorf("fork-and-run is only supported on Windows")
}
