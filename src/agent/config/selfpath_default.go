//go:build !windows || !cgo

package config

import "os"

// selfBinaryPath returns the path of the running executable. This is the
// default for standalone agents (the DLL build overrides it in
// selfpath_windows_cgo.go).
func selfBinaryPath() (string, error) {
	return os.Executable()
}
