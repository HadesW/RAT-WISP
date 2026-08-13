//go:build !windows || !cgo

package config

import "fmt"

// loadOverlayConfigFromMemory is only meaningful on Windows (reflective DLL
// loading). Everywhere else the file-based overlay path always applies.
func loadOverlayConfigFromMemory() (string, error) {
	return "", fmt.Errorf("in-memory overlay scan is Windows-only")
}
