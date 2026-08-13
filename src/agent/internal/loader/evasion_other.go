//go:build !windows

package loader

import "fmt"

// applyEvasion is a no-op off-Windows.
func applyEvasion() {}

// WarmSSNs is unsupported off-Windows.
func WarmSSNs() (string, error) {
	return "", fmt.Errorf("SSN warm-up is only supported on Windows")
}
