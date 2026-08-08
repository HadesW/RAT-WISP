//go:build !windows

package platform

import "os"

// IsElevated reports whether the process runs as root on Unix-like systems.
func IsElevated() bool {
	return os.Geteuid() == 0
}

// GetDomain returns an empty string on Unix; domains are a Windows concept.
func GetDomain() string {
	return ""
}
