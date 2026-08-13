//go:build windows && !amd64

package win

// SpoofedAvailable reports whether the L7 spoofed-stub path can be used. The
// 110-byte stub is amd64-only, so it is always false on other architectures.
func SpoofedAvailable() bool { return false }
