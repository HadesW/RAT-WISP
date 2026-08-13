//go:build windows && !amd64

package win

// invokeSpoofed is unavailable on non-amd64 Windows; fall back to the direct
// syscall path (which itself falls back to the API path in the callers).
func invokeSpoofed(ssn uintptr, a1, a2, a3, a4, a5 uintptr) uintptr {
	return invokeDirect(ssn, a1, a2, a3, a4, a5)
}
