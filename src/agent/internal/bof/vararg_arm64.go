//go:build windows && arm64

package bof

// On Windows ARM64 the first eight parameters travel in X0-X7, so a variadic
// BOF call has up to six register varargs (X2-X7); the rest live on the stack
// at [entrySP + (i-6)*8].
//
//go:nosplit
func readVararg(a1, a2, a3, a4, a5, a6, stack uintptr, idx int) uintptr {
	switch idx {
	case 0:
		return a1
	case 1:
		return a2
	case 2:
		return a3
	case 3:
		return a4
	case 4:
		return a5
	case 5:
		return a6
	default:
		return mem64(stack + uintptr((idx-6)*8))
	}
}
