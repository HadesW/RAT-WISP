//go:build windows && amd64

package bof

// On the MS x64 ABI the first four parameters arrive in RCX/RDX/R8/R9, so a
// variadic BOF call has at most two register varargs (R8, R9); the rest live on
// the stack at [entrySP+40 + (i-2)*8].
//
//go:nosplit
func readVararg(a1, a2, a3, a4, a5, a6, stack uintptr, idx int) uintptr {
	switch idx {
	case 0:
		return a1
	case 1:
		return a2
	default:
		return mem64(stack + 40 + uintptr((idx-2)*8))
	}
}
