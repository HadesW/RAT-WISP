//go:build windows

package platform

import (
	"syscall"
	"unsafe"
)

var (
	modAdvapi32     = syscall.NewLazyDLL("advapi32.dll")
	modKernel32     = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess = modAdvapi32.NewProc("OpenProcessToken")
	procTokenInfo   = modAdvapi32.NewProc("GetTokenInformation")
	procCloseHandle = modKernel32.NewProc("CloseHandle")
)

const (
	tokenQuery          = 0x0008
	tokenInformationElev = 20 // TokenElevation
)

// IsElevated reports whether the current process runs with an elevated token
// (i.e. as administrator). It uses the TokenElevation query instead of the
// unreliable uid check.
func IsElevated() bool {
	var token uintptr
	procHandle, _ := syscall.GetCurrentProcess()
	r1, _, _ := procOpenProcess.Call(uintptr(procHandle), tokenQuery, uintptr(unsafe.Pointer(&token)))
	if r1 == 0 {
		return false
	}
	defer procCloseHandle.Call(token)

	var elevation uint32
	var retLen uint32
	r2, _, _ := procTokenInfo.Call(
		token,
		tokenInformationElev,
		uintptr(unsafe.Pointer(&elevation)),
		uintptr(unsafe.Sizeof(elevation)),
		uintptr(unsafe.Pointer(&retLen)),
	)
	return r2 != 0 && elevation != 0
}

// GetDomain returns the Windows domain or workgroup of the logged-in user.
func GetDomain() string {
	return getDomainFromEnv()
}
