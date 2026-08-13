//go:build windows

package bof

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// callBof invokes the BOF entry with (char* args, int length). Implemented in
// shim_amd64.s / shim_arm64.s.
func callBof(entry, argPtr, argLen uintptr)

// Run parses, maps, relocates and executes a BOF object. The optional entrySym
// overrides the default "go" entry symbol. arg is passed to the BOF as its
// argument buffer (null-terminated).
func Run(obj []byte, entrySym, arg string) (string, error) {
	img, err := Parse(obj)
	if err != nil {
		return "", err
	}
	if entrySym != "" && entrySym != "go" && entrySym != "Go" {
		if off, ok := img.entryOffsetFor(entrySym); ok {
			img.entryOff = off
		}
	}
	return img.run(arg)
}

// buildIAT allocates one 8-byte slot per unique __imp_ import, writes the
// resolved function address into it, and records the slot address in img.iat.
// The slots live immediately after the image sections so REL32 displacements
// from the BOF code to the slots stay within range.
func (img *image) buildIAT() {
	seen := map[string]bool{}
	var names []string
	for _, s := range img.symbols {
		if s.importPtr && s.importName != "" && !seen[s.importName] {
			seen[s.importName] = true
			names = append(names, s.importName)
		}
	}
	if len(names) == 0 {
		return
	}
	// Reserve the slot region inside the (already committed) image block.
	slotOffset := uintptr(len(img.sections)) * 0x1000
	slots := unsafe.Slice((*uintptr)(unsafe.Pointer(img.base+slotOffset)), len(names))
	for i, name := range names {
		if addr, ok := img.imports[name]; ok {
			slots[i] = addr
			img.iat[name] = img.base + slotOffset + uintptr(i)*8
		}
	}
}

// DebugImports parses a BOF and reports the resolved imports + IAT slot
// addresses WITHOUT executing it (diagnostics).
func DebugImports(obj []byte) (string, error) {
	img, err := Parse(obj)
	if err != nil {
		return "", err
	}
	total := uintptr(len(img.sections)) * 0x1000
	addr, err := windows.VirtualAlloc(0, total+0x1000, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if err != nil || addr == 0 {
		return "", fmt.Errorf("VirtualAlloc: %v", err)
	}
	img.base = addr
	for _, s := range img.sections {
		if s.rawSize == 0 {
			continue
		}
		dst := unsafe.Slice((*byte)(unsafe.Pointer(img.base+uintptr(s.va))), s.rawSize)
		copy(dst, s.data)
	}
	if err := img.resolveImports(); err != nil {
		return "", err
	}
	img.buildIAT()
	var out string
	for name, addr := range img.imports {
		out += fmt.Sprintf("import %-24s -> 0x%x\n", name, addr)
	}
	slotOffset := uintptr(len(img.sections)) * 0x1000
	for name, slot := range img.iat {
		content := *(*uintptr)(unsafe.Pointer(slot))
		out += fmt.Sprintf("iat    %-24s slot=0x%x content=0x%x\n", name, slot, content)
	}
	_ = slotOffset
	// Apply relocations and inspect what got written for each one.
	if err := img.applyRelocations(); err != nil {
		out += "applyRelocations err: " + err.Error() + "\n"
	}
	for _, s := range img.sections {
		for _, rel := range s.relocs {
			loc := img.base + uintptr(s.va) + uintptr(rel.VirtualAddress)
			val := *(*uint32)(unsafe.Pointer(loc))
			sym := img.symbolAt(rel.SymbolTableIndex)
			var syminfo string
			if sym != nil {
				syminfo = fmt.Sprintf("sym=%q imp=%q ptr=%v sec=%d", sym.name, sym.importName, sym.importPtr, sym.sectionIdx)
			}
			out += fmt.Sprintf("reloc %s off=0x%x type=0x%x loc=0x%x val=0x%x %s\n", s.name, rel.VirtualAddress, rel.Type, loc, val, syminfo)
		}
	}
	out += fmt.Sprintf("image base=0x%x entry_off=0x%x sections=%d\n", img.base, img.entryOff, len(img.sections))
	return out, nil
}

// run maps the parsed image into executable memory, resolves imports, applies
// relocations and calls the entry point, returning captured Beacon output.
func (img *image) run(arg string) (string, error) {
	total := uintptr(len(img.sections)) * 0x1000
	// Reserve extra space for the IAT slots adjacent to the image.
	addr, err := windows.VirtualAlloc(0, total+0x1000, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if err != nil || addr == 0 {
		return "", fmt.Errorf("VirtualAlloc: %v", err)
	}
	img.base = addr

	for _, s := range img.sections {
		if s.rawSize == 0 {
			continue
		}
		dst := unsafe.Slice((*byte)(unsafe.Pointer(img.base+uintptr(s.va))), s.rawSize)
		copy(dst, s.data)
	}

	if err := img.resolveImports(); err != nil {
		return "", err
	}

	// Build IAT slots for __imp_ imports. Allocate an RW region right after
	// the image sections and write each resolved function address into its
	// slot; `call [rip+disp]` instructions then dereference the slot.
	img.buildIAT()

	if err := img.applyRelocations(); err != nil {
		return "", err
	}

	// Build the argument buffer passed to the entry function.
	var argPtr, argLen uintptr
	if arg != "" {
		n := uintptr(len(arg) + 1)
		ap, err := windows.VirtualAlloc(0, n, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
		if err != nil || ap == 0 {
			return "", fmt.Errorf("VirtualAlloc(args): %v", err)
		}
		dst := unsafe.Slice((*byte)(unsafe.Pointer(ap)), len(arg)+1)
		copy(dst, arg)
		dst[len(arg)] = 0
		argPtr, argLen = ap, n
	}

	shimRecCnt = 0
	shimBufLn = 0

	callBof(img.base+uintptr(img.entryOff), argPtr, argLen)

	// Format any recorded Beacon API calls now that we are back on the Go stack.
	flushShimRecs()

	out := string(shimBuf[:shimBufLn])
	shimBufLn = 0
	return out, nil
}
