// Package peimg maps template PE32+ files into in-memory images and builds the
// jump stub that enters them (plan P5). Shared by the sRDI bootstrap and the
// poly decoder: headers + sections laid out at their RVAs, no imports.
package peimg

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	// ErrNotPE marks a file that is not an import-free AMD64 PE32+ image.
	ErrNotPE = errors.New("peimg: not an AMD64 PE32+ image")
	// ErrImports marks templates with an import table (they cannot run raw).
	ErrImports = errors.New("peimg: template imports DLLs")
)

// Map lays the PE out in memory (headers + sections at their RVAs). The result
// is position-independent: the image is compiled RIP-relative and applies its
// own base relocations when it has any.
func Map(raw []byte) (image []byte, entryRVA uint32, err error) {
	f, err := pe.NewFile(bytes.NewReader(raw))
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrNotPE, err)
	}
	defer f.Close()
	oh, ok := f.OptionalHeader.(*pe.OptionalHeader64)
	if !ok || f.Machine != pe.IMAGE_FILE_MACHINE_AMD64 || oh.SizeOfImage == 0 ||
		oh.SizeOfHeaders == 0 || oh.AddressOfEntryPoint >= oh.SizeOfImage {
		return nil, 0, ErrNotPE
	}
	if libs, err := f.ImportedLibraries(); err == nil && len(libs) > 0 {
		return nil, 0, ErrImports
	}
	if uint64(oh.SizeOfHeaders) > uint64(len(raw)) {
		return nil, 0, ErrNotPE
	}
	image = make([]byte, oh.SizeOfImage)
	copy(image, raw[:oh.SizeOfHeaders])
	for _, s := range f.Sections {
		if s.Size == 0 {
			continue
		}
		virt := s.VirtualSize
		if virt == 0 {
			virt = s.Size
		}
		n := s.Size
		if virt < n {
			n = virt
		}
		if uint64(s.Offset)+uint64(s.Size) > uint64(len(raw)) ||
			uint64(s.VirtualAddress)+uint64(n) > uint64(len(image)) {
			return nil, 0, ErrNotPE
		}
		copy(image[s.VirtualAddress:], raw[s.Offset:s.Offset+n])
	}
	return image, oh.AddressOfEntryPoint, nil
}

// JumpStub is the 34-byte Windows-x64 stub that enters a mapped image with
// (image base, cfg*) in rcx/rdx — the same ABI the sRDI bootstrap and the poly
// decoder implement. It sits directly before the image, so its call/pop pair
// yields the runtime base without any relocations.
func JumpStub(entryRVA, cfgRVA uint32) []byte {
	out := make([]byte, 0, 34)
	out = append(out, 0xE8, 0, 0, 0, 0, 0x59) // call $+5; pop rcx
	out = append(out, 0x48, 0x81, 0xC1)       // add rcx, 34-5
	out = binary.LittleEndian.AppendUint32(out, 34-5)
	out = append(out, 0x48, 0x89, 0xCA) // mov rdx, rcx
	out = append(out, 0x48, 0x81, 0xC2) // add rdx, cfgRVA
	out = binary.LittleEndian.AppendUint32(out, cfgRVA)
	out = append(out, 0x48, 0x89, 0xC8) // mov rax, rcx
	out = append(out, 0x48, 0x05)       // add rax, entryRVA
	out = binary.LittleEndian.AppendUint32(out, entryRVA)
	out = append(out, 0xFF, 0xE0) // jmp rax
	return out
}
