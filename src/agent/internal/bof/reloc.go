package bof

import (
	"fmt"
	"unsafe"
)

// memW32 / memW64 write raw values into the mapped image.
func memW32(addr uintptr, v uint32) {
	*(*uint32)(unsafe.Pointer(addr)) = v
}

func memW64(addr uintptr, v uint64) {
	*(*uint64)(unsafe.Pointer(addr)) = v
}

// applyRelocations fixes up every relocation once the image is mapped at base
// and imports are resolved.
func (img *image) applyRelocations() error {
	for _, s := range img.sections {
		for _, rel := range s.relocs {
			sym := img.symbolAt(rel.SymbolTableIndex)
			if sym == nil {
				continue
			}
			// Address of the relocation site (where the fixup is written).
			loc := img.base + uintptr(s.va) + uintptr(rel.VirtualAddress)

			var target uintptr
			switch {
			case sym.sectionIdx >= 0:
				target = img.base + uintptr(img.sections[sym.sectionIdx].va+sym.value)
			case sym.importName != "":
				addr, ok := img.imports[sym.importName]
				if !ok {
					return fmt.Errorf("COFF: unresolved import %q", sym.importName)
				}
				// __imp_ imports are IAT slots: the code does `call [rip+disp]`,
				// so the relocation target must be the SLOT that holds the
				// function address (for REL32) or the function address itself
				// (for absolute writes that populate the slot).
				if sym.importPtr {
					slot, ok := img.iat[sym.importName]
					if !ok {
						return fmt.Errorf("COFF: IAT slot missing for %q", sym.importName)
					}
					switch rel.Type {
					case relAmd64Rel32, relAmd64Rel32_1, relAmd64Rel32_2, relAmd64Rel32_3, relAmd64Rel32_4, relAmd64Rel32_5, relI386Rel32:
						target = slot
					default:
						target = addr
					}
				} else {
					target = addr
				}
			default:
				// Absolute / section-less symbol: nothing meaningful to fix.
				continue
			}

			if img.machine == 0x8664 {
				if err := img.relocate64(rel.Type, loc, target, uintptr(s.va)); err != nil {
					return err
				}
			} else {
				if err := img.relocate32(rel.Type, loc, target, uintptr(s.va)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// symbolAt resolves a relocation's symbol reference. COFF relocation indices
// are into the ORIGINAL symbol table (including aux entries), so they must be
// looked up via byOrig rather than the densified img.symbols slice.
func (img *image) symbolAt(idx uint32) *symbol {
	if s, ok := img.byOrig[idx]; ok {
		return s
	}
	if int(idx) < len(img.symbols) {
		return &img.symbols[idx]
	}
	return nil
}

// relocate64 applies an AMD64 COFF relocation.
func (img *image) relocate64(typ uint16, loc, target, secVA uintptr) error {
	switch typ {
	case relAmd64Addr64:
		memW64(loc, uint64(target))
	case relAmd64Addr32:
		memW32(loc, uint32(target))
	case relAmd64Addr32NB:
		memW32(loc, uint32(target-img.base))
	case relAmd64Rel32, relAmd64Rel32_1, relAmd64Rel32_2, relAmd64Rel32_3, relAmd64Rel32_4, relAmd64Rel32_5:
		extra := uintptr(typ - relAmd64Rel32) // Rel32_1.._5 carry extra operand bytes
		memW32(loc, uint32(target-(loc+4+extra)))
	case relAmd64Section:
		memW32(loc, uint32(secVA))
	case relAmd64SecRel:
		memW32(loc, uint32(target-img.base-secVA))
	default:
		return fmt.Errorf("COFF: unsupported amd64 relocation type 0x%04x", typ)
	}
	return nil
}

// relocate32 applies an x86 COFF relocation.
func (img *image) relocate32(typ uint16, loc, target, secVA uintptr) error {
	switch typ {
	case 0x0001: // ABS
		// no fixup needed
	case relI386Dir32:
		memW32(loc, uint32(target))
	case relI386Dir32NB:
		memW32(loc, uint32(target-img.base))
	case relI386Rel32:
		memW32(loc, uint32(target-(loc+4)))
	case relI386Section:
		memW32(loc, uint32(secVA))
	case relI386SecRel:
		memW32(loc, uint32(target-img.base-secVA))
	default:
		return fmt.Errorf("COFF: unsupported i386 relocation type 0x%04x", typ)
	}
	return nil
}
