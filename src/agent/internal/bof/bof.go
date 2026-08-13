// Package bof implements a Beacon Object File (BOF) runtime: it parses a COFF
// object, maps its sections into executable memory, applies relocations, and
// calls the entry point with the BOF calling convention. Imported symbols are
// resolved against Windows APIs (GetProcAddress) and a small set of Beacon API
// shims. The parser and relocation engine are pure Go and platform-neutral; the
// actual code execution is Windows-only.
package bof

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// COFF relocation types.
const (
	relAmd64Addr64   = 0x0001
	relAmd64Addr32   = 0x0002
	relAmd64Addr32NB = 0x0003
	relAmd64Rel32    = 0x0004
	relAmd64Rel32_1  = 0x0005
	relAmd64Rel32_2  = 0x0006
	relAmd64Rel32_3  = 0x0007
	relAmd64Rel32_4  = 0x0008
	relAmd64Rel32_5  = 0x0009
	relAmd64Section  = 0x000A
	relAmd64SecRel   = 0x000B

	relI386Dir32   = 0x0006
	relI386Dir32NB = 0x0007
	relI386Section = 0x0010
	relI386SecRel  = 0x0011
	relI386Rel32   = 0x0014
)

const (
	storageExternal = 2
	storageFunction = 101
)

// coffHeader is the 20-byte COFF object header.
type coffHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

// coffSection is a 40-byte COFF section header.
type coffSection struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

// coffSymbol is an 18-byte COFF symbol table entry.
type coffSymbol struct {
	Name               [8]byte
	Value              uint32
	SectionNumber      int16
	Type               uint16
	StorageClass       uint8
	NumberOfAuxSymbols uint8
}

// coffReloc is a 10-byte COFF relocation entry.
type coffReloc struct {
	VirtualAddress   uint32
	SymbolTableIndex uint32
	Type             uint16
}

// section is one mapped COFF section.
type section struct {
	name    string
	va      uint32 // offset of the section within the mapped image
	size    uint32
	rawSize uint32
	data    []byte // section raw bytes (relocations applied over it)
	relocs  []coffReloc
}

// symbol is one resolved symbol table entry.
type symbol struct {
	name       string
	sectionNum int16
	value      uint32
	sectionIdx int    // index into image.sections (-1 for undefined)
	importName string // non-empty for undefined externals
	importPtr  bool   // true when the import is __imp_X (an IAT slot reference)
	origIdx    uint32 // index in the ORIGINAL symbol table (incl. aux entries)
}

// image is the parsed COFF ready to be mapped by run().
type image struct {
	machine  uint16
	base     uintptr // start of mapped sections (set by run)
	entryOff uint32  // entry relative offset (sections[..].va + value)
	sections []*section
	symbols  []symbol
	imports  map[string]uintptr // resolved function addresses
	iat      map[string]uintptr // __imp_ import name → IAT slot address (set by run)
	byOrig   map[uint32]*symbol // original symbol-table index → symbol
}

// Parse validates and indexes a COFF object. It does not touch the OS; the
// returned image is mapped and executed by Run.
func Parse(obj []byte) (*image, error) {
	if len(obj) < 20 {
		return nil, fmt.Errorf("COFF: object too small (%d bytes)", len(obj))
	}
	var h coffHeader
	if err := binary.Read(bytes.NewReader(obj), binary.LittleEndian, &h); err != nil {
		return nil, err
	}
	if h.Machine != 0x8664 && h.Machine != 0x014c {
		return nil, fmt.Errorf("COFF: unsupported machine 0x%04x", h.Machine)
	}
	if h.NumberOfSections > 96 {
		return nil, fmt.Errorf("COFF: implausible section count %d", h.NumberOfSections)
	}

	img := &image{machine: h.Machine, imports: map[string]uintptr{}, iat: map[string]uintptr{}, byOrig: map[uint32]*symbol{}}

	// Sections (headers follow the 20-byte file header).
	off := 20
	for i := 0; i < int(h.NumberOfSections); i++ {
		if off+40 > len(obj) {
			return nil, fmt.Errorf("COFF: truncated section headers")
		}
		var sc coffSection
		if err := binary.Read(bytes.NewReader(obj[off:off+40]), binary.LittleEndian, &sc); err != nil {
			return nil, err
		}
		off += 40
		name := readName(sc.Name[:], obj, h)
		if int(sc.PointerToRawData)+int(sc.SizeOfRawData) > len(obj) {
			return nil, fmt.Errorf("COFF: section %q raw data out of range", name)
		}
		sect := &section{
			name:    name,
			va:      uint32(len(img.sections)) * 0x1000, // page-aligned virtual offset
			size:    sc.VirtualSize,
			rawSize: sc.SizeOfRawData,
		}
		if sc.SizeOfRawData > 0 {
			sect.data = make([]byte, sc.SizeOfRawData)
			copy(sect.data, obj[sc.PointerToRawData:sc.PointerToRawData+sc.SizeOfRawData])
		}
		// Relocations live in the object, not in the mapped copy.
		if sc.PointerToRelocations > 0 {
			for j := 0; j < int(sc.NumberOfRelocations); j++ {
				ro := int(sc.PointerToRelocations) + j*10
				if ro+10 > len(obj) {
					return nil, fmt.Errorf("COFF: truncated relocations")
				}
				var rel coffReloc
				if err := binary.Read(bytes.NewReader(obj[ro:ro+10]), binary.LittleEndian, &rel); err != nil {
					return nil, err
				}
				sect.relocs = append(sect.relocs, rel)
			}
		}
		img.sections = append(img.sections, sect)
	}

	// Symbols.
	symStart := int(h.PointerToSymbolTable)
	if symStart > 0 {
		if symStart+int(h.NumberOfSymbols)*18 > len(obj) {
			return nil, fmt.Errorf("COFF: symbol table out of range")
		}
		for i := 0; i < int(h.NumberOfSymbols); i++ {
			var s coffSymbol
			if err := binary.Read(bytes.NewReader(obj[symStart+i*18:symStart+i*18+18]), binary.LittleEndian, &s); err != nil {
				return nil, err
			}
			name := readName(s.Name[:], obj, h)
			sym := symbol{name: name, sectionNum: s.SectionNumber, value: s.Value, sectionIdx: -1, origIdx: uint32(i)}
			if s.SectionNumber > 0 && int(s.SectionNumber) <= len(img.sections) {
				sym.sectionIdx = int(s.SectionNumber) - 1
			} else if s.SectionNumber == 0 && s.StorageClass == storageExternal {
				imp := name
				isPtr := false
				if len(name) > len("__imp_") && name[:len("__imp_")] == "__imp_" {
					imp = name[len("__imp_"):]
					isPtr = true
				}
				sym.importName = imp
				sym.importPtr = isPtr
			}
			img.symbols = append(img.symbols, sym)
			if s.NumberOfAuxSymbols > 0 {
				i += int(s.NumberOfAuxSymbols)
			}
		}
		// Map original symbol-table indices to symbols AFTER the slice is fully
		// built (append may reallocate the backing array mid-loop).
		for idx := range img.symbols {
			img.byOrig[img.symbols[idx].origIdx] = &img.symbols[idx]
		}
	}

	// Entry point: the "go" symbol by convention, otherwise the last function.
	if err := img.findEntry(); err != nil {
		return nil, err
	}
	return img, nil
}

// readName resolves an 8-byte COFF name field:
//   - field[0] == 0   → a long name; the string-table offset lives in bytes 4-7.
//   - field[0] == '/' → a decimal string-table offset (section headers).
//   - otherwise       → a short name stored inline.
//
// String-table offsets are relative to the START of the table, i.e. they
// include the 4-byte length header (matching Go's debug/pe.StringTable.String).
func readName(field []byte, obj []byte, h coffHeader) string {
	switch {
	case field[0] == 0:
		return stringAt(obj, h, binary.LittleEndian.Uint32(field[4:8]))
	case field[0] == '/':
		var off uint32
		if _, err := fmt.Sscanf(string(field[1:]), "%d", &off); err != nil {
			return ""
		}
		return stringAt(obj, h, off)
	default:
		return string(bytes.TrimRight(field, "\x00"))
	}
}

// stringAt reads a null-terminated string from the COFF string table.
func stringAt(obj []byte, h coffHeader, off uint32) string {
	start := int(h.PointerToSymbolTable) + int(h.NumberOfSymbols)*18 + int(off)
	if start < 0 || start >= len(obj) {
		return ""
	}
	if end := bytes.IndexByte(obj[start:], 0); end >= 0 {
		return string(obj[start : start+end])
	}
	return string(obj[start:])
}

// findEntry resolves the entry symbol as a relative offset from the image base.
func (img *image) findEntry() error {
	for _, s := range img.symbols {
		if (s.name == "go" || s.name == "Go") && s.sectionIdx >= 0 {
			img.entryOff = img.sections[s.sectionIdx].va + s.value
			return nil
		}
	}
	for _, s := range img.symbols {
		if s.sectionIdx >= 0 {
			img.entryOff = img.sections[s.sectionIdx].va + s.value
			return nil
		}
	}
	return fmt.Errorf("COFF: no entry symbol found")
}

// entryOffsetFor returns the relative offset of a named symbol, or ok=false.
func (img *image) entryOffsetFor(name string) (uint32, bool) {
	for _, s := range img.symbols {
		if s.name == name && s.sectionIdx >= 0 {
			return img.sections[s.sectionIdx].va + s.value, true
		}
	}
	return 0, false
}
