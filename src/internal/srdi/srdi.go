// Package srdi converts a Windows x64 DLL into position-independent shellcode
// by prepending a self-locating prologue and the reflective-loader stub from
// srdi_stub.c. The resulting blob is directly executable by a plain loader
// (memcpy + jump): the prologue sets RCX/RDX and jumps to stub_entry().
//
// Blob layout:
//
//	[ prologue (28 bytes) ][ stubBlob ][ dll bytes ][ dll_len u64 ]
//
// The prologue locates its own address via call/pop, then computes the DLL
// pointer and length from the fixed offsets patched below.
package srdi

import (
	"encoding/binary"
	"fmt"
)

// prologueSize is the fixed size of the generated entry prologue.
const prologueSize = 28

// prologue is the position-independent entry that sets up RCX (dll ptr) and
// RDX (dll length) then jumps to stub_entry. The stub is compiled with the
// mingw64 Win64 ABI (native/build_srdi.sh), so the first two parameters arrive
// in RCX / RDX (Microsoft x64 convention). Three 32-bit operands are patched
// at pack time:
//
//	disp[9:13]  = dllOff  - 5   (dll pointer, rax = blob+5)
//	disp[16:20] = lenOff  - 5   (dll length)
//	disp[24:28] = stubEntry     (jmp at offset 23, next insn at 28 => 28+stubEntry)
var prologue = []byte{
	0xE8, 0x00, 0x00, 0x00, 0x00, // call $+5
	0x58,                                     // pop rax
	0x48, 0x8D, 0x88, 0x00, 0x00, 0x00, 0x00, // lea rcx, [rax + d32]
	0x48, 0x8D, 0x90, 0x00, 0x00, 0x00, 0x00, // lea rdx, [rax + d32]
	0x48, 0x8B, 0x12, // mov rdx, [rdx]
	0xE9, 0x00, 0x00, 0x00, 0x00, // jmp stub_entry
}

// Validate checks that a byte slice is a plausible x64 PE (DLL) image.
func Validate(dll []byte) error {
	if len(dll) < 0x40 {
		return fmt.Errorf("srdi: image too small (%d bytes)", len(dll))
	}
	if dll[0] != 'M' || dll[1] != 'Z' {
		return fmt.Errorf("srdi: missing MZ signature")
	}
	lfanew := binary.LittleEndian.Uint32(dll[0x3c:0x40])
	if int(lfanew)+24 > len(dll) {
		return fmt.Errorf("srdi: PE header out of range")
	}
	if dll[lfanew] != 'P' || dll[lfanew+1] != 'E' {
		return fmt.Errorf("srdi: missing PE signature")
	}
	machine := binary.LittleEndian.Uint16(dll[lfanew+4 : lfanew+6])
	if machine != 0x8664 {
		return fmt.Errorf("srdi: unsupported machine 0x%04x (amd64 required)", machine)
	}
	optMagic := binary.LittleEndian.Uint16(dll[lfanew+24 : lfanew+26])
	if optMagic != 0x20b {
		return fmt.Errorf("srdi: unsupported optional header magic 0x%04x (PE32+ required)", optMagic)
	}
	return nil
}

// Pack builds the self-contained shellcode blob for a DLL. The blob starts with
// the prologue (executable with no arguments) and embeds the DLL payload.
func Pack(dll []byte) ([]byte, error) {
	if err := Validate(dll); err != nil {
		return nil, err
	}

	blob := make([]byte, 0, prologueSize+len(stubBlob)+len(dll)+8)
	blob = append(blob, prologue...)
	blob = append(blob, stubBlob...)

	dllOff := prologueSize + len(stubBlob)
	lenOff := dllOff + len(dll)

	binary.LittleEndian.PutUint32(blob[9:13], uint32(dllOff-5))
	binary.LittleEndian.PutUint32(blob[16:20], uint32(lenOff-5))
	binary.LittleEndian.PutUint32(blob[24:28], uint32(stubEntry))

	blob = append(blob, dll...)
	var lenBuf [8]byte
	binary.LittleEndian.PutUint64(lenBuf[:], uint64(len(dll)))
	blob = append(blob, lenBuf[:]...)
	return blob, nil
}

// Layout describes the parts of a packed blob.
type Layout struct {
	Prologue int
	Stub     int
	StubEnd  int
	DLL      int
	LenField int
	Size     int
}

// Describe parses the geometry of a packed blob (pure-Go, for tests and tools).
func Describe(blob []byte) Layout {
	dllOff := prologueSize + len(stubBlob)
	return Layout{
		Prologue: 0,
		Stub:     prologueSize,
		StubEnd:  dllOff,
		DLL:      dllOff,
		LenField: len(blob) - 8,
		Size:     len(blob),
	}
}

// Unpack splits a packed blob back into its DLL bytes (used by the agent to
// feed the loader without re-parsing the machine code).
func Unpack(blob []byte) ([]byte, error) {
	if len(blob) < prologueSize+len(stubBlob)+8 {
		return nil, fmt.Errorf("srdi: blob too small")
	}
	dllOff := prologueSize + len(stubBlob)
	dllLen := binary.LittleEndian.Uint64(blob[len(blob)-8:])
	if int(dllLen) > len(blob)-dllOff-8 {
		return nil, fmt.Errorf("srdi: corrupt length field")
	}
	return blob[dllOff : dllOff+int(dllLen)], nil
}
