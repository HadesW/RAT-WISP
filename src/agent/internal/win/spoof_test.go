//go:build windows && amd64

package win

import (
	"encoding/binary"
	"testing"
	"unsafe"
)

// TestSpoofedStubBytes validates the 110-byte spoofed stub layout without
// executing it: the instruction skeleton must be present and the SSN / gadget
// operands must land at the documented offsets.
func TestSpoofedStubBytes(t *testing.T) {
	if ModuleNtdll() == 0 {
		t.Skip("no ntdll (non-Windows test host)")
	}
	if !SpoofedAvailable() {
		t.Skip("spoof/syscall gadget unavailable on this build")
	}
	EnsureSSNs()
	e, ok := SSN(HashNtAllocateVirtualMemory)
	if !ok || e.SSN == 0 {
		t.Fatal("no SSN for NtAllocateVirtualMemory")
	}
	stub := MakeSpoofedStub(e.SSN)
	if stub == 0 {
		t.Fatal("MakeSpoofedStub returned 0")
	}

	// Read the stub bytes back from the RX page (must be executable-readable).
	addr := stub
	size := uintptr(spoofedStubSize)
	if _, err := ProtectVirtualMemory(InvokeAPI, addr, size, pageReadWrite); err != nil {
		t.Fatalf("flip RW for inspection: %v", err)
	}
	b := unsafe.Slice((*byte)(unsafe.Pointer(stub)), spoofedStubSize)
	defer func() { _, _ = ProtectVirtualMemory(InvokeAPI, addr, size, pageExec) }()

	// +0 sub rsp, 8
	if b[0] != 0x48 || b[1] != 0x83 || b[2] != 0xEC || b[3] != 0x08 {
		t.Fatalf("+0 sub rsp: % x", b[:4])
	}
	// +4 mov r11,[rsp+0x30]  ; first arg shift
	if b[4] != 0x4C || b[5] != 0x8B || b[6] != 0x5C || b[7] != 0x24 || b[8] != 0x30 {
		t.Fatalf("+4 mov r11,[rsp+0x30]: % x", b[4:9])
	}
	// +9 mov [rsp+0x28],r11
	if b[9] != 0x4C || b[10] != 0x89 || b[11] != 0x5C || b[12] != 0x24 || b[13] != 0x28 {
		t.Fatalf("+9 mov [rsp+0x28],r11: % x", b[9:14])
	}
	// +74 mov r11, imm64 (spoof gadget)
	if b[74] != 0x49 || b[75] != 0xBB {
		t.Fatalf("+74 mov r11: % x", b[74:76])
	}
	// +84 mov [rsp],r11
	if b[84] != 0x4C || b[85] != 0x89 || b[86] != 0x1C || b[87] != 0x24 {
		t.Fatalf("+84 mov [rsp],r11: % x", b[84:88])
	}
	// +88 mov r10,rcx
	if b[88] != 0x4C || b[89] != 0x8B || b[90] != 0xD1 {
		t.Fatalf("+88 mov r10,rcx: % x", b[88:91])
	}
	// +91 mov eax, SSN
	if b[91] != 0xB8 {
		t.Fatalf("+91 mov eax: % x", b[91])
	}
	if ssn := binary.LittleEndian.Uint32(b[92:96]); ssn != uint32(e.SSN) {
		t.Fatalf("SSN operand = %d, want %d", ssn, e.SSN)
	}
	// +96 jmp [rip+0]
	if b[96] != 0xFF || b[97] != 0x25 || b[98] != 0 || b[99] != 0 || b[100] != 0 || b[101] != 0 {
		t.Fatalf("+96 jmp [rip+0]: % x", b[96:102])
	}
	// +102 gadget pointer must be a real ntdll address within the image.
	gadget := binary.LittleEndian.Uint64(b[102:110])
	ntdll := ModuleNtdll()
	dos := (*IMAGE_DOS_HEADER)(unsafe.Pointer(ntdll))
	nt := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(ntdll + uintptr(dos.e_lfanew)))
	gu, nu := gadget, uint64(ntdll)
	if gu < nu || gu >= nu+uint64(nt.OptionalHeader.SizeOfImage) {
		t.Fatalf("gadget 0x%x outside ntdll image", gadget)
	}
	t.Logf("spoofed stub OK: ssn=%d gadget=0x%x spoof=0x%x", e.SSN, gadget, binary.LittleEndian.Uint64(b[76:84]))
}
