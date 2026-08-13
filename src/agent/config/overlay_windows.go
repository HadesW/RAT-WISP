//go:build windows && cgo

package config

import (
	"bytes"
	"fmt"
	"unsafe"

	"github.com/user/wisp/shared/protocol"
)

/*
#include <windows.h>

// selfAnchor returns the address of a symbol inside this module (the agent
// DLL). For a reflectively-mapped module (sRDI) the module is NOT present in
// the loader's module list, so GetModuleHandleEx(FROM_ADDRESS) cannot resolve
// it; we instead scan backwards from this anchor for the MZ/PE signature to
// recover the image base.
static void* selfAnchor(void) {
    static int marker;
    return (void*)&marker;
}
*/
import "C"

// loadOverlayConfigFromMemory locates the config overlay by scanning the
// module's own image memory. It is used when the module was mapped reflectively
// (sRDI / shellcode loader) and therefore has no on-disk file to read the
// overlay from. The packer appends the overlay immediately after the PE image,
// so we scan from the image base across SizeOfImage plus a generous tail.
func loadOverlayConfigFromMemory() (string, error) {
	anchor := uintptr(unsafe.Pointer(C.selfAnchor()))
	base := findImageBase(anchor)
	if base == 0 {
		return "", fmt.Errorf("locate agent image base failed")
	}
	img := imageSize(base)
	if img == 0 {
		return "", fmt.Errorf("parse agent PE headers failed")
	}
	// Overlay sits right after the image (packer copies it there). Give some
	// slack in case of rounding / section alignment.
	slack := uintptr(1 << 20)
	total := img + slack
	region := unsafe.Slice((*byte)(unsafe.Pointer(base)), uint64(total))
	idx := bytes.LastIndex(region, protocol.OverlayMarker)
	if idx < 0 {
		return "", fmt.Errorf("no overlay marker in module memory")
	}
	return string(region[idx+len(protocol.OverlayMarker):]), nil
}

// findImageBase walks backwards in page-size steps from a known in-image
// address until it finds an MZ/PE signature, returning the image base.
func findImageBase(addr uintptr) uintptr {
	if addr == 0 {
		return 0
	}
	const page = uintptr(0x1000)
	for i := uintptr(0); i < 64*page; i += page {
		b := addr - i
		if b < page {
			break
		}
		dos := (*IMAGE_DOS_HEADER)(unsafe.Pointer(b))
		if dos.e_magic != 0x5A4D {
			continue
		}
		if dos.e_lfanew <= 0 || dos.e_lfanew > 0x400 {
			continue
		}
		nt := b + uintptr(dos.e_lfanew)
		if *(*uint32)(unsafe.Pointer(nt)) != 0x00004550 {
			continue
		}
		// Verify the anchor really lives within SizeOfImage of this candidate
		// base before accepting it.
		sz := imageSize(b)
		if sz > 0 && addr >= b && addr < b+sz {
			return b
		}
	}
	return 0
}

// imageSize reads SizeOfImage from the optional header of the in-memory PE at
// base. Returns 0 if the image does not parse as a PE32+.
func imageSize(base uintptr) uintptr {
	if base == 0 {
		return 0
	}
	dos := (*IMAGE_DOS_HEADER)(unsafe.Pointer(base))
	if dos.e_magic != 0x5A4D {
		return 0
	}
	nt := base + uintptr(dos.e_lfanew)
	if *(*uint32)(unsafe.Pointer(nt)) != 0x00004550 {
		return 0
	}
	// optional header magic: PE32+ = 0x20b at FileHeader+16
	if *(*uint16)(unsafe.Pointer(nt + 4 + 16)) != 0x20b {
		return 0
	}
	// SizeOfImage at optional-header offset 56 (PE32+).
	return uintptr(*(*uint32)(unsafe.Pointer(nt + 4 + 20 + 56)))
}

// IMAGE_DOS_HEADER mirrors the first fields of the PE DOS header.
type IMAGE_DOS_HEADER struct {
	e_magic  uint16
	_        [58]uint16
	e_lfanew int32
}
