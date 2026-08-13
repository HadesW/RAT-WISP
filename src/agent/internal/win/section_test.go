//go:build windows

package win

import "testing"

// TestSectionConstSanity verifies the NT constants used by section injection /
// phantom loading have the documented values (compile-time correctness check
// that also exercises the proc-resolution init on a real host).
func TestSectionConstSanity(t *testing.T) {
	if sectionAllAccess != 0x000F001F {
		t.Fatalf("sectionAllAccess = %#x", sectionAllAccess)
	}
	if secCommit != 0x08000000 {
		t.Fatalf("secCommit = %#x", secCommit)
	}
	if secImageAttr != 0x01000000 {
		t.Fatalf("secImageAttr = %#x", secImageAttr)
	}
	if viewShare != 0x1 {
		t.Fatalf("viewShare = %#x", viewShare)
	}
}

// TestNTProcResolved verifies the lazily-resolved NT proc pointers are non-zero
// on a real Windows host (they are resolved via the PEB walk, not the IAT).
func TestNTProcResolved(t *testing.T) {
	if ModuleNtdll() == 0 {
		t.Skip("non-Windows host")
	}
	if procNtCreateSection == 0 {
		t.Error("NtCreateSection not resolved")
	}
	if procNtOpenFile == 0 {
		t.Error("NtOpenFile not resolved")
	}
	if procNtMapViewOfSection == 0 {
		t.Error("NtMapViewOfSection not resolved")
	}
	if procNtProtectVirtualMemoryFn() == 0 {
		t.Error("NtProtectVirtualMemory not resolved")
	}
	if procCreateThread == 0 {
		t.Error("CreateThread not resolved")
	}
}
