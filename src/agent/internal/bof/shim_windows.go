//go:build windows

package bof

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// beaconShims maps BOF-imported Beacon API names to the address of their
// assembly trampoline. The trampolines capture the C ABI registers/stack into
// the shimState struct and call a ZERO-argument Go function — this sidesteps
// the ABI0 wrapper argument-offset pitfalls entirely.
var beaconShims = map[string]uintptr{}

// funcAddr returns the machine code entry of a function value.
func funcAddr(fn interface{}) uintptr {
	return **(**uintptr)(unsafe.Pointer(&fn))
}

// shimState is the marshalling buffer shared between the assembly trampolines
// (writers) and the Go shim implementations (readers). Field offsets are fixed
// and referenced by the .s files.
var shimState struct {
	t      uintptr // 0  type / BeaconOutput type
	format uintptr // 8  format string ptr
	a1     uintptr // 16
	a2     uintptr // 24
	a3     uintptr // 32
	a4     uintptr // 40
	a5     uintptr // 48
	a6     uintptr // 56
	stack  uintptr // 64 caller's entry SP (for >4 varargs)

	data   uintptr // 72 BeaconOutput data ptr
	length uintptr // 80 BeaconOutput length / BeaconData size
	parser uintptr // 88 BeaconDataParse parser ptr
	buffer uintptr // 96 BeaconDataParse buffer ptr

	result uintptr // 104 return value
}

// Assembly trampoline declarations (implemented in shim_amd64.s / shim_arm64.s).
// Each trampoline marshals the C ABI args into shimState and calls the
// corresponding zero-arg Go function (defined below).
func shimBeaconOutputTramp()
func shimBeaconPrintfTramp()
func shimBeaconDataParseTramp()
func shimBeaconDataIntTramp()
func shimBeaconDataShortTramp()
func shimBeaconDataLengthTramp()
func shimBeaconDataExtractTramp()

func init() {
	// NOTE: BeaconPrintf/BeaconOutput are intentionally NOT registered. Calling
	// into Go from BOF machine code running on the goroutine stack is unsafe on
	// this host, and COFF REL32 relocations to the agent's high-address shims
	// overflow. BOFs importing them therefore fail cleanly at import-resolution
	// time; BOFs that use plain WinAPI imports still work.
}

// Output capture shared by the shims and run().
//
// Calling into Go while a BOF runs on the goroutine stack is unsafe: the raw C
// frames on the stack have no Go stack map, so any Go call that triggers
// morestack would corrupt them. The trampolines therefore ONLY record the call
// arguments into shimRecs (pure assembly, no Go calls) and return. After the
// BOF's entry returns, run() formats the records back on the normal Go stack.
var (
	shimRecs   [512]shimRec
	shimRecCnt uintptr
	shimBuf    [1 << 20]byte
	shimBufLn  int
)

// shimRec is one recorded Beacon API call made by the BOF. Field offsets are
// fixed and referenced by the .s trampolines.
type shimRec struct {
	kind   uintptr // 0=printf 1=output
	t      uintptr
	format uintptr
	a1     uintptr
	a2     uintptr
	a3     uintptr
	a4     uintptr
	a5     uintptr
	a6     uintptr
	stack  uintptr
	data   uintptr
	length uintptr
}

// beaconDataParser mirrors the C struct the BOFs manipulate:
//
//	typedef struct { char* originalBuffer; char* buffer; int size; int length; } BeaconDataParser;
type beaconDataParser struct {
	originalBuffer uintptr
	buffer         uintptr
	size           int32
	length         int32
}

// mem32/mem64 read raw memory (addresses handed to us by the BOF).
func mem32(p uintptr) int32 { return *(*int32)(unsafe.Pointer(p)) }

//go:nosplit
func mem64(p uintptr) uintptr { return *(*uintptr)(unsafe.Pointer(p)) }

// ---- record processing (runs after the BOF returns, on the Go goroutine) ----

// flushShimRecs formats the recorded Beacon API calls into shimBuf. Called by
// run() once the BOF entry has returned and we are back on a normal Go stack.
func flushShimRecs() {
	for i := uintptr(0); i < shimRecCnt && i < uintptr(len(shimRecs)); i++ {
		rec := &shimRecs[i]
		switch rec.kind {
		case 1: // BeaconOutput
			if rec.data != 0 && rec.length != 0 {
				n := copy(shimBuf[shimBufLn:], unsafe.Slice((*byte)(unsafe.Pointer(rec.data)), rec.length))
				shimBufLn += n
			}
		default: // BeaconPrintf
			shimBufLn += formatInto(shimBuf[shimBufLn:], rec)
		}
	}
	shimRecCnt = 0
}

// formatInto renders one printf record into out, returning bytes written.
func formatInto(out []byte, rec *shimRec) int {
	format := rec.format
	if format == 0 {
		return 0
	}
	oi := 0
	arg := 0
	for fi := 0; fi < 1<<20; fi++ {
		c := *(*byte)(unsafe.Pointer(format + uintptr(fi)))
		if c == 0 {
			break
		}
		if c != '%' {
			if oi < len(out) {
				out[oi] = c
				oi++
			}
			continue
		}
		fi++
		c = *(*byte)(unsafe.Pointer(format + uintptr(fi)))
		if c == 0 {
			break
		}
		for c == 'l' || c == 'h' || c == 'z' || c == 'j' {
			fi++
			c = *(*byte)(unsafe.Pointer(format + uintptr(fi)))
		}
		v := readVararg(rec.a1, rec.a2, rec.a3, rec.a4, rec.a5, rec.a6, rec.stack, arg)
		arg++
		switch c {
		case '%':
			if oi < len(out) {
				out[oi] = '%'
				oi++
			}
			arg--
		case 's':
			p := v
			for p != 0 && oi < len(out) {
				ch := *(*byte)(unsafe.Pointer(p))
				if ch == 0 {
					break
				}
				out[oi] = ch
				oi++
				p++
			}
		case 'c':
			if oi < len(out) {
				out[oi] = byte(v)
				oi++
			}
		case 'd', 'i', 'u':
			s, e := itoa(out[oi:], int32(v))
			oi += e - s
		case 'x', 'X':
			var tmp [16]byte
			j := len(tmp)
			uv := uint32(v)
			if uv == 0 {
				j--
				tmp[j] = '0'
			}
			for uv > 0 {
				j--
				d := byte(uv & 0xF)
				if d < 10 {
					tmp[j] = '0' + d
				} else if c == 'X' {
					tmp[j] = 'A' + d - 10
				} else {
					tmp[j] = 'a' + d - 10
				}
				uv >>= 4
			}
			for ; j < len(tmp) && oi < len(out); j, oi = j+1, oi+1 {
				out[oi] = tmp[j]
			}
		default:
			if oi < len(out) {
				out[oi] = '%'
				oi++
			}
			if oi < len(out) {
				out[oi] = c
				oi++
			}
		}
	}
	return oi
}

// itoa writes an int32 into buf (reversed) and returns (start, end) indices.
func itoa(buf []byte, v int32) (int, int) {
	var tmp [24]byte
	i := len(tmp)
	neg := v < 0
	uv := uint32(v)
	if neg {
		uv = uint32(-v)
	}
	if uv == 0 {
		i--
		tmp[i] = '0'
	}
	for uv > 0 {
		i--
		tmp[i] = byte('0' + uv%10)
		uv /= 10
	}
	if neg {
		i--
		tmp[i] = '-'
	}
	j := 0
	for ; i < len(tmp); i, j = i+1, j+1 {
		buf[j] = tmp[i]
	}
	return 0, j
}

// ---- import resolution ----

// candidateDLLs is consulted (in order) for BOF-imported WinAPI functions.
var candidateDLLs = []string{"kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll", "ws2_32.dll", "shell32.dll", "ole32.dll", "msvcrt.dll"}

// resolveImport resolves a BOF import to an executable address. Beacon API
// shims take priority, then WinAPI lookup across the candidate DLLs.
func (img *image) resolveImport(name string) (uintptr, error) {
	if addr, ok := beaconShims[name]; ok {
		return addr, nil
	}
	for _, dll := range candidateDLLs {
		h, err := windows.LoadLibrary(dll)
		if err != nil {
			continue
		}
		if addr, err := windows.GetProcAddress(h, name); err == nil {
			return addr, nil
		}
	}
	return 0, fmt.Errorf("unresolved import %q", name)
}

// resolveImports populates img.imports for every undefined external.
func (img *image) resolveImports() error {
	seen := map[string]bool{}
	for _, s := range img.symbols {
		if s.importName == "" || seen[s.importName] {
			continue
		}
		addr, err := img.resolveImport(s.importName)
		if err != nil {
			return err
		}
		img.imports[s.importName] = addr
		seen[s.importName] = true
	}
	return nil
}
