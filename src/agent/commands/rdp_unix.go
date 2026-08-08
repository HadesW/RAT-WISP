//go:build !windows

package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// Remote desktop / remote control on Unix is backed by the X11 protocol
// (see x11.go): screen capture via GetImage and input injection via XTEST.
// On composited desktops (KDE Plasma on Wayland) the X root window has no
// framebuffer and GetImage fails with BadMatch; capture then falls back to a
// desktop screenshot tool.

var (
	x11mu sync.Mutex
	x11c  *x11
)

// checkPlatform verifies that an X11 display is available and reachable.
func checkPlatform() error {
	if os.Getenv("DISPLAY") == "" {
		return fmt.Errorf("remote desktop requires an X11 display (DISPLAY is not set)")
	}
	x11mu.Lock()
	defer x11mu.Unlock()
	_, err := getX11()
	return err
}

// getX11 returns the shared (cached) X11 connection, opening it on first use.
func getX11() (*x11, error) {
	if x11c != nil {
		return x11c, nil
	}
	c, err := x11Open()
	if err != nil {
		return nil, err
	}
	x11c = c
	return c, nil
}

func dropX11() {
	if x11c != nil {
		x11c.close()
		x11c = nil
	}
}

// captureScreen grabs the screen and returns JPEG bytes + size. It prefers the
// fast X11 GetImage path and falls back to a desktop screenshot tool when the
// X root has no backing (rootless / Wayland compositors).
func captureScreen(quality int) ([]byte, int, int, error) {
	data, w, h, err := captureX11(quality)
	if err == nil {
		return data, w, h, nil
	}
	if !isXErrorCode(err, 8) { // 8 = BadMatch: X root has no framebuffer
		return nil, 0, 0, err
	}
	return captureViaTool(quality)
}

// captureX11 grabs the primary X11 screen (with a Composite fallback) and
// returns JPEG bytes + size.
func captureX11(quality int) ([]byte, int, int, error) {
	x11mu.Lock()
	defer x11mu.Unlock()

	c, err := getX11()
	if err != nil {
		return nil, 0, 0, err
	}

	data, depth, err := c.grabImage()
	if err != nil {
		dropX11() // stale connection; reconnect on the next capture
		return nil, 0, 0, err
	}

	bytesPerLine := len(data) / c.h
	bpp := bytesPerLine / c.w
	if bpp <= 0 {
		return nil, 0, 0, fmt.Errorf("invalid capture geometry %dx%d (bpp %d)", c.w, c.h, bpp)
	}

	img := image.NewRGBA(image.Rect(0, 0, c.w, c.h))
	for y := 0; y < c.h; y++ {
		row := data[y*bytesPerLine:]
		for x := 0; x < c.w; x++ {
			o := x * bpp
			var r, g, b byte
			switch {
			case bpp == 4 && c.lsbFirst: // little-endian 32bpp: B G R pad
				b, g, r = row[o], row[o+1], row[o+2]
			case bpp == 4 && !c.lsbFirst: // big-endian 32bpp: pad R G B
				r, g, b = row[o+1], row[o+2], row[o+3]
			case bpp == 3 && c.lsbFirst: // little-endian 24bpp packed: B G R
				b, g, r = row[o], row[o+1], row[o+2]
			case bpp == 3 && !c.lsbFirst: // big-endian 24bpp packed: R G B
				r, g, b = row[o], row[o+1], row[o+2]
			case bpp == 2: // RGB565
				var v uint16
				if c.lsbFirst {
					v = uint16(row[o]) | uint16(row[o+1])<<8
				} else {
					v = uint16(row[o])<<8 | uint16(row[o+1])
				}
				r = uint8((v>>11)&0x1f) << 3
				g = uint8((v>>5)&0x3f) << 2
				b = uint8(v&0x1f) << 3
			case bpp == 1:
				r, g, b = row[o], row[o], row[o]
			default:
				return nil, 0, 0, fmt.Errorf("unsupported X11 depth %d (bpp %d)", depth, bpp)
			}
			i := (y*c.w + x) * 4
			img.Pix[i] = r
			img.Pix[i+1] = g
			img.Pix[i+2] = b
			img.Pix[i+3] = 255
		}
	}

	var out bytes.Buffer
	if err := jpeg.Encode(&out, img, &jpeg.Options{Quality: quality}); err != nil {
		return nil, 0, 0, err
	}
	return out.Bytes(), c.w, c.h, nil
}

// captureViaTool captures the screen with a desktop screenshot tool (KDE
// spectacle, grim, gnome-screenshot), decoding the PNG and re-encoding it as
// JPEG. Slower than X11 but works on Wayland compositors.
func captureViaTool(quality int) ([]byte, int, int, error) {
	dir, err := os.MkdirTemp("", "wisp-shot-*")
	if err != nil {
		return nil, 0, 0, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "shot.png")

	var attempts []string
	try := func(name string, args ...string) bool {
		cmd := exec.Command(name, args...)
		if err := cmd.Run(); err != nil {
			attempts = append(attempts, fmt.Sprintf("%s: %v", name, err))
			return false
		}
		return true
	}

	switch {
	case try("spectacle", "-b", "-n", "-o", path):
	case try("grim", path):
	case try("gnome-screenshot", "-f", path):
	default:
		return nil, 0, 0, fmt.Errorf("no screenshot tool available (%s)", strings.Join(attempts, "; "))
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("read screenshot: %w", err)
	}
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, 0, 0, fmt.Errorf("decode screenshot: %w", err)
	}
	b := img.Bounds()
	var out bytes.Buffer
	if err := jpeg.Encode(&out, img, &jpeg.Options{Quality: quality}); err != nil {
		return nil, 0, 0, err
	}
	return out.Bytes(), b.Dx(), b.Dy(), nil
}

// rdpInputMsg describes a mouse / keyboard event injected on the target.
type rdpInputMsg struct {
	Type   string `json:"type"` // move | click | key
	X      int    `json:"x"`
	Y      int    `json:"y"`
	Button string `json:"button"` // left | right | middle
	Code   int    `json:"code"`   // Windows virtual-key code
	Down   bool   `json:"down"`
}

// rdpInput injects a mouse / keyboard event via XTEST.
func rdpInput(argsJSON string) string {
	var msg rdpInputMsg
	if err := json.Unmarshal([]byte(argsJSON), &msg); err != nil {
		return "error: invalid input args: " + err.Error()
	}

	x11mu.Lock()
	defer x11mu.Unlock()
	c, err := getX11()
	if err != nil {
		return "error: " + err.Error()
	}

	switch msg.Type {
	case "move":
		if err := c.warpPointer(msg.X, msg.Y); err != nil {
			dropX11()
			return "error: " + err.Error()
		}
	case "click":
		detail := byte(1)
		switch msg.Button {
		case "right":
			detail = 3
		case "middle":
			detail = 2
		}
		var mtype byte = xtButtonDown
		if !msg.Down {
			mtype = xtButtonUp
		}
		if err := c.fakeInput(mtype, detail, msg.X, msg.Y); err != nil {
			dropX11()
			return "error: " + err.Error()
		}
	case "key":
		keycode := vkToKeycode(msg.Code)
		if keycode <= 0 {
			return "error: no mapping for key code " + fmt.Sprint(msg.Code)
		}
		var mtype byte = xtKeyDown
		if !msg.Down {
			mtype = xtKeyRelease
		}
		if err := c.fakeInput(mtype, byte(keycode), 0, 0); err != nil {
			dropX11()
			return "error: " + err.Error()
		}
	default:
		return "error: unknown input type: " + msg.Type
	}
	return "ok"
}
