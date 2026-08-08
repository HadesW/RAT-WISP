//go:build !windows

package commands

import (
	"bytes"
	"os"
	"testing"
)

// TestX11CaptureSmoke verifies real screen capture on an X11 display. It is
// skipped when no DISPLAY is available (e.g. CI) or when the server has no
// root framebuffer (rootless Xwayland: GetImage on the root fails with
// BadMatch even for Xlib) so the suite stays green on headless hosts.
func TestX11CaptureSmoke(t *testing.T) {
	if os.Getenv("DISPLAY") == "" {
		t.Skip("no X11 display")
	}

	data, w, h, err := captureScreen(50)
	if err != nil {
		if isXErrorCode(err, 8) { // BadMatch: no root backing (rootless Xwayland)
			t.Skipf("server has no root framebuffer (BadMatch): %v", err)
		}
		t.Fatalf("captureScreen: %v", err)
	}
	if w <= 0 || h <= 0 {
		t.Fatalf("bad capture size %dx%d", w, h)
	}
	// JPEG magic: FF D8 FF
	if len(data) < 4 || !bytes.Equal(data[:3], []byte{0xff, 0xd8, 0xff}) {
		t.Fatalf("captured data is not a JPEG (len=%d, prefix=% x)", len(data), data[:4])
	}
	t.Logf("captured %dx%d, %d bytes", w, h, len(data))
}

// TestX11InputSmoke verifies the input path against the real display (only a
// mouse move is injected, which is harmless).
func TestX11InputSmoke(t *testing.T) {
	if os.Getenv("DISPLAY") == "" {
		t.Skip("no X11 display")
	}
	if out := rdpInput(`{"type":"move","x":50,"y":50}`); out != "ok" {
		t.Fatalf("rdpInput move: %s", out)
	}
	if out := rdpInput(`{"type":"key","code":65,"down":false}`); out != "ok" {
		t.Fatalf("rdpInput key up: %s", out)
	}
}
