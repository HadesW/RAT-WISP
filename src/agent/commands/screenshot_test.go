package commands

import (
	"encoding/json"
	"testing"
)

func TestScreenshotCommand(t *testing.T) {
	old := CaptureScreen
	CaptureScreen = mockCapture
	defer func() { CaptureScreen = old }()

	d := NewDispatcher(nil, nil)
	out := d.execScreenshot()
	if len(out) == 0 {
		t.Fatal("empty screenshot output")
	}
	var res struct {
		W    int    `json:"w"`
		H    int    `json:"h"`
		Data string `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("parse output %q: %v", out, err)
	}
	if res.W != 4 || res.H != 4 {
		t.Errorf("dimensions = %dx%d, want 4x4", res.W, res.H)
	}
	if res.Data == "" {
		t.Error("base64 data is empty")
	}
}
