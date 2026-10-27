package main

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
)

// inputEvent is the remote-control input message from the browser page.
type inputEvent struct {
	T string `json:"t"` // key | cmd
	S string `json:"s"` // printable text for t=key
	K string `json:"k"` // named key for t=cmd
}

var namedKeys = map[string]string{"enter": "Return", "tab": "Tab", "esc": "Escape", "backspace": "BackSpace", "space": "space"}
var psKeys = map[string]string{"enter": "{ENTER}", "tab": "{TAB}", "esc": "{ESC}", "backspace": "{BACKSPACE}", "space": " "}
var macCodes = map[string]string{"enter": "36", "tab": "48", "esc": "53", "backspace": "51", "space": "49"}

// inputInject best-effort OS keystroke injection for the remote-control page:
// darwin osascript (needs Accessibility permission), windows PowerShell
// SendKeys, linux xdotool when present. Failures are silent by design.
func inputInject(ev inputEvent) {
	switch runtime.GOOS {
	case "darwin":
		var stmt string
		switch ev.T {
		case "cmd":
			code, ok := macCodes[ev.K]
			if !ok {
				return
			}
			stmt = "key code " + code
		case "key":
			if ev.S == "" || len(ev.S) > 64 {
				return
			}
			stmt = fmt.Sprintf("keystroke %q", ev.S)
		default:
			return
		}
		_ = exec.Command("osascript", "-e", fmt.Sprintf(`tell application "System Events" to %s`, stmt)).Run()
	case "windows":
		text := ev.S
		if ev.T == "cmd" {
			text = psKeys[ev.K]
		}
		if text == "" || len(text) > 64 {
			return
		}
		_ = exec.Command("powershell", "-NoProfile", "-Command",
			fmt.Sprintf(`Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SendKeys]::SendWait(%q)`, text)).Run()
	case "linux":
		if _, err := exec.LookPath("xdotool"); err != nil {
			return
		}
		if ev.T == "cmd" {
			if k, ok := namedKeys[ev.K]; ok {
				_ = exec.Command("xdotool", "key", k).Run()
			}
		} else if ev.S != "" && len(ev.S) <= 64 {
			_ = exec.Command("xdotool", "type", "--", ev.S).Run()
		}
	}
}

var _ = json.Marshal
