//go:build !windows

package commands

import (
	"os/exec"
	"os/user"
	"runtime"
	"strings"
)

// runHostCommand executes a system management command and returns its output
// (or the error when the command failed).
func runHostCommand(name string, args ...string) string {
	c := exec.Command(name, args...)
	c.SysProcAttr = noWindowAttr()
	out, err := c.CombinedOutput()
	s := strings.TrimSpace(string(out))
	if err != nil {
		if s == "" {
			s = err.Error()
		} else {
			s += "\n[exit: " + err.Error() + "]"
		}
	}
	return s
}

// execHostReboot reboots the computer. Classic reboot/poweroff are symlinked
// to systemctl on systemd systems, so plain commands stay portable.
func execHostReboot() string {
	if runtime.GOOS == "darwin" {
		return runHostCommand("shutdown", "-r", "now")
	}
	return runHostCommand("reboot")
}

// execHostShutdown powers the computer off.
func execHostShutdown() string {
	if runtime.GOOS == "darwin" {
		return runHostCommand("shutdown", "-h", "now")
	}
	return runHostCommand("poweroff")
}

// execHostLogoff ends the current user session.
func execHostLogoff() string {
	if runtime.GOOS == "darwin" {
		return runHostCommand("osascript", "-e", `tell application "System Events" to log out`)
	}
	return runHostCommand("loginctl", "terminate-user", hostUsername())
}

// execHostLock is not meaningful on Unix desktops; the lock mechanism varies
// by DE/WM, so it reports an explicit error.
func execHostLock() string {
	return "error: lock screen is not supported on this platform"
}

func hostUsername() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return "root"
}
