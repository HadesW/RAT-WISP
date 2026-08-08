//go:build windows

package commands

import (
	"os/exec"
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

// execHostReboot reboots the computer.
func execHostReboot() string {
	return runHostCommand("shutdown.exe", "/r", "/f", "/t", "0")
}

// execHostShutdown shuts the computer down.
func execHostShutdown() string {
	return runHostCommand("shutdown.exe", "/s", "/f", "/t", "0")
}

// execHostLogoff signs out the current user.
func execHostLogoff() string {
	return runHostCommand("shutdown.exe", "/l")
}

// execHostLock locks the workstation.
func execHostLock() string {
	return runHostCommand("rundll32.exe", "user32.dll,LockWorkStation")
}
