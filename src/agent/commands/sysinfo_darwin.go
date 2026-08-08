//go:build darwin

package commands

import (
	"fmt"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
)

func listProcessesPlatform() string {
	out, err := exec.Command("ps", "-eo", "pid,user,comm").CombinedOutput()
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	return strings.TrimRight(string(out), "\n")
}

func getSysInfo() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("OS: %s\n", runtime.GOOS))
	sb.WriteString(fmt.Sprintf("Arch: %s\n", runtime.GOARCH))

	u, err := user.Current()
	if err == nil {
		sb.WriteString(fmt.Sprintf("User: %s\n", u.Username))
	}

	out, err := exec.Command("sw_vers", "-productVersion").Output()
	if err == nil {
		sb.WriteString(fmt.Sprintf("Version: macOS %s\n", strings.TrimSpace(string(out))))
	}

	return sb.String()
}
