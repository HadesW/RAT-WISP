//go:build linux

package commands

import (
	"fmt"
	"os"
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

	// Read /etc/os-release
	data, err := os.ReadFile("/etc/os-release")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				name := strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
				sb.WriteString(fmt.Sprintf("Version: %s\n", name))
				break
			}
		}
	}

	return sb.String()
}
