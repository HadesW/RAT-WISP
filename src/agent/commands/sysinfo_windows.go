//go:build windows

package commands

import (
	"fmt"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

func listProcessesPlatform() string {
	c := exec.Command("tasklist", "/FO", "CSV", "/NH")
	c.SysProcAttr = noWindowAttr()
	out, err := c.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	return strings.TrimRight(string(out), "\n\r")
}

func getSysInfo() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("OS: %s\n", runtime.GOOS))
	sb.WriteString(fmt.Sprintf("Arch: %s\n", runtime.GOARCH))

	u, err := user.Current()
	if err == nil {
		sb.WriteString(fmt.Sprintf("User: %s\n", u.Username))
	}

	// Get Windows version info
	ver := getWindowsVersion()
	if ver != "" {
		sb.WriteString(fmt.Sprintf("Version: %s\n", ver))
	}

	return sb.String()
}

func getWindowsVersion() string {
	ntdll := syscall.NewLazyDLL("ntdll.dll")
	proc := ntdll.NewProc("RtlGetVersion")

	type osVersionInfo struct {
		dwOSVersionInfoSize uint32
		dwMajorVersion      uint32
		dwMinorVersion      uint32
		dwBuildNumber       uint32
		dwPlatformId        uint32
		szCSDVersion        [128]uint16
	}

	var info osVersionInfo
	info.dwOSVersionInfoSize = uint32(unsafe.Sizeof(info))

	ret, _, _ := proc.Call(uintptr(unsafe.Pointer(&info)))
	if ret != 0 {
		return ""
	}

	return fmt.Sprintf("Windows %d.%d (Build %d)", info.dwMajorVersion, info.dwMinorVersion, info.dwBuildNumber)
}
