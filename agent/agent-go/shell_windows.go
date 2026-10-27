//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

// shellCommand passes the command line through verbatim: os/exec would escape
// inner quotes in a way cmd.exe does not unescape, breaking filters such as
// tasklist /FI "IMAGENAME eq x.exe".
func shellCommand(command string) *exec.Cmd {
	c := exec.Command("cmd")
	// Force UTF-8 for redirected console output; without it Chinese text comes
	// back as GBK bytes and the console renders mojibake.
	c.SysProcAttr = &syscall.SysProcAttr{CmdLine: `cmd /C chcp 65001>nul & ` + command}
	return c
}
