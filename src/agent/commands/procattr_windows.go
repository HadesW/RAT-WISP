//go:build windows

package commands

import "syscall"

// noWindowAttr returns process attributes for running child commands without
// flashing a console window (the agent itself runs as a GUI-subsystem binary,
// so children would otherwise open a black console on every command).
// CREATE_NO_WINDOW (0x08000000) is not exported by the standard syscall
// package, so it is spelled out here.
const createNoWindow = 0x08000000

func noWindowAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | createNoWindow}
}
