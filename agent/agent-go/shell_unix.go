//go:build !windows

package main

import "os/exec"

func shellCommand(command string) *exec.Cmd {
	return exec.Command("/bin/sh", "-c", command)
}
