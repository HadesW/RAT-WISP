//go:build windows

package commands

import (
	"context"
	"os/exec"
	"strconv"
	"syscall"
)

// runShellCommand runs a command via cmd.exe, killing the whole process tree
// when the context is cancelled (cmd /c leaves child processes behind).
func runShellCommand(ctx context.Context, cmd string) ([]byte, error) {
	c := exec.CommandContext(ctx, "cmd.exe", "/c", cmd)
	// CREATE_NO_WINDOW keeps cmd.exe from flashing a console window: the agent
	// itself runs windowless (GUI subsystem), so children would otherwise open
	// a new black console on every command.
	c.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | createNoWindow}
	c.Cancel = func() error {
		if c.Process == nil {
			return nil
		}
		tk := exec.Command("taskkill", "/F", "/T", "/PID", strconv.Itoa(c.Process.Pid))
		tk.SysProcAttr = noWindowAttr()
		return tk.Run()
	}
	return c.CombinedOutput()
}
