//go:build !windows

package commands

import (
	"context"
	"os/exec"
	"syscall"
)

// runShellCommand runs a command via /bin/sh. The whole process group is
// killed on timeout: CommandContext only terminates the direct child, which
// would leave grandchildren (e.g. `sh -c "sleep 60"`) holding stdout open and
// hang the agent until they exit.
func runShellCommand(ctx context.Context, cmd string) ([]byte, error) {
	c := exec.CommandContext(ctx, "/bin/sh", "-c", cmd)
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	c.Cancel = func() error {
		if c.Process != nil {
			return syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
	return c.CombinedOutput()
}
