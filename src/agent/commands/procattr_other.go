//go:build !windows

package commands

import "syscall"

// noWindowAttr is a no-op on non-Windows platforms.
func noWindowAttr() *syscall.SysProcAttr {
	return nil
}
