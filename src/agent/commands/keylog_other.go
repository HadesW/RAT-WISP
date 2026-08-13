//go:build !windows

package commands

import (
	"context"
	"fmt"
)

// keylogStart is unsupported off-Windows.
func keylogStart(ctx context.Context, intervalMS int, onEvent func(string)) error {
	return fmt.Errorf("keylogging is only supported on Windows")
}

// clipboardRead is unsupported off-Windows (no portable clipboard API).
func clipboardRead() (string, error) {
	return "", fmt.Errorf("clipboard access is only supported on Windows")
}
