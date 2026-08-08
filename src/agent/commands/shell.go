package commands

import (
	"context"
	"encoding/json"
	"strings"
)

func (d *Dispatcher) execShell(argsJSON string) string {
	var args map[string]string
	if err := json.Unmarshal([]byte(argsJSON), &args); err != nil {
		return "error: invalid args"
	}

	cmd := args["cmd"]
	if cmd == "" {
		return "error: no command specified"
	}

	timeout := d.shellTimeout
	if timeout <= 0 {
		timeout = CommandTimeout
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	out, err := runShellCommand(ctx, cmd)

	// Decode GBK/UTF-8 so Chinese output reaches the frontend correctly
	result := strings.TrimRight(decodeToUTF8(out), "\n\r")
	switch {
	case ctx.Err() == context.DeadlineExceeded:
		result = "[timeout: command exceeded " + timeout.String() + "]"
	case err != nil:
		if result == "" {
			result = err.Error()
		} else {
			result += "\n[exit: " + err.Error() + "]"
		}
	}
	return result
}
