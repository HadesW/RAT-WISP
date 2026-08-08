package commands

import (
	"fmt"
	"os"
	"runtime"
)

// recoverGoroutine logs a background goroutine panic without killing the agent.
func recoverGoroutine(where string) {
	if r := recover(); r != nil {
		buf := make([]byte, 1<<16)
		n := runtime.Stack(buf, true)
		fmt.Fprintf(os.Stderr, "[agent] PANIC in %s: %v\n%s\n", where, r, buf[:n])
	}
}
