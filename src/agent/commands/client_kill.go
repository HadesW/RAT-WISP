package commands

import (
	"os"
	"time"
)

// execClientKill terminates the agent process. The graceful path stops the
// main loop via OnExit; the pending result is still reported on this checkin
// before the loop exits. When the agent runs as a standalone binary a hard
// force-exit is scheduled as a safety net so a stuck background goroutine
// cannot keep it alive. In DLL mode the host process must not be killed, so
// only the graceful path runs.
func (d *Dispatcher) execClientKill() string {
	if d.OnExit != nil {
		d.OnExit()
	}
	if d.forceExit {
		go func() {
			time.Sleep(time.Second)
			os.Exit(0)
		}()
	}
	return "agent terminated"
}
