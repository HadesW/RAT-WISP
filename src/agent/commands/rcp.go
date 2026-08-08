package commands

// Remote control commands. The agent receives CmdRCPConnect from the server
// (with the automatically chosen RCP port), opens a long-lived TCP channel and
// streams screen frames there, independent of the polling sleep.

import (
	"encoding/json"
	"fmt"
)

// execRCPConnect opens the RCP channel to the server.
// args: {"port": <rcp listener port>, "proto": "tcp"|"kcp"}
func (d *Dispatcher) execRCPConnect(argsJSON string) string {
	if d.rcp == nil {
		return "error: remote control client is not configured"
	}
	// Platform support check (not a capture probe — a single transient capture
	// failure must not block the connection; the stream loop reports sustained
	// failures to the operator instead).
	if err := checkPlatform(); err != nil {
		return "error: cannot start remote control: " + err.Error()
	}
	var args struct {
		Port  int    `json:"port"`
		Proto string `json:"proto"`
	}
	if err := json.Unmarshal([]byte(argsJSON), &args); err != nil {
		return "error: invalid rcp args: " + err.Error()
	}
	if args.Port <= 0 {
		return "error: rcp port is required"
	}
	// KCP is the default transport; an explicit "tcp" opts into TCP.
	if args.Proto == "tcp" {
		d.rcp.Proto = "tcp"
	} else {
		d.rcp.Proto = "kcp"
	}
	if err := d.rcp.Connect(args.Port); err != nil {
		return "error: " + err.Error()
	}
	return fmt.Sprintf("remote control connected (port %d, %s)", args.Port, d.rcp.Proto)
}

// execRCPDisconnect tears down the RCP channel.
func (d *Dispatcher) execRCPDisconnect() string {
	if d.rcp == nil {
		return "remote control not configured"
	}
	d.rcp.Close()
	return "remote control disconnected"
}

// HandleRCPInput dispatches a mouse / keyboard event received over the RCP
// channel to the platform input implementation.
func HandleRCPInput(msg string) string {
	return rdpInput(msg)
}
