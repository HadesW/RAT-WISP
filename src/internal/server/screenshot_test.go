package server

import (
	"testing"
	"time"

	"github.com/user/wisp/shared/protocol"
)

// TestScreenshotTaskSuppressesConsoleLog ensures the raw base64 JPEG result of
// a screenshot task is NOT written to the console log and does NOT emit a
// session:output event (it would flood the console with megabytes of text).
func TestScreenshotTaskSuppressesConsoleLog(t *testing.T) {
	s, em := newRDPTestServer(t)
	seedSession(t, s, "shot-sess", time.Now())

	task, err := s.db.CreateTask("shot-sess", int(protocol.CmdScreenshot), "")
	if err != nil {
		t.Fatalf("create task: %v", err)
	}

	bigResult := `{"w":1920,"h":1080,"data":"` + "AAAA" + `"}`
	s.CompleteTask(task.ID, bigResult, "completed")

	for _, e := range em.events {
		if e.name == "session:output" {
			t.Errorf("screenshot must not emit session:output, got %+v", e)
		}
	}

	logs, err := s.db.ListConsoleLogs("shot-sess", 100)
	if err != nil {
		t.Fatalf("list logs: %v", err)
	}
	if len(logs) != 0 {
		t.Errorf("screenshot must not write console logs, got %d entries", len(logs))
	}
}
