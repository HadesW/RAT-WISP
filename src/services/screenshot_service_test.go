package services

import (
	"encoding/base64"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/user/wisp/internal/db"
)

func seedSessionSvc(t *testing.T, svc *ServerService, id string) string {
	t.Helper()
	ln, err := svc.db.CreateListener("lst-"+id, "tcp", "127.0.0.1", 7700+len(id), false, "")
	if err != nil {
		t.Fatalf("create listener: %v", err)
	}
	now := time.Now()
	err = svc.db.CreateSession(&db.SessionRow{
		ID:            id,
		ListenerID:    ln.ID,
		ExternalIP:    "1.2.3.4",
		Hostname:      "host-" + id,
		Username:      "user",
		SleepInterval: 5000,
		FirstSeen:     now,
		LastSeen:      now,
		Status:        "alive",
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	return ln.ID
}

func TestTakeScreenshotCreatesTask(t *testing.T) {
	svc := &ServerService{}
	svc.db, _ = openTestDB(t)
	seedSessionSvc(t, svc, "s1")

	ss := NewSessionService(svc)
	taskID, err := ss.TakeScreenshot("s1")
	if err != nil {
		t.Fatalf("take screenshot: %v", err)
	}
	if taskID == "" {
		t.Fatal("empty task id")
	}

	// Pending until the agent reports
	res, err := ss.GetScreenshot(taskID)
	if err != nil {
		t.Fatalf("get pending: %v", err)
	}
	if res.Status != "pending" {
		t.Errorf("status = %q, want pending", res.Status)
	}
}

func TestGetScreenshotSavesFile(t *testing.T) {
	svc := &ServerService{}
	svc.db, _ = openTestDB(t)
	seedSessionSvc(t, svc, "s2")

	task, err := svc.db.CreateTask("s2", 25, "")
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	jpeg := []byte{0xff, 0xd8, 0xff, 0xe0, 0x01, 0x02, 0x03}
	result := fmt.Sprintf(`{"w":4,"h":4,"data":%q}`, base64.StdEncoding.EncodeToString(jpeg))
	if err := svc.db.CompleteTask(task.ID, result, "completed"); err != nil {
		t.Fatalf("complete task: %v", err)
	}

	ss := NewSessionService(svc)
	res, err := ss.GetScreenshot(task.ID)
	if err != nil {
		t.Fatalf("get screenshot: %v", err)
	}
	if res.Status != "completed" {
		t.Fatalf("status = %q, want completed", res.Status)
	}
	if res.W != 4 || res.H != 4 {
		t.Errorf("dimensions = %dx%d", res.W, res.H)
	}
	data, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read saved file: %v", err)
	}
	if len(data) != len(jpeg) {
		t.Errorf("saved bytes = %d, want %d", len(data), len(jpeg))
	}
	_ = os.Remove(res.Path)
}
