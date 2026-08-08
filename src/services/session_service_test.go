package services

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/user/wisp/internal/db"
	"github.com/user/wisp/internal/server"
	"github.com/user/wisp/shared/protocol"
)

func newTestSessionService(t *testing.T) (*SessionService, *db.Database) {
	t.Helper()
	database, err := db.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	srv, err := server.New(database, nil)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	ss := &SessionService{serverSvc: &ServerService{db: database, server: srv}}
	return ss, database
}

// seedTestSession creates a listener + session and returns the session ID.
func seedTestSession(t *testing.T, database *db.Database) string {
	t.Helper()
	ln, err := database.CreateListener("l1", "tcp", "127.0.0.1", 4444, false, "")
	if err != nil {
		t.Fatalf("create listener: %v", err)
	}
	now := time.Now()
	err = database.CreateSession(&db.SessionRow{
		ID:            "sess1",
		ListenerID:    ln.ID,
		Hostname:      "host1",
		Username:      "user",
		SleepInterval: 5000,
		FirstSeen:     now,
		LastSeen:      now,
		Status:        protocol.StatusAlive,
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	return "sess1"
}

func TestUploadFileCreatesChunkTasks(t *testing.T) {
	ss, database := newTestSessionService(t)
	seedTestSession(t, database)

	// ~1.2MB local file -> 3 chunks
	local := filepath.Join(t.TempDir(), "local.bin")
	content := make([]byte, 2*FileChunkSize+500)
	for i := range content {
		content[i] = byte(i % 251)
	}
	if err := os.WriteFile(local, content, 0644); err != nil {
		t.Fatalf("write local: %v", err)
	}

	remote := `C:\remote\payload.bin`
	count, err := ss.UploadFile("sess1", local, remote)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if count != 3 {
		t.Errorf("chunk count = %d, want 3", count)
	}

	tasks, err := database.ListTasksForSession("sess1")
	if err != nil {
		t.Fatalf("list tasks: %v", err)
	}
	if len(tasks) != 3 {
		t.Fatalf("task count = %d, want 3", len(tasks))
	}

	// Reassemble from task args (order tasks by their chunk index)
	chunks := make([][]byte, 3)
	for _, task := range tasks {
		if task.CommandID != int(protocol.CmdUpload) {
			t.Fatalf("command_id = %d, want upload", task.CommandID)
		}
		var blk uploadBlock
		if err := json.Unmarshal([]byte(task.Args), &blk); err != nil {
			t.Fatalf("parse args: %v", err)
		}
		if blk.Path != remote {
			t.Errorf("block path = %q, want %q", blk.Path, remote)
		}
		if blk.Index < 0 || blk.Index >= len(chunks) {
			t.Fatalf("unexpected chunk index %d", blk.Index)
		}
		chunks[blk.Index], _ = base64.StdEncoding.DecodeString(blk.Data)
	}

	got := append(chunks[0], chunks[1]...)
	got = append(got, chunks[2]...)
	if string(got) != string(content) {
		t.Error("reassembled upload content does not match local file")
	}
}

func TestUploadFileRejectsTraversal(t *testing.T) {
	ss, database := newTestSessionService(t)
	seedTestSession(t, database)

	local := filepath.Join(t.TempDir(), "x.txt")
	os.WriteFile(local, []byte("x"), 0644)

	if _, err := ss.UploadFile("sess1", local, `C:\..\evil.dll`); err == nil {
		t.Error("expected traversal rejection")
	}
}

func TestDownloadFileCreatesTask(t *testing.T) {
	ss, database := newTestSessionService(t)
	seedTestSession(t, database)

	err := ss.DownloadFile("sess1", `C:\remote\report.pdf`, filepath.Join(t.TempDir(), "report.pdf"))
	if err != nil {
		t.Fatalf("download: %v", err)
	}

	tasks, err := database.ListTasksForSession("sess1")
	if err != nil {
		t.Fatalf("list tasks: %v", err)
	}
	if len(tasks) != 1 {
		t.Fatalf("task count = %d, want 1", len(tasks))
	}
	if tasks[0].CommandID != int(protocol.CmdDownload) {
		t.Errorf("command_id = %d, want download", tasks[0].CommandID)
	}
	if !strings.Contains(tasks[0].Args, "report.pdf") {
		t.Errorf("args = %q, want remote path", tasks[0].Args)
	}
}

func TestDownloadFileMissingSession(t *testing.T) {
	ss, database := newTestSessionService(t)
	seedTestSession(t, database)

	err := ss.DownloadFile("no-such-session", `C:\x.bin`, filepath.Join(t.TempDir(), "x.bin"))
	if err == nil {
		t.Error("expected error for missing session")
	}
}

func TestSendCommandWritesConsoleLog(t *testing.T) {
	ss, database := newTestSessionService(t)
	seedTestSession(t, database)

	if err := ss.SendCommand("sess1", "shell", `{"cmd":"whoami"}`); err != nil {
		t.Fatalf("send command: %v", err)
	}

	logs, err := ss.GetConsoleLogs("sess1", 0)
	if err != nil {
		t.Fatalf("get logs: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("log count = %d, want 1", len(logs))
	}
	if logs[0].Type != "input" {
		t.Errorf("log type = %q, want input", logs[0].Type)
	}
	if !strings.Contains(logs[0].Content, "shell") {
		t.Errorf("log content = %q, want shell command", logs[0].Content)
	}
}

func TestClearConsoleLogs(t *testing.T) {
	ss, database := newTestSessionService(t)
	seedTestSession(t, database)

	if err := ss.SendCommand("sess1", "ls", ""); err != nil {
		t.Fatalf("send command: %v", err)
	}
	if err := ss.ClearConsoleLogs("sess1"); err != nil {
		t.Fatalf("clear logs: %v", err)
	}
	logs, err := ss.GetConsoleLogs("sess1", 0)
	if err != nil {
		t.Fatalf("get logs: %v", err)
	}
	if len(logs) != 0 {
		t.Errorf("log count after clear = %d, want 0", len(logs))
	}
}
