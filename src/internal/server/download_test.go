package server

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/user/wisp/internal/db"
	"github.com/user/wisp/shared/protocol"
)

// recordingEmitter collects emitted events for assertions.
type recordingEmitter struct {
	events []map[string]string
}

func (r *recordingEmitter) EmitEvent(name string, data ...any) {
	if len(data) > 0 {
		if m, ok := data[0].(map[string]string); ok {
			r.events = append(r.events, m)
		}
	}
}

func newDownloadTestServer(t *testing.T) (*Server, *recordingEmitter) {
	t.Helper()
	database, err := db.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	if _, err := database.CreateListener("l1", "tcp", "127.0.0.1", 4444, false, ""); err != nil {
		t.Fatalf("seed listener: %v", err)
	}
	em := &recordingEmitter{}
	s, err := New(database, em)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return s, em
}

func mkBlock(index, total int, data []byte) string {
	blk := downloadBlock{
		Index:    index,
		Total:    total,
		Filename: "payload.bin",
		Data:     base64.StdEncoding.EncodeToString(data),
	}
	b, _ := json.Marshal(blk)
	return string(b)
}

// createDownloadTask seeds a session + a download task and returns the task ID.
func createDownloadTask(t *testing.T, s *Server, cmdID int) string {
	t.Helper()
	seedSession(t, s, "sess-"+t.Name(), time.Now())
	task, err := s.db.CreateTask("sess-"+t.Name(), cmdID, `{"path":"dummy"}`)
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	return task.ID
}

func TestDownloadSingleChunkCompletes(t *testing.T) {
	s, em := newDownloadTestServer(t)
	save := filepath.Join(t.TempDir(), "out", "single.bin")
	content := []byte("small file content")

	taskID := createDownloadTask(t, s, int(protocol.CmdDownload))
	s.RegisterDownload(taskID, save)
	s.CompleteTask(taskID, mkBlock(0, 1, content), protocol.TaskDownloading)

	got, err := os.ReadFile(save)
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("downloaded content = %q, want %q", got, content)
	}

	row, err := s.db.GetTask(taskID)
	if err != nil {
		t.Fatalf("get task: %v", err)
	}
	if row.Status != protocol.TaskCompleted {
		t.Errorf("task status = %q, want completed", row.Status)
	}
	if len(em.events) == 0 {
		t.Error("expected a download-complete event")
	}
	// state cleaned up
	if _, ok := s.getDownload(taskID); ok {
		t.Error("download state should be removed after completion")
	}
}

func TestDownloadMultiChunkOutOfOrder(t *testing.T) {
	s, _ := newDownloadTestServer(t)
	save := filepath.Join(t.TempDir(), "big.bin")

	// 3 chunks, delivered out of order
	chunk0 := []byte("AAAA")
	chunk1 := []byte("BBBB")
	chunk2 := []byte("CCCC")

	taskID := createDownloadTask(t, s, int(protocol.CmdDownload))
	s.RegisterDownload(taskID, save)
	s.CompleteTask(taskID, mkBlock(2, 3, chunk2), protocol.TaskDownloading) // last arrives first
	s.CompleteTask(taskID, mkBlock(0, 3, chunk0), protocol.TaskDownloading)
	s.CompleteTask(taskID, mkBlock(1, 3, chunk1), protocol.TaskDownloading)

	got, err := os.ReadFile(save)
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	want := "AAAABBBBCCCC"
	if string(got) != want {
		t.Errorf("downloaded content = %q, want %q", got, want)
	}

	row, err := s.db.GetTask(taskID)
	if err != nil {
		t.Fatalf("get task: %v", err)
	}
	if row.Status != protocol.TaskCompleted {
		t.Errorf("task status = %q, want completed", row.Status)
	}
}

func TestDownloadCorruptChunkFails(t *testing.T) {
	s, _ := newDownloadTestServer(t)
	save := filepath.Join(t.TempDir(), "partial.bin")

	taskID := createDownloadTask(t, s, int(protocol.CmdDownload))
	s.RegisterDownload(taskID, save)
	s.CompleteTask(taskID, "not-json", protocol.TaskDownloading)

	row, err := s.db.GetTask(taskID)
	if err != nil {
		t.Fatalf("get task: %v", err)
	}
	if row.Status != protocol.TaskFailed {
		t.Errorf("corrupt chunk task status = %q, want failed", row.Status)
	}
}

func TestDownloadNormalTaskUnaffected(t *testing.T) {
	s, _ := newDownloadTestServer(t)

	// Normal task result must not hit the download aggregation path
	taskID := createDownloadTask(t, s, int(protocol.CmdShell))
	s.CompleteTask(taskID, "output", protocol.TaskCompleted)
	row, err := s.db.GetTask(taskID)
	if err != nil {
		t.Fatalf("get task: %v", err)
	}
	if row.Status != protocol.TaskCompleted {
		t.Errorf("normal task status = %q, want completed", row.Status)
	}
}
