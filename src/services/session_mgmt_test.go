package services

import (
	"testing"
	"time"

	"github.com/user/wisp/internal/db"
)

func TestUpdateSessionNoteAPI(t *testing.T) {
	ss, database := newTestSessionService(t)
	seedTestSession(t, database)

	if err := ss.UpdateSessionNote("sess1", "red team target"); err != nil {
		t.Fatalf("update note: %v", err)
	}
	row, err := database.GetSession("sess1")
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if row.Note != "red team target" {
		t.Errorf("note = %q", row.Note)
	}

	if err := ss.UpdateSessionNote("nope", "x"); err == nil {
		t.Error("expected error for missing session")
	}
}

func TestTaskManagementAPI(t *testing.T) {
	ss, database := newTestSessionService(t)
	seedTestSession(t, database)

	task, err := database.CreateTask("sess1", 1, `{"cmd":"whoami"}`)
	if err != nil {
		t.Fatalf("create task: %v", err)
	}

	// Rerun creates a new task with the same command/args
	rerun, err := ss.RerunTask(task.ID)
	if err != nil {
		t.Fatalf("rerun: %v", err)
	}
	if rerun.ID == task.ID {
		t.Error("rerun should create a new task id")
	}
	if rerun.CommandID != task.CommandID || rerun.Args != task.Args {
		t.Errorf("rerun mismatch: cmd %d->%d args %q->%q", task.CommandID, rerun.CommandID, task.Args, rerun.Args)
	}

	// Delete the original task
	if err := ss.DeleteTask(task.ID); err != nil {
		t.Fatalf("delete task: %v", err)
	}
	tasks, _ := database.ListTasksForSession("sess1")
	if len(tasks) != 1 || tasks[0].ID != rerun.ID {
		t.Errorf("after delete tasks = %d, want only rerun", len(tasks))
	}

	// Clear all
	if err := ss.ClearTasks("sess1"); err != nil {
		t.Fatalf("clear tasks: %v", err)
	}
	tasks, _ = database.ListTasksForSession("sess1")
	if len(tasks) != 0 {
		t.Errorf("after clear tasks = %d, want 0", len(tasks))
	}

	// Rerun of missing task fails
	if _, err := ss.RerunTask("missing-task"); err == nil {
		t.Error("expected error rerunning missing task")
	}
}

func TestListSessionsFiltered(t *testing.T) {
	ss, database := newTestSessionService(t)
	ln, _ := database.CreateListener("ln2", "tcp", "127.0.0.1", 5555, false, "")
	seedTestSession(t, database)

	now := time.Now()
	if err := database.CreateSession(&db.SessionRow{
		ID:            "sess2",
		ListenerID:    ln.ID,
		Hostname:      "server-02",
		Username:      "root",
		ExternalIP:    "10.1.2.3",
		SleepInterval: 5000,
		FirstSeen:     now,
		LastSeen:      now,
		Status:        "dead",
	}); err != nil {
		t.Fatalf("seed sess2: %v", err)
	}

	// Status filter
	alive, err := ss.ListSessions("alive", "", "")
	if err != nil || len(alive) != 1 || alive[0].ID != "sess1" {
		t.Errorf("alive filter = %+v (err %v)", alive, err)
	}

	// Listener filter
	byLn, err := ss.ListSessions("", ln.ID, "")
	if err != nil || len(byLn) != 1 || byLn[0].ID != "sess2" {
		t.Errorf("listener filter = %+v (err %v)", byLn, err)
	}

	// Query
	byQuery, err := ss.ListSessions("", "", "server-02")
	if err != nil || len(byQuery) != 1 || byQuery[0].ID != "sess2" {
		t.Errorf("query filter = %+v (err %v)", byQuery, err)
	}
}
