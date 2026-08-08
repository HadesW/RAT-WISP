package db

import (
	"testing"
	"time"
)

func newDBWithSession(t *testing.T) *Database {
	t.Helper()
	d, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	seedSessionRow(t, d, "s1", "l1", "h1", "u1", "1.1.1.1", "alive")
	return d
}

func TestTaskLifecycle(t *testing.T) {
	d := newDBWithSession(t)

	task, err := d.CreateTask("s1", 1, `{"cmd":"whoami"}`)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if task.Status != "pending" {
		t.Errorf("new task status = %q, want pending", task.Status)
	}
	if task.Result != "" {
		t.Errorf("new task result should be empty, got %q", task.Result)
	}

	// Task is returned as pending, then the server marks it sent
	pending, _ := d.GetPendingTasks("s1")
	if len(pending) != 1 || pending[0].ID != task.ID {
		t.Fatalf("pending = %+v, want the task", pending)
	}
	if err := d.MarkTasksSent([]string{task.ID}); err != nil {
		t.Fatalf("mark sent: %v", err)
	}
	got, _ := d.GetTask(task.ID)
	if got.Status != "sent" {
		t.Errorf("after mark sent status = %q, want sent", got.Status)
	}

	// Complete
	if err := d.CompleteTask(task.ID, "output-here", "completed"); err != nil {
		t.Fatalf("complete: %v", err)
	}
	got, _ = d.GetTask(task.ID)
	if got.Status != "completed" {
		t.Errorf("after complete status = %q", got.Status)
	}
	if got.Result != "output-here" {
		t.Errorf("result = %q", got.Result)
	}
	if got.CompletedAt == nil {
		t.Error("completed_at should be set")
	}
}

func TestGetPendingTasks(t *testing.T) {
	d := newDBWithSession(t)

	t1, _ := d.CreateTask("s1", 1, "a")
	t2, _ := d.CreateTask("s1", 2, "b")

	// Both pending
	pending, err := d.GetPendingTasks("s1")
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if len(pending) != 2 {
		t.Fatalf("pending count = %d, want 2", len(pending))
	}

	// Complete one -> only one remains pending
	_ = d.CompleteTask(t1.ID, "r", "completed")
	pending, _ = d.GetPendingTasks("s1")
	if len(pending) != 1 || pending[0].ID != t2.ID {
		t.Errorf("pending after complete = %+v, want only t2", pending)
	}

	// Marking sent moves it out of pending
	_ = d.MarkTasksSent([]string{t2.ID})
	pending, _ = d.GetPendingTasks("s1")
	if len(pending) != 0 {
		t.Errorf("pending after mark sent = %d, want 0", len(pending))
	}
}

func TestListTasksForSessionOrder(t *testing.T) {
	d := newDBWithSession(t)

	d.CreateTask("s1", 1, "first")
	time.Sleep(5 * time.Millisecond)
	d.CreateTask("s1", 2, "second")

	tasks, err := d.ListTasksForSession("s1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(tasks) != 2 {
		t.Fatalf("count = %d", len(tasks))
	}
	// ListTasksForSession is newest-first
	if tasks[0].Args != "second" || tasks[1].Args != "first" {
		t.Errorf("order wrong: %q then %q, want newest first", tasks[0].Args, tasks[1].Args)
	}
}
