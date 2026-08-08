package db

import (
	"testing"
	"time"
)

// seedSessionRow creates a listener (for the FK) and a session; returns the
// listener ID for filter tests.
func seedSessionRow(t *testing.T, d *Database, id, listenerName, hostname, username, ip, status string) string {
	t.Helper()
	ln, err := d.CreateListener(listenerName+"-"+id, "tcp", "127.0.0.1", 6000+int(id[0])%200, false, "")
	if err != nil {
		t.Fatalf("create listener: %v", err)
	}
	now := time.Now()
	err = d.CreateSession(&SessionRow{
		ID:            id,
		ListenerID:    ln.ID,
		ExternalIP:    ip,
		Hostname:      hostname,
		Username:      username,
		SleepInterval: 5000,
		FirstSeen:     now,
		LastSeen:      now,
		Status:        status,
	})
	if err != nil {
		t.Fatalf("seed session %s: %v", id, err)
	}
	return ln.ID
}

func TestUpdateSessionNote(t *testing.T) {
	d, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer d.Close()

	seedSessionRow(t, d, "s1", "l1", "h1", "u1", "1.1.1.1", "alive")
	if err := d.UpdateSessionNote("s1", "priority target"); err != nil {
		t.Fatalf("update note: %v", err)
	}
	got, err := d.GetSession("s1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Note != "priority target" {
		t.Errorf("note = %q, want %q", got.Note, "priority target")
	}
}

func TestSearchSessions(t *testing.T) {
	d, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer d.Close()

	ln1 := seedSessionRow(t, d, "aaa111", "l1", "workstation-a", "alice", "10.0.0.1", "alive")
	ln1b := seedSessionRow(t, d, "bbb222", "l1", "workstation-b", "bob", "10.0.0.2", "alive")
	ln2 := seedSessionRow(t, d, "ccc333", "l2", "server-01", "root", "10.0.0.3", "dead")

	// Filter by status
	alive, _ := d.SearchSessions("alive", "", "")
	if len(alive) != 2 {
		t.Errorf("alive count = %d, want 2", len(alive))
	}

	// Filter by listener
	l2, _ := d.SearchSessions("", ln2, "")
	if len(l2) != 1 || l2[0].ID != "ccc333" {
		t.Errorf("l2 sessions = %+v, want only ccc333", l2)
	}
	_ = ln1
	_ = ln1b

	// Free-text query matches hostname
	byHost, _ := d.SearchSessions("", "", "workstation")
	if len(byHost) != 2 {
		t.Errorf("hostname query count = %d, want 2", len(byHost))
	}

	// Free-text query matches username
	byUser, _ := d.SearchSessions("", "", "alice")
	if len(byUser) != 1 || byUser[0].ID != "aaa111" {
		t.Errorf("username query = %+v, want aaa111", byUser)
	}

	// Free-text query matches ID
	byID, _ := d.SearchSessions("", "", "bbb")
	if len(byID) != 1 || byID[0].ID != "bbb222" {
		t.Errorf("id query = %+v, want bbb222", byID)
	}

	// Combined filters
	combo, _ := d.SearchSessions("alive", ln1b, "bob")
	if len(combo) != 1 || combo[0].ID != "bbb222" {
		t.Errorf("combined query = %+v, want bbb222", combo)
	}
}

func TestDeleteSessionCascades(t *testing.T) {
	d, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer d.Close()

	seedSessionRow(t, d, "s1", "l1", "h1", "u1", "1.1.1.1", "alive")

	// Attach child rows that reference the session
	if _, err := d.CreateTask("s1", 1, `{"cmd":"whoami"}`); err != nil {
		t.Fatalf("create task: %v", err)
	}
	if err := d.InsertConsoleLog("s1", "input", "> whoami"); err != nil {
		t.Fatalf("insert log: %v", err)
	}
	if err := d.CreateFileTransfer("s1", "download", `C:\f.txt`, "/tmp/f.txt", 1024, "completed", "t1"); err != nil {
		t.Fatalf("create transfer: %v", err)
	}

	// Deleting the session must cascade to all referencing tables
	if err := d.DeleteSession("s1"); err != nil {
		t.Fatalf("delete session: %v", err)
	}

	if _, err := d.GetSession("s1"); err == nil {
		t.Errorf("session s1 still exists after delete")
	}

	count := func(table string) int {
		t.Helper()
		var n int
		if err := d.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		return n
	}
	if n := count("tasks"); n != 0 {
		t.Errorf("tasks left = %d, want 0", n)
	}
	if n := count("console_logs"); n != 0 {
		t.Errorf("console_logs left = %d, want 0", n)
	}
	if n := count("file_transfers"); n != 0 {
		t.Errorf("file_transfers left = %d, want 0", n)
	}
}

func TestDeleteTaskAndClear(t *testing.T) {
	d, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer d.Close()

	seedSessionRow(t, d, "s1", "l1", "h1", "u1", "1.1.1.1", "alive")
	t1, _ := d.CreateTask("s1", 1, `{"cmd":"whoami"}`)
	t2, _ := d.CreateTask("s1", 2, `{}`)

	// Delete one task
	if err := d.DeleteTask(t1.ID); err != nil {
		t.Fatalf("delete task: %v", err)
	}
	tasks, _ := d.ListTasksForSession("s1")
	if len(tasks) != 1 || tasks[0].ID != t2.ID {
		t.Errorf("after delete tasks = %d, want only t2", len(tasks))
	}

	// Clear all
	if err := d.ClearTasksForSession("s1"); err != nil {
		t.Fatalf("clear tasks: %v", err)
	}
	tasks, _ = d.ListTasksForSession("s1")
	if len(tasks) != 0 {
		t.Errorf("after clear tasks = %d, want 0", len(tasks))
	}
}

// TestNextSessionSeq verifies sequence numbers are monotonic and are never
// reused after a session is deleted: 1,2,3,4 -> delete 3 -> next is 5.
func TestNextSessionSeq(t *testing.T) {
	d, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer d.Close()

	ln, err := d.CreateListener("l", "tcp", "127.0.0.1", 7777, false, "")
	if err != nil {
		t.Fatalf("create listener: %v", err)
	}

	// Simulate the registration flow: allocate a seq, then store the session.
	create := func(id string) int {
		seq, err := d.NextSessionSeq()
		if err != nil {
			t.Fatalf("NextSessionSeq: %v", err)
		}
		if err := d.CreateSession(&SessionRow{ID: id, Seq: seq, ListenerID: ln.ID, FirstSeen: time.Now(), LastSeen: time.Now()}); err != nil {
			t.Fatalf("create session: %v", err)
		}
		return seq
	}

	s1 := create("s1")
	s2 := create("s2")
	s3 := create("s3")
	s4 := create("s4")
	if s1 != 1 || s2 != 2 || s3 != 3 || s4 != 4 {
		t.Fatalf("seqs = %d,%d,%d,%d, want 1,2,3,4", s1, s2, s3, s4)
	}

	// Delete one session; the remaining numbers must be unchanged.
	if err := d.DeleteSession("s3"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	rows, err := d.ListSessions("")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	byID := map[string]int{}
	for _, r := range rows {
		byID[r.ID] = r.Seq
	}
	if byID["s1"] != 1 || byID["s2"] != 2 || byID["s4"] != 4 {
		t.Fatalf("after delete seqs = %v, want s1=1 s2=2 s4=4", byID)
	}

	// A new session must not reuse the deleted number (3) -> next is 5.
	s5 := create("s5")
	if s5 != 5 {
		t.Fatalf("new session seq = %d, want 5 (no reuse)", s5)
	}
}
