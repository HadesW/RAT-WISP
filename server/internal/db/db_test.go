package db

import (
	"testing"
	"time"

	"wispp/protocol"
)

func TestStoreRoundTrip(t *testing.T) {
	s, err := Open(t.TempDir() + "/x.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()

	info := protocol.SystemInfo{Hostname: "h1", OS: "win", Arch: "amd64", User: "u"}
	now := time.Now()
	if err := s.UpsertSession("a1", "default", info, now, now, 3, "online", 7); err != nil {
		t.Fatal(err)
	}
	// refresh
	if err := s.UpsertSession("a1", "default", info, now, now.Add(time.Second), 4, "idle", 0); err != nil {
		t.Fatal(err)
	}
	rows, err := s.Sessions("default")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Seq != 4 || rows[0].Status != "idle" {
		t.Fatalf("bad row: %+v", rows)
	}
	if rows[0].Num != 7 {
		t.Fatalf("num lost on upsert with num=0: %+v", rows[0])
	}
	if got := s.SessionNum("a1"); got != 7 {
		t.Fatalf("SessionNum=%d want 7", got)
	}
	// counter monotonic & survives deletes
	n1, _ := s.NextCounter("session")
	if err := s.DeleteSession("a1"); err != nil {
		t.Fatal(err)
	}
	n2, _ := s.NextCounter("session")
	if n2 <= n1 {
		t.Fatalf("counter reused after delete: %d -> %d", n1, n2)
	}
	if s.SessionNum("a1") != 0 {
		t.Fatal("deleted session still has a number")
	}
	// project isolation
	if err := s.EnsureProject("p2", "Op2", "#f00"); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSession("b2", "p2", info, now, now, 1, "online", 9); err != nil {
		t.Fatal(err)
	}
	rows, _ = s.Sessions("p2")
	if len(rows) != 1 || rows[0].ID != "b2" {
		t.Fatalf("project leak: %+v", rows)
	}

	if err := s.TaskCreated("t1", "a1", "default", 1, []byte(`{"command":"id"}`)); err != nil {
		t.Fatal(err)
	}
	if err := s.TaskStatus("t1", "completed", "uid=0", 0); err != nil {
		t.Fatal(err)
	}
	if err := s.Audit(time.Now(), "ok", "task", "default", "done"); err != nil {
		t.Fatal(err)
	}
}
