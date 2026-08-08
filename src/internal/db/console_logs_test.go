package db

import (
	"testing"
)

func TestConsoleLogsCRUD(t *testing.T) {
	database, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer database.Close()

	// Insert in chronological order
	entries := []struct{ logType, content string }{
		{"input", "> shell whoami"},
		{"output", "[completed] DESKTOP-ABC\\user"},
		{"output", "[completed] admin"},
	}
	for _, e := range entries {
		if err := database.InsertConsoleLog("s1", e.logType, e.content); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	// Full list in chronological order
	logs, err := database.ListConsoleLogs("s1", 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(logs) != 3 {
		t.Fatalf("log count = %d, want 3", len(logs))
	}
	if logs[0].Content != "> shell whoami" || logs[0].Type != "input" {
		t.Errorf("first log = %+v, want input entry", logs[0])
	}
	if logs[2].Content != "[completed] admin" {
		t.Errorf("last log = %+v, want the last inserted entry", logs[2])
	}

	// Limit keeps the most recent N entries (chronological)
	limited, err := database.ListConsoleLogs("s1", 2)
	if err != nil {
		t.Fatalf("list limited: %v", err)
	}
	if len(limited) != 2 {
		t.Fatalf("limited count = %d, want 2", len(limited))
	}
	if limited[0].Content != "[completed] DESKTOP-ABC\\user" {
		t.Errorf("limited[0] = %q, want 2nd entry", limited[0].Content)
	}
	if limited[1].Content != "[completed] admin" {
		t.Errorf("limited[1] = %q, want 3rd entry", limited[1].Content)
	}

	// Other session unaffected
	other, err := database.ListConsoleLogs("s2", 0)
	if err != nil || len(other) != 0 {
		t.Errorf("other session logs = %d (err %v), want 0", len(other), err)
	}

	// Clear
	if err := database.ClearConsoleLogs("s1"); err != nil {
		t.Fatalf("clear: %v", err)
	}
	cleared, _ := database.ListConsoleLogs("s1", 0)
	if len(cleared) != 0 {
		t.Errorf("after clear count = %d, want 0", len(cleared))
	}
}

func TestListAllConsoleLogs(t *testing.T) {
	database, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer database.Close()

	// Logs from two different sessions
	database.InsertConsoleLog("s1", "input", "> shell whoami")
	database.InsertConsoleLog("s2", "output", "[completed] DESKTOP-A")
	database.InsertConsoleLog("s1", "output", "[completed] admin")

	all, err := database.ListAllConsoleLogs(0)
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("all count = %d, want 3", len(all))
	}
	if all[0].SessionID != "s1" || all[0].Content != "> shell whoami" {
		t.Errorf("first log = %+v, want s1 input", all[0])
	}
	if all[2].SessionID != "s1" || all[2].Content != "[completed] admin" {
		t.Errorf("last log = %+v, want s1 last", all[2])
	}

	// Limit takes the most recent N (chronological)
	limited, err := database.ListAllConsoleLogs(2)
	if err != nil {
		t.Fatalf("limited: %v", err)
	}
	if len(limited) != 2 {
		t.Fatalf("limited count = %d, want 2", len(limited))
	}
	if limited[1].Content != "[completed] admin" {
		t.Errorf("limited last = %q, want the newest log", limited[1].Content)
	}
}
