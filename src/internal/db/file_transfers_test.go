package db

import "testing"

func TestFileTransferCRUD(t *testing.T) {
	d, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer d.Close()

	// FK on sessions requires a seeded session
	seedSessionRow(t, d, "s1", "l1", "h1", "u1", "1.1.1.1", "alive")

	if err := d.CreateFileTransfer("s1", "download", `C:\out\a.bin`, `C:\remote\a.bin`, 0, "started", "task1"); err != nil {
		t.Fatalf("create download: %v", err)
	}
	if err := d.CreateFileTransfer("s1", "upload", `C:\local\b.bin`, `C:\remote\b.bin`, 1024, "started", ""); err != nil {
		t.Fatalf("create upload: %v", err)
	}

	// Update download status via task ID
	if err := d.UpdateFileTransferByTask("task1", "completed", 1048576); err != nil {
		t.Fatalf("update by task: %v", err)
	}

	transfers, err := d.ListFileTransfers(0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(transfers) != 2 {
		t.Fatalf("count = %d, want 2", len(transfers))
	}

	// Newest first
	if transfers[0].Direction != "upload" {
		t.Errorf("newest transfer = %+v, want upload", transfers[0])
	}
	// Updated download record
	for _, tr := range transfers {
		if tr.Direction == "download" {
			if tr.Status != "completed" || tr.Size != 1048576 {
				t.Errorf("download transfer not updated: %+v", tr)
			}
		}
	}

	// Limit
	limited, _ := d.ListFileTransfers(1)
	if len(limited) != 1 {
		t.Errorf("limited count = %d, want 1", len(limited))
	}
}

func TestGetAllTasks(t *testing.T) {
	d := newDBWithSession(t)

	d.CreateTask("s1", 1, `{"cmd":"whoami"}`)
	t2, _ := d.CreateTask("s1", 2, `{}`)
	d.CreateTask("s1", 3, `x`)
	if err := d.CompleteTask(t2.ID, "some-result", "completed"); err != nil {
		t.Fatalf("complete: %v", err)
	}

	tasks, err := d.ListTasks(0)
	if err != nil {
		t.Fatalf("list tasks: %v", err)
	}
	if len(tasks) != 3 {
		t.Fatalf("count = %d, want 3", len(tasks))
	}
	// Encrypted result round-trips through the global list
	found := false
	for _, t := range tasks {
		if t.ID == t2.ID && t.Result == "some-result" && t.Status == "completed" {
			found = true
		}
	}
	if !found {
		t.Error("completed task with decrypted result not found in global list")
	}
}
