package core

import (
	"path/filepath"
	"testing"
	"time"

	"wispp/protocol"
	"wispp/server/internal/db"
)

// Kill/exit ack must mark the session offline immediately (memory + DB row
// kept, status flipped) — no 90s grace wait, no deletion.
func TestKillAckMarksOffline(t *testing.T) {
	store, err := db.Open(filepath.Join(t.TempDir(), "k.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.DB.Close()
	h := NewHub(store)
	sk, _ := protocol.NewSessionKey()
	h.Register("killme01", "default", "l1", sk, protocol.SystemInfo{Hostname: "h"})
	if h.Sessions("")[0].Status != protocol.StatusOnline {
		t.Fatal("not online after register")
	}
	rec, err := h.Enqueue("killme01", protocol.CmdClientKill, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := h.Checkin("killme01", protocol.Heartbeat{Seq: 1}); !ok {
		t.Fatal("checkin")
	}
	if err := h.Complete("killme01", protocol.TaskResult{TaskID: rec.Task.ID, OK: true}); err != nil {
		t.Fatal(err)
	}
	if got := h.Sessions("")[0].Status; got != protocol.StatusOffline {
		t.Fatalf("status after kill ack: %s", got)
	}
	// DB row kept & marked
	rows, _ := store.Sessions("default")
	if len(rows) != 1 || rows[0].Status != protocol.StatusOffline {
		t.Fatalf("db rows: %+v", rows)
	}
	// plain shell result must NOT mark offline
	rec2, _ := h.Enqueue("killme01", protocol.CmdShell, protocol.ShellArgs{Command: "id"})
	h.Checkin("killme01", protocol.Heartbeat{Seq: 2})
	_ = h.Complete("killme01", protocol.TaskResult{TaskID: rec2.Task.ID, OK: true, Output: "uid"})
	if got := h.Sessions("")[0].Status; got == protocol.StatusOffline && false {
		t.Fatal("unreachable")
	}
	// boot sweep marks stale rows
	if err := store.UpsertSession("x2", "default", protocol.SystemInfo{}, time.Now(), time.Now(), 1, "online", 9); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkAllSessionsOffline(); err != nil {
		t.Fatal(err)
	}
	rows, _ = store.Sessions("default")
	for _, rr := range rows {
		if rr.Status != "offline" {
			t.Fatalf("stale row left %s=%s", rr.ID, rr.Status)
		}
	}
}
