package core

import (
	"path/filepath"
	"testing"
	"time"

	"wispp/protocol"
	"wispp/server/internal/db"
)

func TestRestoreHistory(t *testing.T) {
	store, err := db.Open(filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.DB.Close()

	last := time.Now().Add(-time.Hour).Truncate(time.Second)
	info := protocol.SystemInfo{Hostname: "restored", OS: "windows", Arch: "amd64", User: "admin"}
	if err := store.UpsertSession("hist0001", "default", info, last.Add(-time.Minute), last, 7, "online", 12); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkAllSessionsOffline(); err != nil {
		t.Fatal(err)
	}

	h := NewHub(store)
	if err := h.RestoreHistory(); err != nil {
		t.Fatal(err)
	}
	views := h.Sessions("")
	if len(views) != 1 {
		t.Fatalf("sessions = %d, want 1", len(views))
	}
	got := views[0]
	if got.Status != protocol.StatusOffline || got.Num != 12 || got.Info.Hostname != "restored" {
		t.Fatalf("unexpected restored session: %+v", got)
	}
	if got.LastSeen.Unix() != last.Unix() || got.Seq != 7 {
		t.Fatalf("restored timestamps/seq = %v/%d", got.LastSeen, got.Seq)
	}

	sk, _ := protocol.NewSessionKey()
	h.Register("hist0001", "default", "listener-2", sk, info)
	views = h.Sessions("")
	if views[0].Status != protocol.StatusOnline || views[0].Num != 12 || views[0].Listener != "listener-2" {
		t.Fatalf("reconnect lost history: %+v", views[0])
	}
}

func TestKeyRejectsRestoredSession(t *testing.T) {
	h := NewHub(nil)
	h.sessions["old"] = &Session{ID: "old"} // restored history: no session key
	if _, ok := h.Key("old"); ok {
		t.Fatal("restored session without key reported as live")
	}
	sk, err := protocol.NewSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	h.Register("new", "default", "", sk, protocol.SystemInfo{})
	if got, ok := h.Key("new"); !ok || got != sk {
		t.Fatalf("registered key = %v ok=%v", got, ok)
	}
}

func TestRekeyGrace(t *testing.T) {
	h := NewHub(nil)
	sk1, _ := protocol.NewSessionKey()
	sk2, _ := protocol.NewSessionKey()
	info := protocol.SystemInfo{Hostname: "h"}
	h.Register("rot", "default", "l1", sk1, info)
	if _, ok := h.GraceKey("rot"); ok {
		t.Fatal("no grace window before rotation")
	}
	h.Register("rot", "default", "l1", sk2, info) // operator rekey
	if cur, ok := h.Key("rot"); !ok || cur != sk2 {
		t.Fatalf("current key not updated: %+v", cur)
	}
	if g, ok := h.GraceKey("rot"); !ok || g != sk1 {
		t.Fatal("previous key should remain available inside the grace window")
	}
}
