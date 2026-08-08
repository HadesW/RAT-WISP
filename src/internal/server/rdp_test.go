package server

import (
	"testing"

	"github.com/user/wisp/internal/db"
)

type namedEvent struct {
	name string
	data map[string]string
}

type namedEmitter struct {
	events []namedEvent
}

func (n *namedEmitter) EmitEvent(name string, data ...any) {
	if len(data) > 0 {
		if m, ok := data[0].(map[string]string); ok {
			n.events = append(n.events, namedEvent{name: name, data: m})
		}
	}
}

func newRDPTestServer(t *testing.T) (*Server, *namedEmitter) {
	t.Helper()
	database, err := db.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	if _, err := database.CreateListener("l1", "tcp", "127.0.0.1", 4444, false, ""); err != nil {
		t.Fatalf("seed listener: %v", err)
	}
	em := &namedEmitter{}
	s, err := New(database, em)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return s, em
}

func TestRDPFrameForwardedToFrontend(t *testing.T) {
	s, em := newRDPTestServer(t)
	frame := `{"seq":1,"w":1920,"h":1080,"data":"abc123"}`

	s.CompleteTask("rdp:sess-1", frame, rdpFrameStatus)

	if len(em.events) != 1 {
		t.Fatalf("events = %d, want 1", len(em.events))
	}
	if em.events[0].name != "rdp:frame" {
		t.Errorf("event name = %q, want rdp:frame", em.events[0].name)
	}
	if em.events[0].data["session_id"] != "sess-1" || em.events[0].data["frame"] != frame {
		t.Errorf("event data = %+v", em.events[0].data)
	}

	// The synthetic task id must not be persisted
	if _, err := s.db.GetTask("rdp:sess-1"); err == nil {
		t.Error("rdp frame task should not exist in the database")
	}
}

func TestRDPFrameNonRdpPrefixIgnored(t *testing.T) {
	s, em := newRDPTestServer(t)
	s.CompleteTask("normal-task", `{"seq":1}`, rdpFrameStatus)
	if len(em.events) != 0 {
		t.Errorf("unexpected events: %+v", em.events)
	}
}
