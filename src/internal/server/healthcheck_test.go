package server

import (
	"testing"
	"time"

	"github.com/user/wisp/internal/db"
	"github.com/user/wisp/shared/protocol"
)

// newTestServer builds a Server backed by a temp database.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	database, err := db.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	// sessions have a FK on listeners(id); create a listener the seeds can use
	if _, err := database.CreateListener("l1", "tcp", "127.0.0.1", 4444, false, ""); err != nil {
		t.Fatalf("seed listener: %v", err)
	}

	s, err := New(database, nil)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return s
}

func seedSession(t *testing.T, s *Server, id string, lastSeen time.Time) {
	t.Helper()
	listeners, err := s.db.ListListeners()
	if err != nil || len(listeners) == 0 {
		t.Fatalf("no listener available for FK: %v", err)
	}
	now := time.Now()
	row := &db.SessionRow{
		ID:            id,
		ListenerID:    listeners[0].ID,
		ExternalIP:    "1.2.3.4",
		InternalIP:    "10.0.0.5",
		Hostname:      "host-" + id,
		Username:      "user",
		SleepInterval: 5000,
		FirstSeen:     now,
		LastSeen:      lastSeen,
		Status:        protocol.StatusAlive,
	}
	if err := s.db.CreateSession(row); err != nil {
		t.Fatalf("seed session: %v", err)
	}
}

func getStatus(t *testing.T, s *Server, id string) string {
	t.Helper()
	row, err := s.db.GetSession(id)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	return row.Status
}

// TestCheckDeadSessionsStaleDBOnly covers sessions that only exist in the
// database (not in memory, e.g. from a previous run): they must be marked dead.
func TestCheckDeadSessionsStaleDBOnly(t *testing.T) {
	s := newTestServer(t)

	seedSession(t, s, "stale", time.Now().Add(-10*time.Minute))
	seedSession(t, s, "fresh", time.Now())

	s.checkDeadSessions()

	if got := getStatus(t, s, "stale"); got != protocol.StatusDead {
		t.Errorf("stale db-only session status = %q, want %q", got, protocol.StatusDead)
	}
	if got := getStatus(t, s, "fresh"); got != protocol.StatusAlive {
		t.Errorf("fresh db-only session status = %q, want %q", got, protocol.StatusAlive)
	}
}

// TestCheckDeadSessionsInMemory uses the in-memory LastSeen when available.
func TestCheckDeadSessionsInMemory(t *testing.T) {
	s := newTestServer(t)

	// Session exists in DB with a stale timestamp but is alive in memory
	seedSession(t, s, "mem", time.Now().Add(-10*time.Minute))
	s.sessions["mem"] = &AgentSession{
		Info: &db.SessionRow{
			ID:            "mem",
			SleepInterval: 5000,
			Status:        protocol.StatusAlive,
		},
		LastSeen: time.Now(),
	}

	s.checkDeadSessions()

	if got := getStatus(t, s, "mem"); got != protocol.StatusAlive {
		t.Errorf("in-memory alive session marked %q, want %q", got, protocol.StatusAlive)
	}
}

// TestCheckDeadSessionsShortSleep ensures the minimum timeout floor applies.
func TestCheckDeadSessionsShortSleep(t *testing.T) {
	s := newTestServer(t)

	// Sleep 100ms but last seen 10s ago -> still over the 30s floor
	listeners, err := s.db.ListListeners()
	if err != nil || len(listeners) == 0 {
		t.Fatalf("no listener available for FK: %v", err)
	}
	row := &db.SessionRow{
		ID:            "short",
		ListenerID:    listeners[0].ID,
		SleepInterval: 100,
		FirstSeen:     time.Now().Add(-1 * time.Hour),
		LastSeen:      time.Now().Add(-10 * time.Second),
		Status:        protocol.StatusAlive,
	}
	if err := s.db.CreateSession(row); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	s.checkDeadSessions()

	if got := getStatus(t, s, "short"); got != protocol.StatusAlive {
		t.Errorf("session within 30s floor marked %q, want %q", got, protocol.StatusAlive)
	}
}
