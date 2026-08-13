package server

import (
	"testing"

	"github.com/user/wisp/internal/db"
)

// TestCanaryBurn verifies RecordCanaryBurn marks a registered token as burned,
// emits the burn event once, and ignores repeats/unknown tokens.
func TestCanaryBurn(t *testing.T) {
	database, err := db.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	var emitted []map[string]any
	srv, err := New(database, &testEmitter{fn: func(name string, data ...any) {
		if name == "canary:burn" && len(data) > 0 {
			if m, ok := data[0].(map[string]any); ok {
				emitted = append(emitted, m)
			}
		}
	}})
	if err != nil {
		t.Fatal(err)
	}

	if err := srv.IssueCanary("tok123", "build-test"); err != nil {
		t.Fatalf("IssueCanary: %v", err)
	}

	// First hit burns it.
	if !srv.RecordCanaryBurn("tok123", "10.0.0.9") {
		t.Fatal("first burn should succeed")
	}
	// A second hit is a no-op (already burned).
	if srv.RecordCanaryBurn("tok123", "10.0.0.9") {
		t.Fatal("second burn should be a no-op")
	}
	// Unknown token is a no-op.
	if srv.RecordCanaryBurn("nope", "1.2.3.4") {
		t.Fatal("unknown token should not burn")
	}

	row, err := database.GetCanary("tok123")
	if err != nil {
		t.Fatal(err)
	}
	if row.Status != "burned" || row.RemoteIP != "10.0.0.9" {
		t.Fatalf("canary row = %+v", row)
	}
	if len(emitted) != 1 {
		t.Fatalf("expected 1 burn event, got %d", len(emitted))
	}
	if emitted[0]["token"] != "tok123" {
		t.Fatalf("event = %+v", emitted[0])
	}
}

type testEmitter struct {
	fn func(name string, data ...any)
}

func (e *testEmitter) EmitEvent(name string, data ...any) {
	if e.fn != nil {
		e.fn(name, data...)
	}
}
