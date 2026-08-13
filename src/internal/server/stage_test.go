package server

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/user/wisp/internal/db"
)

// TestStagePersistence verifies a stage survives a server restart: the store
// is reconstructed from SQLite so an already-issued stager keeps working.
func TestStagePersistence(t *testing.T) {
	database, err := db.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	s1 := newStageStore(database)
	token, keyB64, err := s1.Issue([]byte("stage2-payload"), 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_ = keyB64

	// "Restart": new store over the same database.
	s2 := newStageStore(database)
	k2, enc, ok := s2.Consume(token)
	if !ok {
		t.Fatal("stage lost across restart")
	}
	if k2 == "" || enc == "" {
		t.Fatal("empty key/enc after restore")
	}
	key, _ := base64.StdEncoding.DecodeString(k2)
	if len(key) != 32 {
		t.Fatalf("key len = %d", len(key))
	}

	// Consumed one-time token is gone even after another restart.
	s3 := newStageStore(database)
	if _, _, ok := s3.Consume(token); ok {
		t.Fatal("one-time token reused after restart")
	}
}

// TestStageReusable verifies a non-one-time stage can be fetched many times
// (same stager deployed to multiple hosts).
func TestStageReusable(t *testing.T) {
	database, err := db.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	s := newStageStore(database)
	token, _, err := s.IssuePersistent([]byte("stage2"), 0, true) // never expires
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		_, _, ok := s.ConsumeRaw(token)
		if !ok {
			t.Fatalf("reusable fetch %d failed", i)
		}
	}
}

// TestStageTTLExpiry verifies a stage with a TTL stops being served after the
// window (0 = never expires).
func TestStageTTLExpiry(t *testing.T) {
	database, err := db.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	s := newStageStore(database)
	token, _, err := s.Issue([]byte("stage2"), 1*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	if _, _, ok := s.Consume(token); ok {
		t.Fatal("expired stage still served")
	}
}
