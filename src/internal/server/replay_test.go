package server

import (
	"testing"
)

func TestAcceptSeqMonotonic(t *testing.T) {
	as := &AgentSession{}

	if !as.acceptSeq(1) {
		t.Fatal("first seq should be accepted")
	}
	if !as.acceptSeq(2) {
		t.Fatal("increasing seq should be accepted")
	}
	if !as.acceptSeq(5) {
		t.Fatal("increasing seq should be accepted")
	}
	// Replay of an old sequence must be rejected
	if as.acceptSeq(2) {
		t.Error("replayed seq should be rejected")
	}
	if as.acceptSeq(5) {
		t.Error("duplicate seq should be rejected")
	}
	// Zero is never valid
	if as.acceptSeq(0) {
		t.Error("zero seq should be rejected")
	}
}

func TestProcessCheckinReplayRejected(t *testing.T) {
	s := newTestServer(t)
	ln, err := s.db.CreateListener("replay-l", "tcp", "127.0.0.1", 7101, false, "")
	if err != nil {
		t.Fatalf("create listener: %v", err)
	}

	// Register the agent (seq is set up by registering a session manually)
	keys, ack, err := s.processRegistration(buildRegPayload(t, s, ""), ln.ID, "9.9.9.9")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	_ = ack
	_ = keys

	// First checkin with seq 1 succeeds
	if _, err := s.processCheckin("agent-psk-1", 1, nil); err != nil {
		t.Fatalf("first checkin: %v", err)
	}
	// Replaying seq 1 must fail
	if _, err := s.processCheckin("agent-psk-1", 1, nil); err == nil {
		t.Error("replayed checkin should be rejected")
	}
	// A fresh seq succeeds
	if _, err := s.processCheckin("agent-psk-1", 2, nil); err != nil {
		t.Errorf("next checkin should succeed: %v", err)
	}
}
