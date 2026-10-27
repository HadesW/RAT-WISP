package guard

import (
	"testing"
	"time"
)

func TestNoncesRejectsReplay(t *testing.T) {
	n := NewNonces(50 * time.Millisecond)
	if !n.CheckAndAdd("abc") {
		t.Fatal("fresh nonce rejected")
	}
	if n.CheckAndAdd("abc") {
		t.Fatal("replayed nonce accepted")
	}
	if n.CheckAndAdd("") {
		t.Fatal("empty nonce accepted")
	}
	time.Sleep(80 * time.Millisecond)
	if !n.CheckAndAdd("abc") {
		t.Fatal("expired nonce should be reusable")
	}
}
