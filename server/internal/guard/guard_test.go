package guard

import (
	"testing"
	"time"
)

func TestBanWindow(t *testing.T) {
	b := NewBan(60*time.Second, 3, 0)
	ip := "1.2.3.4"
	if b.Blocked(ip) {
		t.Fatal("blocked before failures")
	}
	for i := 0; i < 2; i++ {
		if b.Fail(ip) {
			t.Fatal("banned too early")
		}
	}
	if !b.Fail(ip) {
		t.Fatal("3rd failure should ban")
	}
	if !b.Blocked(ip) {
		t.Fatal("not blocked after ban")
	}
	if b.Blocked("5.6.7.8") {
		t.Fatal("unrelated IP banned")
	}
}

func TestToken(t *testing.T) {
	if CheckToken("x", "y") || CheckToken("", "y") || CheckToken("x", "") {
		t.Fatal("bad token accepted")
	}
	if !CheckToken("secret", "secret") {
		t.Fatal("good token rejected")
	}
}
