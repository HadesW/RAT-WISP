package server

import (
	"testing"
	"time"
)

func TestRateLimiterPerIP(t *testing.T) {
	// 3 connections / window per IP
	rl := newRateLimiter(3, time.Hour, 100)

	ip := "1.2.3.4"
	for i := 0; i < 3; i++ {
		if !rl.allow(ip) {
			t.Fatalf("connection %d should be allowed", i+1)
		}
	}
	// 4th connection in the same window must be rejected
	if rl.allow(ip) {
		t.Error("4th connection within the window should be rejected")
	}

	// A different IP is unaffected
	if !rl.allow("5.6.7.8") {
		t.Error("different IP should be allowed")
	}
}

func TestRateLimiterWindowReset(t *testing.T) {
	rl := newRateLimiter(2, 50*time.Millisecond, 100)

	if !rl.allow("ip1") || !rl.allow("ip1") {
		t.Fatal("first two connections should be allowed")
	}
	if rl.allow("ip1") {
		t.Fatal("third connection should be rejected")
	}

	time.Sleep(80 * time.Millisecond)
	if !rl.allow("ip1") {
		t.Error("window should have reset and allowed a new connection")
	}
}

func TestRateLimiterGlobalCap(t *testing.T) {
	// Global cap of 2 concurrent connections across all IPs
	rl := newRateLimiter(100, time.Hour, 2)

	if !rl.allow("a") || !rl.allow("b") {
		t.Fatal("first two connections should be allowed")
	}
	if rl.allow("c") {
		t.Error("third connection should hit the global cap")
	}

	// Releasing frees a slot
	rl.release()
	if !rl.allow("c") {
		t.Error("after release a new connection should be allowed")
	}
}

func TestRateLimiterRelease(t *testing.T) {
	rl := newRateLimiter(100, time.Hour, 1)
	if !rl.allow("x") {
		t.Fatal("first connection should be allowed")
	}
	rl.release()
	if !rl.allow("x") {
		t.Error("after release the slot should be free")
	}
	// Release below zero must not panic
	rl.release()
	rl.release()
}
