package db

import (
	"path/filepath"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "f.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.DB.Close() })
	return s
}

func TestDeliveryStore(t *testing.T) {
	s := testStore(t)
	now := time.Now().Unix()
	d := Delivery{ID: "d1", Token: "tok", Payload: "p1", Name: "a.bin", File: "/tmp/a",
		Project: "default", ExpiresAt: now + 60, MaxDownloads: 1, Created: now}
	if err := s.DeliveryCreate(d); err != nil {
		t.Fatal(err)
	}
	got, err := s.DeliveryByTokenHash(TokenHash("tok"))
	if err != nil || got == nil || got.ID != "d1" {
		t.Fatalf("lookup: %+v %v", got, err)
	}
	if ok, err := s.DeliveryClaim("d1", now, true); err != nil || !ok {
		t.Fatalf("first claim: %v %v", ok, err)
	}
	if ok, _ := s.DeliveryClaim("d1", now, true); ok {
		t.Fatal("limit not enforced")
	}
	if ok, _ := s.DeliveryClaim("d1", now, false); !ok {
		t.Fatal("HEAD claim should still pass under limit")
	}
	s.DeliveryAddBytes("d1", 12)
	list, _ := s.Deliveries("default")
	if len(list) != 1 || list[0].Downloads != 1 || list[0].BytesOut != 12 {
		t.Fatalf("stats: %+v", list)
	}
	max := 5
	ct := "text/plain"
	if err := s.DeliveryPatch("d1", nil, &max, &ct, nil); err != nil {
		t.Fatal(err)
	}
	list, _ = s.Deliveries("")
	if list[0].MaxDownloads != 5 || list[0].ContentType != "text/plain" {
		t.Fatalf("patch: %+v", list[0])
	}
	if err := s.DeliveryDelete("d1"); err != nil {
		t.Fatal(err)
	}
	if list, _ := s.Deliveries(""); len(list) != 0 {
		t.Fatalf("delete: %+v", list)
	}
}

func TestShareStore(t *testing.T) {
	s := testStore(t)
	now := time.Now().Unix()
	sh := Share{ID: "s1", Token: "stok", Name: "r.txt", File: "docs/r.txt",
		Project: "default", PasswordHash: "hash", HasPassword: true, Created: now}
	if err := s.ShareCreate(sh); err != nil {
		t.Fatal(err)
	}
	got, err := s.ShareByTokenHash(TokenHash("stok"))
	if err != nil || got == nil || !got.HasPassword {
		t.Fatalf("lookup: %+v %v", got, err)
	}
	if ok, _ := s.ShareClaim("s1", now, true); !ok {
		t.Fatal("claim failed")
	}
	s.ShareAddBytes("s1", 3)
	past := now - 10
	if err := s.SharePatch("s1", &past, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.ShareClaim("s1", now, true); ok {
		t.Fatal("expired claim accepted")
	}
	list, _ := s.Shares("default")
	if len(list) != 1 || list[0].Downloads != 1 || list[0].BytesOut != 3 {
		t.Fatalf("stats: %+v", list)
	}
	revoked := true
	_ = s.SharePatch("s1", nil, nil, nil, &revoked)
	list, _ = s.Shares("")
	if !list[0].Revoked {
		t.Fatalf("revoke: %+v", list[0])
	}
	if err := s.ShareDelete("s1"); err != nil {
		t.Fatal(err)
	}
}
