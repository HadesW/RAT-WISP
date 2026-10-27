package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"wispp/protocol"
)

func TestXferRoundtripAndAuth(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.bin")
	data := make([]byte, 70000)
	for i := range data {
		data[i] = byte(i * 7)
	}
	if err := os.WriteFile(src, data, 0o600); err != nil {
		t.Fatal(err)
	}
	// happy path
	addr, err := xferServe(&protocol.XferServeArgs{Addr: "127.0.0.1:0", Path: src, Nonce: "n1"}, "psk-x")
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "dst.bin")
	fr, err := xferFetch(&protocol.XferFetchArgs{Addr: addr, Nonce: "n1", Local: dst}, "psk-x")
	if err != nil {
		t.Fatal(err)
	}
	if fr.Bytes != int64(len(data)) {
		t.Fatalf("bytes %d", fr.Bytes)
	}
	got, _ := os.ReadFile(dst)
	if string(got) != string(data) {
		t.Fatal("content mismatch")
	}
	// wrong proof: serve must drop silently, fetch must fail
	addr2, err := xferServe(&protocol.XferServeArgs{Addr: "127.0.0.1:0", Path: src, Nonce: "n2"}, "psk-x")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := xferFetch(&protocol.XferFetchArgs{Addr: addr2, Nonce: "evil", Local: filepath.Join(dir, "nope.bin")}, "psk-x")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("wrong proof must fail")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("fetch hung on wrong proof")
	}
	if _, err := os.Stat(filepath.Join(dir, "nope.bin")); err == nil {
		t.Fatal("unauthenticated fetch wrote a file")
	}
}
