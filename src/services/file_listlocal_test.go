package services

import (
	"os"
	"path/filepath"
	"testing"
)

func TestListLocalDir(t *testing.T) {
	ss, _ := newTestSessionService(t)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0644)
	os.WriteFile(filepath.Join(dir, "b.bin"), make([]byte, 2048), 0644)
	os.Mkdir(filepath.Join(dir, "sub"), 0755)

	items, err := ss.ListLocalDir(dir)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(items) != 3 {
		t.Fatalf("count = %d, want 3", len(items))
	}
	byName := map[string]LocalEntry{}
	for _, it := range items {
		byName[it.Name] = it
	}
	if _, ok := byName["a.txt"]; !ok {
		t.Error("missing a.txt")
	}
	if byName["b.bin"].Size != 2048 {
		t.Errorf("b.bin size = %d", byName["b.bin"].Size)
	}
	if !byName["sub"].IsDir {
		t.Errorf("sub isDir = false")
	}
}

func TestListLocalDirErrors(t *testing.T) {
	ss, _ := newTestSessionService(t)
	if _, err := ss.ListLocalDir(""); err == nil {
		t.Error("empty path should fail")
	}
	if _, err := ss.ListLocalDir("Z:\\definitely\\missing\\nope"); err == nil {
		t.Error("missing dir should fail")
	}
}
