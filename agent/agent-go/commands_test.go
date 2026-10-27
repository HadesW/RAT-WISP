package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"wispp/protocol"
)

func TestCmdLs(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	args, _ := json.Marshal(protocol.LsArgs{Path: dir})
	res := cmdLs(args)
	if !res.OK {
		t.Fatal(res.Output)
	}
	var out struct {
		Path    string             `json:"path"`
		Entries []protocol.LsEntry `json:"entries"`
	}
	if err := json.Unmarshal([]byte(res.Output), &out); err != nil {
		t.Fatal(err)
	}
	if out.Path != dir || len(out.Entries) != 2 {
		t.Fatalf("bad listing: %+v", out)
	}
	if !out.Entries[0].Dir || out.Entries[0].Name != "sub" { // dirs first
		t.Fatalf("ordering: %+v", out.Entries)
	}
	if out.Entries[1].Size != 5 {
		t.Fatalf("file meta: %+v", out.Entries[1])
	}
}

func TestCmdMkdirRm(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "x", "y")
	a, _ := json.Marshal(protocol.MkdirArgs{Path: target})
	if r := cmdMkdir(a); !r.OK {
		t.Fatal(r.Output)
	}
	if st, err := os.Stat(target); err != nil || !st.IsDir() {
		t.Fatal("mkdir failed")
	}
	r, _ := json.Marshal(protocol.RmArgs{Path: target})
	if res := cmdRm(r); !res.OK {
		t.Fatal(res.Output)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("rm failed")
	}
}

func TestCmdRmRefusesDangerous(t *testing.T) {
	for _, p := range []string{"", "/", "."} {
		a, _ := json.Marshal(protocol.RmArgs{Path: p})
		if res := cmdRm(a); res.OK {
			t.Fatalf("rm %q should be refused", p)
		}
	}
}

func TestCmdPwd(t *testing.T) {
	if r := cmdPwd(); !r.OK || r.Output == "" {
		t.Fatal(r)
	}
}

func TestCmdPs(t *testing.T) {
	r := cmdPs()
	if !r.OK {
		t.Fatal(r.Output)
	}
	var rows []struct {
		Pid  int    `json:"pid"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal([]byte(r.Output), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) < 5 {
		t.Fatalf("too few processes: %d", len(rows))
	}
	self := false
	for _, x := range rows {
		if x.Pid == os.Getpid() {
			self = true
		}
	}
	if !self {
		t.Fatal("own pid missing from ps output")
	}
}
