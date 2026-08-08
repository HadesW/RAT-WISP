package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecLsJSON(t *testing.T) {
	d := NewDispatcher(nil, nil)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0644)
	os.Mkdir(filepath.Join(dir, "sub"), 0755)

	out := d.execLsJSON(jsonArgs(t, map[string]string{"path": dir}))

	var result struct {
		Cwd     string `json:"cwd"`
		Path    string `json:"path"`
		Entries []struct {
			Name  string `json:"name"`
			IsDir bool   `json:"is_dir"`
			Size  int64  `json:"size"`
			Mod   string `json:"mod"`
		} `json:"entries"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("ls output is not valid JSON: %v\n%s", err, out)
	}
	if result.Path == "" {
		t.Error("path should be resolved")
	}
	var foundFile, foundDir bool
	for _, e := range result.Entries {
		if e.Name == "a.txt" && !e.IsDir && e.Size == 5 {
			foundFile = true
		}
		if e.Name == "sub" && e.IsDir {
			foundDir = true
		}
	}
	if !foundFile || !foundDir {
		t.Errorf("entries missing: file=%v dir=%v (%+v)", foundFile, foundDir, result.Entries)
	}
}

func TestExecLsJSONMissingDir(t *testing.T) {
	d := NewDispatcher(nil, nil)
	out := d.execLsJSON(jsonArgs(t, map[string]string{"path": filepath.Join(t.TempDir(), "nope")}))
	if !strings.Contains(out, "error") {
		t.Errorf("expected error for missing dir, got %q", out)
	}
}

func TestExecMkdirRmRename(t *testing.T) {
	d := NewDispatcher(nil, nil)
	base := t.TempDir()

	newDir := filepath.Join(base, "new", "nested")
	if out := d.execMkdir(jsonArgs(t, map[string]string{"path": newDir})); !strings.Contains(out, "directory created") {
		t.Fatalf("mkdir output = %q", out)
	}
	if _, err := os.Stat(newDir); err != nil {
		t.Fatalf("mkdir did not create dir: %v", err)
	}

	// Rename
	src := filepath.Join(base, "old.txt")
	dst := filepath.Join(base, "new.txt")
	os.WriteFile(src, []byte("x"), 0644)
	if out := d.execRename(jsonArgs(t, map[string]string{"old_path": src, "new_path": dst})); !strings.Contains(out, "renamed") {
		t.Fatalf("rename output = %q", out)
	}
	if _, err := os.Stat(dst); err != nil {
		t.Fatalf("rename failed: %v", err)
	}

	// Remove (file)
	if out := d.execRm(jsonArgs(t, map[string]string{"path": dst})); !strings.Contains(out, "removed") {
		t.Fatalf("rm output = %q", out)
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Errorf("rm did not remove file: %v", err)
	}

	// Remove (directory tree)
	if out := d.execRm(jsonArgs(t, map[string]string{"path": newDir})); !strings.Contains(out, "removed") {
		t.Fatalf("rm dir output = %q", out)
	}
}

func TestExecMkdirTraversal(t *testing.T) {
	d := NewDispatcher(nil, nil)
	out := d.execMkdir(jsonArgs(t, map[string]string{"path": `C:\..\..\evil`}))
	if !strings.Contains(out, "path traversal") {
		t.Errorf("expected traversal rejection, got %q", out)
	}
}

func TestExecRenameValidation(t *testing.T) {
	d := NewDispatcher(nil, nil)
	if out := d.execRename(`{}`); !strings.Contains(out, "old_path") {
		t.Errorf("expected validation error, got %q", out)
	}
}
