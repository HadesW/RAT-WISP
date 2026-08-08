package commands

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecUploadWritesChunks(t *testing.T) {
	d := NewDispatcher(nil, nil)
	dir := t.TempDir()
	target := filepath.Join(dir, "sub", "payload.bin")

	content := []byte("chunk-0-data")
	blk := uploadBlock{
		Path:  target,
		Index: 0,
		Total: 2,
		Data:  base64.StdEncoding.EncodeToString(content),
	}
	args, _ := json.Marshal(blk)

	if out := d.execUpload(string(args)); !strings.Contains(out, "chunk 1/2") {
		t.Fatalf("first chunk output = %q", out)
	}

	// Second chunk appends
	blk.Index = 1
	blk.Data = base64.StdEncoding.EncodeToString([]byte("-chunk-1-data"))
	args, _ = json.Marshal(blk)
	if out := d.execUpload(string(args)); !strings.Contains(out, "upload complete") {
		t.Fatalf("last chunk output = %q", out)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	want := "chunk-0-data-chunk-1-data"
	if string(got) != want {
		t.Errorf("file content = %q, want %q", got, want)
	}
}

func TestExecUploadRejectsTraversal(t *testing.T) {
	d := NewDispatcher(nil, nil)
	// Use the raw string so filepath normalization cannot strip the ".." parts
	blk := uploadBlock{
		Path:  `C:\..\..\Windows\system32\evil.dll`,
		Index: 0,
		Total: 1,
		Data:  base64.StdEncoding.EncodeToString([]byte("x")),
	}
	args, _ := json.Marshal(blk)
	if out := d.execUpload(string(args)); !strings.Contains(out, "path traversal") {
		t.Errorf("expected traversal rejection, got %q", out)
	}
}

func TestExecDownloadSingleChunk(t *testing.T) {
	d := NewDispatcher(nil, nil)
	dir := t.TempDir()
	file := filepath.Join(dir, "small.txt")
	os.WriteFile(file, []byte("hello world"), 0644)

	task := &Task{ID: "t1", CommandID: CmdDownload, Args: jsonArgs(t, map[string]string{"path": file})}
	res := d.execDownload(task)

	if res.Status != "downloading" {
		t.Errorf("status = %q, want downloading", res.Status)
	}
	var blk downloadBlock
	if err := json.Unmarshal([]byte(res.Output), &blk); err != nil {
		t.Fatalf("parse block: %v", err)
	}
	if blk.Total != 1 {
		t.Errorf("total = %d, want 1", blk.Total)
	}
	data, _ := base64.StdEncoding.DecodeString(blk.Data)
	if string(data) != "hello world" {
		t.Errorf("decoded data = %q, want %q", data, "hello world")
	}
	if got := d.DrainPending(); got != nil {
		t.Errorf("expected no queued chunks for single-chunk file, got %d", len(got))
	}
}

func TestExecDownloadMultiChunkQueuesRest(t *testing.T) {
	d := NewDispatcher(nil, nil)
	dir := t.TempDir()
	file := filepath.Join(dir, "big.bin")

	// ~1.3MB: three chunks of DownloadChunkSize
	size := 2*DownloadChunkSize + 100
	content := make([]byte, size)
	for i := range content {
		content[i] = byte(i % 251)
	}
	os.WriteFile(file, content, 0644)

	task := &Task{ID: "t1", CommandID: CmdDownload, Args: jsonArgs(t, map[string]string{"path": file})}
	res := d.execDownload(task)

	if res.Status != "downloading" {
		t.Fatalf("status = %q, want downloading", res.Status)
	}
	var first downloadBlock
	json.Unmarshal([]byte(res.Output), &first)
	if first.Total != 3 {
		t.Fatalf("total = %d, want 3", first.Total)
	}

	pending := d.DrainPending()
	if len(pending) != 2 {
		t.Fatalf("queued chunks = %d, want 2", len(pending))
	}

	// Reassemble all three chunks and verify content
	chunks := make([][]byte, 3)
	chunks[first.Index] = mustDecode(t, first.Data)
	for _, p := range pending {
		var blk downloadBlock
		if err := json.Unmarshal([]byte(p.Output), &blk); err != nil {
			t.Fatalf("parse queued block: %v", err)
		}
		chunks[blk.Index] = mustDecode(t, blk.Data)
	}

	got := append(chunks[0], chunks[1]...)
	got = append(got, chunks[2]...)
	if string(got) != string(content) {
		t.Error("reassembled content does not match original")
	}
}

func TestExecDownloadMissingFile(t *testing.T) {
	d := NewDispatcher(nil, nil)
	task := &Task{ID: "t1", CommandID: CmdDownload, Args: `{"path":"Z:\\no\\such\\file"}`}
	res := d.execDownload(task)
	if res.Status != "failed" {
		t.Errorf("status = %q, want failed", res.Status)
	}
}

// jsonArgs marshals a map into a task args JSON string (properly escaping
// Windows backslashes).
func jsonArgs(t *testing.T, m map[string]string) string {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal args: %v", err)
	}
	return string(b)
}

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return data
}

func TestHasPathTraversal(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"C:\\Users\\test\\file.txt", false},
		{"C:\\Users\\..\\evil", true},
		{"/etc/../passwd", true},
		{"/home/user/file", false},
		{"../../escape", true},
		{"safe\\name.bin", false},
	}
	for _, c := range cases {
		if got := hasPathTraversal(c.path); got != c.want {
			t.Errorf("hasPathTraversal(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestExtractPathArg(t *testing.T) {
	if got := extractPathArg(`{"path":"C:\\x\\y.bin"}`); got != `C:\x\y.bin` {
		t.Errorf("json path = %q", got)
	}
	if got := extractPathArg(`/plain/path`); got != "/plain/path" {
		t.Errorf("plain path = %q", got)
	}
	if got := extractPathArg(""); got != "" {
		t.Errorf("empty = %q", got)
	}
}
