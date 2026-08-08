package services

import (
	"encoding/json"
	"testing"

	"github.com/user/wisp/shared/protocol"
)

func TestFileAPICreatesTasks(t *testing.T) {
	ss, database := newTestSessionService(t)
	seedTestSession(t, database)

	taskID, err := ss.FileList("sess1", `C:\Users`)
	if err != nil {
		t.Fatalf("file list: %v", err)
	}
	task, err := database.GetTask(taskID)
	if err != nil {
		t.Fatalf("get task: %v", err)
	}
	if task.CommandID != int(protocol.CmdLsJSON) {
		t.Errorf("command = %d, want lsjson", task.CommandID)
	}
	var args map[string]string
	json.Unmarshal([]byte(task.Args), &args)
	if args["path"] != `C:\Users` {
		t.Errorf("args path = %q", args["path"])
	}
}

func TestFileManagementCommands(t *testing.T) {
	ss, database := newTestSessionService(t)
	seedTestSession(t, database)

	cases := []struct {
		name string
		cmd  int
		do   func() (string, error)
	}{
		{"mkdir", int(protocol.CmdMkdir), func() (string, error) { return ss.FileMkdir("sess1", `C:\tmp\new`) }},
		{"rm", int(protocol.CmdRm), func() (string, error) { return ss.FileRemove("sess1", `C:\tmp\old`) }},
		{"rename", int(protocol.CmdRename), func() (string, error) { return ss.FileRename("sess1", `C:\a`, `C:\b`) }},
		{"exec", int(protocol.CmdExecFile), func() (string, error) { return ss.FileExec("sess1", `C:\Tools\agent.exe`) }},
	}
	for _, c := range cases {
		taskID, err := c.do()
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		task, err := database.GetTask(taskID)
		if err != nil {
			t.Fatalf("%s get task: %v", c.name, err)
		}
		if task.CommandID != c.cmd {
			t.Errorf("%s command = %d, want %d", c.name, task.CommandID, c.cmd)
		}
	}
}

func TestFileAPITraversalRejected(t *testing.T) {
	ss, database := newTestSessionService(t)
	seedTestSession(t, database)

	if _, err := ss.FileMkdir("sess1", `C:\..\..\evil`); err == nil {
		t.Error("mkdir traversal should be rejected")
	}
	if _, err := ss.FileRemove("sess1", `..\evil`); err == nil {
		t.Error("rm traversal should be rejected")
	}
	if _, err := ss.FileRename("sess1", `C:\a`, `C:\..\b`); err == nil {
		t.Error("rename traversal should be rejected")
	}
	if _, err := ss.FileList("missing-session", `C:\`); err == nil {
		t.Error("missing session should be rejected")
	}
}

func TestIshellAPI(t *testing.T) {
	ss, database := newTestSessionService(t)
	seedTestSession(t, database)

	cases := []struct {
		name string
		cmd  int
		do   func() (string, error)
	}{
		{"open", int(protocol.CmdIshellOpen), func() (string, error) { return ss.IshellOpen("sess1", "cmd") }},
		{"run", int(protocol.CmdIshellRun), func() (string, error) { return ss.IshellRun("sess1", "whoami") }},
		{"close", int(protocol.CmdIshellClose), func() (string, error) { return ss.IshellClose("sess1") }},
	}
	for _, c := range cases {
		taskID, err := c.do()
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		task, err := database.GetTask(taskID)
		if err != nil {
			t.Fatalf("%s get task: %v", c.name, err)
		}
		if task.CommandID != c.cmd {
			t.Errorf("%s command = %d, want %d", c.name, task.CommandID, c.cmd)
		}
	}

	// Missing session is rejected
	if _, err := ss.IshellOpen("nope", "cmd"); err == nil {
		t.Error("missing session should be rejected")
	}
}

// Ensure file operations still write console logs.
func TestFileAPIWritesConsoleLog(t *testing.T) {
	ss, database := newTestSessionService(t)
	seedTestSession(t, database)

	ss.FileList("sess1", `C:\`)
	logs, err := database.ListConsoleLogs("sess1", 0)
	if err != nil {
		t.Fatalf("logs: %v", err)
	}
	if len(logs) != 1 {
		t.Errorf("log count = %d, want 1", len(logs))
	}
}
