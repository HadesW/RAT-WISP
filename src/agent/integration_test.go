//go:build integration

// End-to-end test for the KCP (UDP) transport: starts a real server with a KCP
// listener and drives a full agent lifecycle with the KCP transport — register,
// checkin, task dispatch and result submission.
//
// Run with CGO enabled (internal/server uses go-sqlite3):
//
//	CGO_ENABLED=1 go test -tags integration -run TestKCPEndToEnd ./...
package main

import (
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/user/wisp/agent/commands"
	"github.com/user/wisp/agent/transport"
	"github.com/user/wisp/internal/db"
	"github.com/user/wisp/internal/server"
	"github.com/user/wisp/shared/protocol"
)

func TestKCPEndToEnd(t *testing.T) {
	database, err := db.Open(filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer database.Close()

	srv, err := server.New(database, nil)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	// Pick a free UDP port for the KCP listener.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	probe.Close()

	row, err := database.CreateListener("kcp-e2e", "kcp", "127.0.0.1", port, false, "")
	if err != nil {
		t.Fatalf("create listener: %v", err)
	}
	if err := srv.StartListener(row.ID); err != nil {
		t.Fatalf("start listener: %v", err)
	}
	defer srv.StopListener(row.ID)

	// The agent side: a KCP transport with the server's public key.
	agentID := "aa11223344556677"
	tp := transport.NewKCPTransport("127.0.0.1", port, agentID, string(srv.GetRSAPublicKeyPEM()))

	regJSON, _ := json.Marshal(map[string]any{
		"id":           agentID,
		"hostname":     "kcp-test-host",
		"username":     "tester",
		"internal_ip":  "127.0.0.1",
		"os":           "linux amd64",
		"arch":         "amd64",
		"pid":          1234,
		"process_name": "agent",
		"sleep":        1000,
		"jitter":       0,
	})
	if err := tp.Register(regJSON); err != nil {
		t.Fatalf("register: %v", err)
	}

	// Dispatch a shell task and pick it up on the next checkin.
	if _, err := database.CreateTask(agentID, int(protocol.CmdShell), `{"cmd":"echo kcp-hello"}`); err != nil {
		t.Fatalf("create task: %v", err)
	}
	tasksData, err := tp.Checkin(nil)
	if err != nil {
		t.Fatalf("checkin: %v", err)
	}

	dispatcher := commands.NewDispatcher(nil, nil)
	results, err := dispatcher.ProcessTasks(tasksData)
	if err != nil {
		t.Fatalf("process tasks: %v", err)
	}
	if len(results) != 1 || !strings.Contains(results[0].Output, "kcp-hello") {
		t.Fatalf("unexpected results: %+v", results)
	}

	// Submit the results over KCP.
	resJSON, _ := json.Marshal(results)
	if _, err := tp.Checkin(resJSON); err != nil {
		t.Fatalf("submit results: %v", err)
	}

	// The server must now have the session and the completed task.
	sess := srv.GetSession(agentID)
	if sess == nil {
		t.Fatalf("session %s not registered on the server", agentID)
	}
	time.Sleep(50 * time.Millisecond)
	tasks, err := database.ListTasksForSession(agentID)
	if err != nil {
		t.Fatalf("get tasks: %v", err)
	}
	found := false
	for _, tk := range tasks {
		if tk.Status == protocol.TaskCompleted {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("task was not completed on the server")
	}
}
