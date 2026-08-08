package services

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// freePort grabs a temporary free TCP port.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

func newTestFileServerService(t *testing.T) (*FileServerService, *ServerService, string) {
	t.Helper()
	svc := &ServerService{}
	dbase, err := openTestDB(t)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	svc.db = dbase

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "agent.exe"), []byte("fake-agent"), 0644); err != nil {
		t.Fatal(err)
	}
	return NewFileServerService(svc), svc, root
}

func TestFileServerStartServeAndStop(t *testing.T) {
	fs, _, root := newTestFileServerService(t)
	port := freePort(t)

	if err := fs.StartFileServer(root, port, false, ""); err != nil {
		t.Fatalf("start: %v", err)
	}

	// Download the file over HTTP
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/agent.exe", port))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "fake-agent" {
		t.Errorf("body = %q", body)
	}

	// Status lists the file with a URL
	st, err := fs.GetFileServerStatus()
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !st.Running || st.Port != port {
		t.Errorf("status = %+v", st)
	}
	if len(st.Files) != 1 || st.Files[0].Name != "agent.exe" {
		t.Errorf("files = %+v", st.Files)
	}

	// Stop and verify the port is closed
	if err := fs.StopFileServer(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	st, _ = fs.GetFileServerStatus()
	if st.Running {
		t.Error("should be stopped")
	}
	if _, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/agent.exe", port)); err == nil {
		t.Error("expected connection error after stop")
	}
}

func TestFileServerValidation(t *testing.T) {
	fs, _, root := newTestFileServerService(t)

	if err := fs.StartFileServer(root, 0, false, ""); err == nil {
		t.Error("port 0 should fail")
	}
	if err := fs.StartFileServer(root, 70000, false, ""); err == nil {
		t.Error("port > 65535 should fail")
	}
	if err := fs.StartFileServer("Z:\\missing\\dir\\nope", 8080, false, ""); err == nil {
		t.Error("missing dir should fail")
	}
	// A configured host must appear in the URL
	if err := fs.StartFileServer(root, 8080, false, "myhost.example.com"); err != nil {
		t.Fatalf("start with host: %v", err)
	}
	defer fs.StopFileServer()
	st, _ := fs.GetFileServerStatus()
	if st.URL != "http://myhost.example.com:8080/" {
		t.Errorf("url = %q", st.URL)
	}
}

func TestFileServerPersistRestore(t *testing.T) {
	_, svc, root := newTestFileServerService(t)
	port := freePort(t)

	// Simulate "was running before the restart": persist an enabled config
	cfg := FileServerConfig{RootDir: root, Port: port, UseTLS: false, Enabled: true}
	data, _ := json.Marshal(cfg)
	if err := svc.db.SetSetting(fileServerSettingKey, string(data)); err != nil {
		t.Fatal(err)
	}

	fs := NewFileServerService(svc)
	if err := fs.Restore(); err != nil {
		t.Fatalf("restore: %v", err)
	}
	defer fs.StopFileServer()

	st, err := fs.GetFileServerStatus()
	if err != nil {
		t.Fatal(err)
	}
	if !st.Running || st.RootDir != root || st.Port != port {
		t.Errorf("restored status = %+v", st)
	}

	// A config marked disabled (user stopped it) must NOT auto-start
	cfg.Enabled = false
	data, _ = json.Marshal(cfg)
	if err := svc.db.SetSetting(fileServerSettingKey, string(data)); err != nil {
		t.Fatal(err)
	}
	fs2 := NewFileServerService(svc)
	if err := fs2.Restore(); err != nil {
		t.Fatal(err)
	}
	st, _ = fs2.GetFileServerStatus()
	if st.Running {
		t.Error("server should not auto-start after being stopped")
	}
}
