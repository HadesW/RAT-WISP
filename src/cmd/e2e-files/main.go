// Command e2e-files verifies the file transfer loop end to end without the GUI:
//
//	1. start an HTTP listener
//	2. build an HTTP agent, launch it
//	3. wait for the session to register
//	4. upload small (single chunk) + big (multi chunk) files to the agent
//	5. download the big file back and verify the content matches
package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/user/wisp/services"
)

const (
	waitSession = 20 * time.Second
	waitTask    = 30 * time.Second
)

func main() {
	tmpDir, err := os.MkdirTemp("", "wisp-e2e-files")
	if err != nil {
		log.Fatalf("temp dir: %v", err)
	}

	svc := services.NewServerService()
	svc.Initialize()

	// HTTP listener on a random-ish high port
	row, err := svc.GetDB().CreateListener("e2e-files", "http", "127.0.0.1", 18080, false, "")
	if err != nil {
		log.Fatalf("create listener: %v", err)
	}
	if err := svc.GetServer().StartListener(row.ID); err != nil {
		log.Fatalf("start listener: %v", err)
	}

	// Build + launch agent
	agentPath := filepath.Join(tmpDir, "agent-e2e-files.exe")
	ps := services.NewPayloadService(svc)
	if _, err := ps.Generate(services.PayloadConfig{
		ListenerID: row.ID,
		TargetOS:   runtime.GOOS,
		TargetArch: runtime.GOARCH,
		Sleep:      1000,
		Jitter:     0,
		OutputPath: agentPath,
	}); err != nil {
		log.Fatalf("build agent: %v", err)
	}

	agentCmd := exec.Command(agentPath)
	if err := agentCmd.Start(); err != nil {
		log.Fatalf("launch agent: %v", err)
	}
	defer agentCmd.Process.Kill()

	// Wait for the session to register
	sessionID := waitForSession(svc, waitSession)
	if sessionID == "" {
		log.Fatalf("agent did not register within %v", waitSession)
	}
	fmt.Printf("[e2e] session registered: %s\n", sessionID)

	// Local fixtures
	small := filepath.Join(tmpDir, "small.bin")
	big := filepath.Join(tmpDir, "big.bin")
	if err := os.WriteFile(small, bytes.Repeat([]byte("S"), 100*1024), 0644); err != nil {
		log.Fatalf("write small: %v", err)
	}
	if err := os.WriteFile(big, randomBytes(2*512*1024+700), 0644); err != nil {
		log.Fatalf("write big: %v", err)
	}

	remoteDir := filepath.Join(os.TempDir(), "wisp-e2e-files-remote")
	os.MkdirAll(remoteDir, 0755)
	remoteSmall := filepath.Join(remoteDir, "small.bin")
	remoteBig := filepath.Join(remoteDir, "big.bin")

	// --- Uploads (small = 1 chunk, big = 3 chunks) ---
	if n, err := svc.GetSessionService().UploadFile(sessionID, small, remoteSmall); err != nil {
		log.Fatalf("upload small: %v", err)
	} else {
		fmt.Printf("[e2e] upload small scheduled (%d chunks)\n", n)
	}
	if n, err := svc.GetSessionService().UploadFile(sessionID, big, remoteBig); err != nil {
		log.Fatalf("upload big: %v", err)
	} else {
		fmt.Printf("[e2e] upload big scheduled (%d chunks)\n", n)
	}
	if !waitTasksDone(svc, sessionID, waitTask) {
		log.Fatalf("upload tasks did not complete within %v", waitTask)
	}
	fmt.Println("[e2e] upload tasks completed")

	// --- Download the big file back ---
	saveBig := filepath.Join(tmpDir, "big-downloaded.bin")
	if err := svc.GetSessionService().DownloadFile(sessionID, remoteBig, saveBig); err != nil {
		log.Fatalf("download: %v", err)
	}
	if !waitForFile(saveBig, waitTask) {
		log.Fatalf("download did not complete within %v", waitTask)
	}
	fmt.Println("[e2e] download completed")

	// --- Verify content ---
	want, _ := os.ReadFile(big)
	got, err := os.ReadFile(saveBig)
	if err != nil {
		log.Fatalf("read downloaded: %v", err)
	}
	if bytes.Equal(want, got) {
		fmt.Printf("[e2e] PASS: downloaded file matches source (%d bytes, %d chunks)\n", len(got), (len(got)+512*1024-1)/(512*1024))
	} else {
		fmt.Printf("[e2e] FAIL: downloaded size %d != source size %d\n", len(got), len(want))
		os.Exit(1)
	}

	// Verify the agent actually wrote the uploaded file (same host)
	if ok, err := fileExists(remoteBig); err == nil && ok {
		fmt.Printf("[e2e] PASS: agent-side uploaded file exists (%d bytes)\n", fileSize(remoteBig))
	} else {
		fmt.Printf("[e2e] WARN: cannot verify agent-side file: %v\n", err)
	}
}

func waitForSession(svc *services.ServerService, timeout time.Duration) string {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		sessions, err := svc.GetDB().ListSessions("")
		if err == nil {
			for _, s := range sessions {
				if s.Status == "alive" {
					return s.ID
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return ""
}

func waitTasksDone(svc *services.ServerService, sessionID string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		tasks, err := svc.GetDB().ListTasksForSession(sessionID)
		if err == nil {
			done := 0
			for _, t := range tasks {
				if t.Status == "completed" || t.Status == "failed" {
					done++
				}
			}
			if done > 0 && done == len(tasks) {
				return true
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

func waitForFile(path string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ok, _ := fileExists(path); ok {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func fileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return -1
	}
	return info.Size()
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i * 31 % 251)
	}
	return b
}
