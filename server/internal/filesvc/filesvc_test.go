package filesvc

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"wispp/protocol"
	"wispp/server/internal/db"
	"wispp/server/internal/rcp"
	"wispp/server/internal/rcptest"
)

type fakeAgent struct {
	t      *testing.T
	conn   net.Conn
	agent  string
	chanID uint32
}

func dialAgent(t *testing.T, addr, psk, agent string) *fakeAgent {
	t.Helper()
	c, err := rcptest.Dial(addr, psk, agent)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeAgent{t: t, conn: c, agent: agent}
}

func (fa *fakeAgent) waitOpen() protocol.FileCtrl {
	fa.t.Helper()
	for {
		f, err := protocol.ReadRCPFrame(fa.conn)
		if err != nil {
			fa.t.Fatal(err)
		}
		if f.Kind == protocol.RCPKindOpen {
			var op protocol.RCPOpen
			_ = json.Unmarshal(f.Payload, &op)
			var c protocol.FileCtrl
			_ = json.Unmarshal(op.Args, &c)
			fa.chanID = f.Chan
			return c
		}
	}
}

func (fa *fakeAgent) sendCtrl(c protocol.FileCtrl) {
	b, _ := json.Marshal(c)
	_ = protocol.WriteRCPFrame(fa.conn, &protocol.RCPFrame{
		Chan: fa.chanID, Kind: protocol.RCPKindFrame, Flags: protocol.RCPFlagJSON, Payload: b})
}

func (fa *fakeAgent) sendData(p []byte) {
	_ = protocol.WriteRCPFrame(fa.conn, &protocol.RCPFrame{
		Chan: fa.chanID, Kind: protocol.RCPKindFrame, Payload: p})
}

func (fa *fakeAgent) readCtrl() protocol.FileCtrl {
	fa.t.Helper()
	for {
		f, err := protocol.ReadRCPFrame(fa.conn)
		if err != nil {
			fa.t.Fatal(err)
		}
		if f.Kind == protocol.RCPKindFrame && f.Flags&protocol.RCPFlagJSON != 0 {
			var c protocol.FileCtrl
			_ = json.Unmarshal(f.Payload, &c)
			return c
		}
	}
}

func waitOnline(h *rcp.Hub, agent string) {
	deadline := time.Now().Add(3 * time.Second)
	for !h.Online(agent) && time.Now().Before(deadline) {
		time.Sleep(30 * time.Millisecond)
	}
}

func newService(t *testing.T) (*Service, *rcp.Hub, *db.Store, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	psk := "file-psk"
	h := rcp.NewHub(psk, nil)
	go h.Serve(ln)
	store, err := db.Open(t.TempDir() + "/f.db")
	if err != nil {
		t.Fatal(err)
	}
	svcDir := t.TempDir() + "/files"
	t.Cleanup(func() { ln.Close(); store.DB.Close() })
	_ = svcDir
	return New(h, store, nil, svcDir), h, store, ln.Addr().String()
}

func waitJob(t *testing.T, store *db.Store, id, status string) db.FileJob {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		jobs, _ := store.FileJobs("")
		for _, j := range jobs {
			if j.ID == id && j.Status == status {
				return j
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("job %s never reached %s", id, status)
	return db.FileJob{}
}

// fakeUploadAgent streams src in chunks starting at resume, then ends + waits done.
func fakeUploadAgent(src string, psk, addr string, t *testing.T) *fakeAgent {
	fa := dialAgent(t, addr, psk, "up-agent")
	go func() {
		begin := fa.waitOpen()
		srcF, err := os.Open(src)
		if err != nil {
			t.Error(err)
			return
		}
		defer srcF.Close()
		resume := fa.readCtrl() // server resume checkpoint
		off := int64(resume.Resume) * int64(begin.Chunk)
		if _, err := srcF.Seek(off, 0); err != nil {
			t.Error(err)
			return
		}
		buf := make([]byte, begin.Chunk)
		for {
			n, rerr := srcF.Read(buf)
			if n > 0 {
				fa.sendData(buf[:n])
			}
			if rerr != nil {
				break
			}
		}
		hh := sha256.New()
		if f2, err := os.Open(src); err == nil {
			_, _ = io.Copy(hh, f2)
			f2.Close()
		}
		fa.sendCtrl(protocol.FileCtrl{Op: protocol.FileOpEnd, Job: begin.Job, SHA256: hex.EncodeToString(hh.Sum(nil))})
		done := fa.readCtrl()
		if done.Op != protocol.FileOpDone || !done.OK {
			t.Errorf("expected done ok, got %+v", done)
		}
		time.Sleep(100 * time.Millisecond)
		fa.conn.Close()
	}()
	return fa
}

func TestGrabUpFlow(t *testing.T) {
	svc, h, store, addr := newService(t)
	src := filepath.Join(t.TempDir(), "payload.bin")
	data := make([]byte, 3*1024*1024+1234) // 6 full chunks + tail
	for i := range data {
		data[i] = byte(i % 251)
	}
	if err := os.WriteFile(src, data, 0o600); err != nil {
		t.Fatal(err)
	}
	fa := fakeUploadAgent(src, "file-psk", addr, t)
	_ = fa
	waitOnline(h, "up-agent")
	job, err := svc.Grab("up-agent", "default", src)
	if err != nil {
		t.Fatal(err)
	}
	done := waitJob(t, store, job.ID, "done")
	got, err := os.ReadFile(done.Local)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(data) {
		t.Fatalf("aggregated bytes differ: %d vs %d", len(got), len(data))
	}
	if done.SHA256 == "" {
		t.Fatal("missing sha256 on job")
	}
}

// TestResumeAfterKill: agent dies after 3 chunks; retry must resume at 3.
func TestResumeAfterKill(t *testing.T) {
	svc, h, store, addr := newService(t)
	src := filepath.Join(t.TempDir(), "big.bin")
	chunk := DefaultChunk
	data := make([]byte, 10*chunk)
	for i := range data {
		data[i] = byte(i)
	}
	if err := os.WriteFile(src, data, 0o600); err != nil {
		t.Fatal(err)
	}

	// partial agent: exactly 3 chunks then kill the connection
	fa := dialAgent(t, addr, "file-psk", "up-agent")
	waitOnline(h, "up-agent")
	job, err := svc.Grab("up-agent", "default", src)
	if err != nil {
		t.Fatal(err)
	}
	_ = fa.waitOpen()
	fa.readCtrl() // resume {0}
	go func() {
		for i := 0; i < 3; i++ {
			fa.sendData(data[i*chunk : (i+1)*chunk])
		}
		time.Sleep(200 * time.Millisecond)
		fa.conn.Close() // <-- kill
	}()
	waitJob(t, store, job.ID, "failed")

	// retry with a complete agent; it must be told resume=3
	fa2 := dialAgent(t, addr, "file-psk", "up-agent")
	waitOnline(h, "up-agent")
	go func() { _ = svc.Retry(job.ID) }()
	begin2 := fa2.waitOpen()
	if begin2.Job != job.ID {
		t.Fatal("retry reused a different job id")
	}
	resume := fa2.readCtrl()
	if resume.Resume != 3 {
		t.Fatalf("resume checkpoint = %d, want 3", resume.Resume)
	}
	go func() {
		for i := 3; i < 10; i++ {
			fa2.sendData(data[i*chunk : (i+1)*chunk])
		}
		hh := sha256.Sum256(data)
		fa2.sendCtrl(protocol.FileCtrl{Op: protocol.FileOpEnd, Job: job.ID, SHA256: hex.EncodeToString(hh[:])})
		fa2.readCtrl()
		fa2.conn.Close()
	}()
	done := waitJob(t, store, job.ID, "done")
	got, _ := os.ReadFile(done.Local)
	if len(got) != len(data) {
		t.Fatalf("size %d want %d", len(got), len(data))
	}
	for i := range got {
		if got[i] != data[i] {
			t.Fatalf("byte %d differs after resume", i)
		}
	}
}

func TestPushDownFlow(t *testing.T) {
	svc, h, store, addr := newService(t)
	payload := make([]byte, 2*DefaultChunk+7)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	id := "inbox1"
	if _, err := svc.SaveInbox(bytes.NewReader(payload), id); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "pushed.bin")

	fa := dialAgent(t, addr, "file-psk", "down-agent")
	waitOnline(h, "down-agent")
	job, err := svc.Push("down-agent", "default", svc.InboxPath(id), dst)
	if err != nil {
		t.Fatal(err)
	}
	begin := fa.waitOpen()
	if begin.Mode != "down" {
		t.Fatalf("mode %s", begin.Mode)
	}
	go func() {
		fa.sendCtrl(protocol.FileCtrl{Op: protocol.FileOpReady, Job: begin.Job, Mode: "down", Resume: 0})
		f, _ := os.Create(dst)
		want := 0
		const total = 2*DefaultChunk + 7
		buf := make([]byte, 0, total)
		_ = buf
		for len(buf) < total {
			f2, err := protocol.ReadRCPFrame(fa.conn)
			if err != nil {
				t.Error(err)
				return
			}
			if f2.Kind == protocol.RCPKindFrame && f2.Flags&protocol.RCPFlagJSON != 0 {
				var c protocol.FileCtrl
				_ = json.Unmarshal(f2.Payload, &c)
				if c.Op == protocol.FileOpEnd {
					break
				}
				continue
			}
			buf = append(buf, f2.Payload...)
			_ = want
		}
		f.Write(buf)
		f.Close()
		sha := sha256.Sum256(buf)
		fa.sendCtrl(protocol.FileCtrl{Op: protocol.FileOpDone, Job: begin.Job, OK: true, SHA256: hex.EncodeToString(sha[:])})
		time.Sleep(300 * time.Millisecond)
		fa.conn.Close()
	}()

	waitJob(t, store, job.ID, "done")
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("pushed bytes differ (%d vs %d)", len(got), len(payload))
	}
}
