// Package filesvc implements Type3 file transfers over RCP channels
// (plan §2.4): 512KB ordered chunks, SHA-256 end-to-end verification,
// bitmap-free resume (TCP order makes a received-count checkpoint enough),
// server-side token-bucket rate limiting, and durable job bookkeeping.
package filesvc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"wispp/protocol"
	"wispp/server/internal/core"
	"wispp/server/internal/db"
	"wispp/server/internal/rcp"
)

const DefaultChunk = 512 * 1024

// Emittable hooks the service into the teamserver event bus.
type Emit func(level, project, text string)

type Service struct {
	H   *rcp.Hub
	DB  *db.Store
	E   Emit
	Dir string // data/files
	// RateBps limits server<->agent chunk flow (0 = unlimited); per-transfer.
	RateBps int

	mu   sync.Mutex
	jobs map[string]*run // active transfers
}

type run struct {
	job  db.FileJob
	ch   *rcp.Channel
	tmp  *os.File // up: receiving temp
	next int      // next chunk index (expected or to send)
	sha  string   // down: precomputed source hash
	end  chan struct{}

	closed bool
}

func New(h *rcp.Hub, store *db.Store, emit Emit, dir string) *Service {
	return &Service{H: h, DB: store, E: emit, Dir: dir, jobs: make(map[string]*run)}
}

func newJobID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Service) emitf(job *db.FileJob, level, format string, args ...any) {
	if s.E != nil {
		s.E(level, job.Project, formatText(format, args...))
	}
}

// Grab asks an agent to upload one of its files to the teamserver (mode "up").
func (s *Service) Grab(agentID, project, remote string) (*db.FileJob, error) {
	return s.start(db.FileJob{
		ID: newJobID(), Agent: agentID, Project: project, Mode: "up",
		Remote: remote, Chunk: DefaultChunk, Status: protocol.TaskPending,
	})
}

// Push sends a teamserver-stored file (operator inbox) to the agent (mode "down").
func (s *Service) Push(agentID, project, localPath, remote string) (*db.FileJob, error) {
	st, err := os.Stat(localPath)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("filesvc: source is not a regular file")
	}
	return s.start(db.FileJob{
		ID: newJobID(), Agent: agentID, Project: project, Mode: "down",
		Remote: remote, Local: localPath, Size: st.Size(),
		Chunk: DefaultChunk, Status: protocol.TaskPending,
	})
}

// InboxPath is where operator-uploaded sources live before a Push.
func (s *Service) InboxPath(id string) string {
	return filepath.Join(s.Dir, "inbox", id)
}

func (s *Service) SaveInbox(r io.Reader, id string) (string, error) {
	dir := filepath.Join(s.Dir, "inbox")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	f, err := os.OpenFile(filepath.Join(dir, id), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := io.Copy(f, r); err != nil {
		return "", err
	}
	return f.Name(), nil
}

func (s *Service) start(job db.FileJob) (*db.FileJob, error) {
	if !s.H.Online(job.Agent) {
		return nil, errors.New("agent RCP offline (Type2 required for file jobs)")
	}
	if err := os.MkdirAll(filepath.Join(s.Dir, job.Agent), 0o700); err != nil {
		return nil, err
	}
	job.Created = time.Now().Unix()
	if s.DB != nil {
		if err := s.DB.FileJobCreated(&job); err != nil {
			return nil, err
		}
	}
	args, _ := json.Marshal(protocol.FileCtrl{
		Op: protocol.FileOpBegin, Mode: job.Mode, Job: job.ID,
		Path: job.Remote, Size: job.Size, Chunk: job.Chunk,
	})
	ch, err := s.H.Open(job.Agent, protocol.RCPChanFile, args)
	if err != nil {
		return nil, err
	}
	r := &run{job: job, ch: ch, end: make(chan struct{})}
	s.mu.Lock()
	s.jobs[job.ID] = r
	s.mu.Unlock()
	s.emitf(&job, "info", "file job %s %s %s %s", job.ID, job.Mode, job.Remote, core.ShortID(job.Agent))
	switch job.Mode {
	case "up":
		go s.pumpUp(r)
	case "down":
		go s.pumpDown(r)
	default:
		return nil, errors.New("filesvc: bad mode")
	}
	return &job, nil
}

// Retry reopens the channel for a failed job; resume picks up where it left.
func (s *Service) Retry(jobID string) error {
	if s.DB == nil {
		return errors.New("filesvc: no db")
	}
	jobs, err := s.DB.FileJobs("")
	if err != nil {
		return err
	}
	for _, j := range jobs {
		if j.ID == jobID && j.Status != "done" {
			_, err := s.start(j)
			return err
		}
	}
	return errors.New("filesvc: job not found or already done")
}

// Store exposes the job bookkeeping store to the API layer.
func (s *Service) Store() *db.Store { return s.DB }

func (s *Service) get(jobID string) *run {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.jobs[jobID]
}

func (s *Service) finish(r *run, status string, reason string) {
	s.mu.Lock()
	if r.closed {
		s.mu.Unlock()
		return
	}
	r.closed = true
	delete(s.jobs, r.job.ID)
	s.mu.Unlock()
	if r.tmp != nil {
		r.tmp.Close()
	}
	r.job.Status = status
	if s.DB != nil {
		_ = s.DB.FileJobProgress(r.job.ID, r.next, status)
	}
	level := "ok"
	if status != "done" {
		level = "warn"
	}
	s.emitf(&r.job, level, "file job %s -> %s %s", r.job.ID, status, reason)
	select {
	case <-r.end:
	default:
		close(r.end)
	}
}

// up: agent streams its remote file into our store.
func (s *Service) pumpUp(r *run) {
	defer s.H.Close(r.job.Agent, r.ch.ID, "up finished")
	tmpPath := filepath.Join(s.Dir, r.job.Agent, r.job.ID+".part")
	var written int64
	if st, err := os.Stat(tmpPath); err == nil {
		written = st.Size()
		r.next = int(written / int64(r.job.Chunk))
	}
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		s.finish(r, "failed", err.Error())
		return
	}
	r.tmp = f
	sendCtrl(r, s, protocol.FileCtrl{Op: protocol.FileOpResume, Job: r.job.ID, Resume: r.next})

	for {
		select {
		case <-r.end:
			return
		case d, ok := <-r.ch.Sub():
			if !ok {
				s.finish(r, "failed", "agent disconnected (resumable)")
				return
			}
			if d.Ctrl {
				var c protocol.FileCtrl
				if json.Unmarshal(d.Data, &c) != nil {
					continue
				}
				switch c.Op {
				case protocol.FileOpEnd:
					if err := verifyAndSeal(tmpPath, f, r, c.SHA256); err != nil {
						s.finish(r, "failed", err.Error())
						return
					}
					if s.DB != nil {
						_ = s.DB.FileJobSealed(r.job.ID, r.job.Local, r.job.SHA256, r.job.Size, "active")
					}
					sendCtrl(r, s, protocol.FileCtrl{Op: protocol.FileOpDone, Job: r.job.ID, OK: true})
					s.finish(r, "done", "sha "+r.job.SHA256[:min(8, len(r.job.SHA256))])
					return
				case protocol.FileOpError:
					s.finish(r, "failed", c.Reason)
					return
				}
				continue
			}
			// raw chunk: ordered by TCP; ignore ones we already have on resume
			if _, err := f.WriteAt(d.Data, int64(r.next)*int64(r.job.Chunk)); err != nil {
				s.finish(r, "failed", err.Error())
				return
			}
			r.next++
			s.rateWait(int64(len(d.Data)))
			if s.DB != nil && r.next%16 == 0 {
				_ = s.DB.FileJobProgress(r.job.ID, r.next, "active")
			}
		}
	}
}

func verifyAndSeal(tmpPath string, f *os.File, r *run, want string) error {
	if err := f.Sync(); err != nil {
		return err
	}
	// Windows refuses to rename a file while any handle to it is open: close
	// both our write side and the hashing reader before the rename
	// (finish() re-Closing an already-closed file is harmless).
	if err := f.Close(); err != nil {
		return err
	}
	src, err := os.Open(tmpPath)
	if err != nil {
		return err
	}
	h := sha256.New()
	_, err = io.Copy(h, src)
	src.Close()
	if err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if want != "" && got != want {
		return errors.New("sha256 mismatch")
	}
	// final name: keep basename for operator convenience inside job dir
	final := filepath.Join(filepath.Dir(tmpPath), r.job.ID+filepath.Ext(r.job.Remote))
	if err := os.Rename(tmpPath, final); err != nil {
		return err
	}
	r.job.Local = final
	r.job.SHA256 = got
	r.job.Size = lenOf(final)
	return nil
}

// down: server streams an inbox file to the agent (ready-wait, stream and
// done-ack all live in one goroutine so the channel stays open end-to-end).
func (s *Service) pumpDown(r *run) {
	defer s.H.Close(r.job.Agent, r.ch.ID, "down finished")
	src, err := s.waitReadyDown(r)
	if err != nil {
		s.finish(r, "failed", err.Error())
		return
	}
	defer src.Close()
	s.streamDown(r, src)
}

func (s *Service) waitReadyDown(r *run) (*os.File, error) {
	src, err := os.Open(r.job.Local)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	if _, err := io.Copy(h, src); err != nil {
		src.Close()
		return nil, err
	}
	r.sha = hex.EncodeToString(h.Sum(nil))
	for {
		d, ok := <-r.ch.Sub()
		if !ok {
			src.Close()
			return nil, errors.New("agent disconnected before ready")
		}
		if !d.Ctrl {
			continue
		}
		var c protocol.FileCtrl
		if json.Unmarshal(d.Data, &c) != nil {
			continue
		}
		switch c.Op {
		case protocol.FileOpReady:
			sendCtrl(r, s, protocol.FileCtrl{Op: protocol.FileOpResume, Job: r.job.ID, Resume: c.Resume})
			if _, err := src.Seek(int64(c.Resume)*int64(r.job.Chunk), io.SeekStart); err != nil {
				src.Close()
				return nil, err
			}
			r.next = c.Resume
			return src, nil
		case protocol.FileOpError:
			src.Close()
			return nil, errors.New(c.Reason)
		}
	}
}

func (s *Service) streamDown(r *run, src *os.File) {
	sha := r.sha
	buf := make([]byte, r.job.Chunk)
	for i := r.next; ; i++ {
		n, err := src.Read(buf)
		if n > 0 {
			if e := s.H.Input(r.job.Agent, r.ch.ID, append([]byte(nil), buf[:n]...)); e != nil {
				s.finish(r, "failed", "agent gone (resumable)")
				return
			}
			r.next = i + 1
			s.rateWait(int64(n))
			if s.DB != nil && r.next%16 == 0 {
				_ = s.DB.FileJobProgress(r.job.ID, r.next, "active")
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			s.finish(r, "failed", err.Error())
			return
		}
	}
	sendCtrl(r, s, protocol.FileCtrl{Op: protocol.FileOpEnd, Job: r.job.ID, SHA256: sha})
	// await agent done ack
	for {
		select {
		case <-r.end:
			return
		case d, ok := <-r.ch.Sub():
			if !ok {
				s.finish(r, "failed", "no done ack (resumable)")
				return
			}
			var c protocol.FileCtrl
			if d.Ctrl && json.Unmarshal(d.Data, &c) == nil && c.Op == protocol.FileOpDone {
				if c.OK {
					r.job.SHA256 = sha
					if s.DB != nil {
						_ = s.DB.FileJobProgress(r.job.ID, r.next, "done")
					}
					s.finish(r, "done", "agent verified")
				} else {
					s.finish(r, "failed", c.Reason)
				}
				return
			}
		case <-time.After(5 * time.Minute):
			s.finish(r, "failed", "done ack timeout")
			return
		}
	}
}

func (s *Service) rateWait(n int64) {
	if s.RateBps <= 0 {
		return
	}
	time.Sleep(time.Duration(n) * time.Second / time.Duration(s.RateBps))
}

func sendCtrl(r *run, s *Service, c protocol.FileCtrl) {
	b, _ := json.Marshal(c)
	_ = s.H.SendCtrl(r.job.Agent, r.ch.ID, b)
}

func lenOf(p string) int64 {
	if st, err := os.Stat(p); err == nil {
		return st.Size()
	}
	return 0
}

func formatText(format string, args ...any) string {
	return fmt.Sprintf(format, args...)
}

// Jobs returns recent job bookkeeping (API view).
func (s *Service) Jobs(project string) []db.FileJob {
	if s.DB == nil {
		return nil
	}
	out, _ := s.DB.FileJobs(project)
	return out
}
