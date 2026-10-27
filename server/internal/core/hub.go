package core

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"wispp/protocol"
	"wispp/server/internal/db"
)

// Session is one registered agent. Memory is authoritative for live sessions;
// the (optional) Store keeps durable history/audit (plan §1 存储).
type Session struct {
	ID        string
	Project   string
	Listener  string // listener id that served the registration
	Num       int    // monotonic display number, bound to the agent id (never reused)
	Info      protocol.SystemInfo
	Caps      []string
	Key       *protocol.SessionKey
	prevKey   *protocol.SessionKey // P6 rekey grace: previous key, time-boxed
	prevUntil time.Time
	FirstSeen time.Time
	LastSeen  time.Time
	Seq       uint64
	Status    string // online|idle|offline, maintained by the reaper

	mu      sync.Mutex
	pending []protocol.Task // FIFO, one task per checkin
}

// TaskRecord keeps server-side bookkeeping for a dispatched task.
type TaskRecord struct {
	Task      protocol.Task        `json:"task"`
	SessionID string               `json:"session"`
	Project   string               `json:"project"`
	Status    string               `json:"status"` // pending|sent|completed|failed
	Updated   int64                `json:"updated"`
	Result    *protocol.TaskResult `json:"result,omitempty"`
}

// Event is one line of the teamserver event stream.
type Event struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"` // info|ok|warn|err
	Kind    string    `json:"kind"`  // listener|session|task|security
	Project string    `json:"project,omitempty"`
	Text    string    `json:"text"`
}

// Hub owns sessions, task queues, the event log and its fan-out.
type Hub struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	tasks    map[string]*TaskRecord
	events   []Event // bounded ring
	subs     map[chan Event]struct{}

	store *db.Store // nil until persistence is on

	IdleAfter    time.Duration
	OfflineAfter time.Duration
	stopReaper   chan struct{}
}

const eventRingMax = 512

func NewHub(store *db.Store) *Hub {
	return &Hub{
		sessions:     make(map[string]*Session),
		tasks:        make(map[string]*TaskRecord),
		subs:         make(map[chan Event]struct{}),
		store:        store,
		IdleAfter:    20 * time.Second,
		OfflineAfter: 90 * time.Second,
	}
}

// RestoreHistory loads persisted sessions as offline rows so the console keeps
// its history across teamserver restarts. Register refreshes a row on checkin.
func (h *Hub) RestoreHistory() error {
	if h.store == nil {
		return nil
	}
	rows, err := h.store.Sessions("")
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range rows {
		if _, ok := h.sessions[r.ID]; ok {
			continue
		}
		var info protocol.SystemInfo
		_ = json.Unmarshal([]byte(r.Info), &info)
		h.sessions[r.ID] = &Session{
			ID: r.ID, Project: r.Project, Num: r.Num, Info: info,
			FirstSeen: time.Unix(r.FirstSeen, 0), LastSeen: time.Unix(r.LastSeen, 0),
			Seq: uint64(r.Seq), Status: protocol.StatusOffline,
		}
	}
	return nil
}

// Subscribe returns a channel fed with every emitted event (never blocks;
// slow consumers drop). Cancel with Unsubscribe.
func (h *Hub) Subscribe(buf int) chan Event {
	ch := make(chan Event, buf)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *Hub) Unsubscribe(ch chan Event) {
	h.mu.Lock()
	delete(h.subs, ch)
	h.mu.Unlock()
}

func (h *Hub) Emit(level, kind, project, format string, args ...any) {
	ev := Event{Time: time.Now(), Level: level, Kind: kind, Project: project, Text: fmt.Sprintf(format, args...)}
	h.mu.Lock()
	h.events = append(h.events, ev)
	if len(h.events) > eventRingMax {
		h.events = h.events[len(h.events)-eventRingMax:]
	}
	for ch := range h.subs {
		select {
		case ch <- ev:
		default:
		}
	}
	store := h.store
	h.mu.Unlock()
	if store != nil {
		_ = store.Audit(ev.Time, level, kind, project, ev.Text)
	}
}

// Events returns a copy of the recent event ring.
func (h *Hub) Events() []Event {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]Event, len(h.events))
	copy(out, h.events)
	return out
}

// StartReaper transitions sessions to idle/offline and emits the changes.
func (h *Hub) StartReaper(interval time.Duration) {
	h.stopReaper = make(chan struct{})
	stop := h.stopReaper
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				h.reap()
			}
		}
	}()
}

func (h *Hub) StopReaper() { close(h.stopReaper) }

func (h *Hub) reap() {
	h.mu.RLock()
	list := make([]*Session, 0, len(h.sessions))
	for _, s := range h.sessions {
		list = append(list, s)
	}
	h.mu.RUnlock()
	for _, s := range list {
		age := time.Since(s.LastSeen)
		want := protocol.StatusOnline
		switch {
		case age > h.OfflineAfter:
			want = protocol.StatusOffline
		case age > h.IdleAfter:
			want = protocol.StatusIdle
		}
		s.mu.Lock()
		changed := s.Status != want
		if changed {
			s.Status = want
			h.persist(s) // every transition hits the DB: history stays truthful
		}
		s.mu.Unlock()
		if changed {
			h.Emit("warn", "session", s.Project, "agent %s -> %s (%ds since checkin)",
				ShortID(s.ID), want, int(age.Seconds()))
		}
	}
}

// Register creates or refreshes a session from a validated registration.
// Returns true when the agent is new.
func (h *Hub) Register(agentID, project, listener string, key *protocol.SessionKey, info protocol.SystemInfo, caps ...string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	isNew := false
	s, ok := h.sessions[agentID]
	if !ok {
		s = &Session{ID: agentID, Project: project, Listener: listener, FirstSeen: now}
		h.sessions[agentID] = s
		isNew = true
		s.Num = h.assignNumLocked(agentID)
	}
	s.mu.Lock()
	if s.Key != nil && (s.prevKey == nil || s.Key.ID != s.prevKey.ID) {
		// P6 rekey: keep the outgoing key for in-flight frames (2 min window).
		s.prevKey = s.Key
		s.prevUntil = now.Add(2 * time.Minute)
	}
	s.Key, s.Info, s.LastSeen = key, info, now
	s.Caps = append([]string(nil), caps...)
	s.Listener = listener
	s.Status = protocol.StatusOnline
	s.mu.Unlock()
	h.persist(s)
	return isNew
}

// assignNumLocked gives an agent its durable number: existing rows keep it
// across teamserver restarts; deleted sessions are gone, so new agents take
// the next counter value (numbers never recycle). Caller holds h.mu.
func (h *Hub) assignNumLocked(agentID string) int {
	if h.store == nil {
		return 0
	}
	if n := h.store.SessionNum(agentID); n > 0 {
		return n
	}
	n, err := h.store.NextCounter("session")
	if err != nil {
		return 0
	}
	return n
}

// MarkOffline flags a session offline right now (e.g. implant acknowledged a
// kill/exit task — it is gone, no need to wait for the grace window). Row is
// kept: offline history is an audit asset, deletion is an explicit operator
// action only.
func (h *Hub) MarkOffline(agentID string) {
	h.mu.RLock()
	s, ok := h.sessions[agentID]
	h.mu.RUnlock()
	if !ok {
		return
	}
	s.mu.Lock()
	changed := s.Status != protocol.StatusOffline
	s.Status = protocol.StatusOffline
	s.mu.Unlock()
	if changed {
		h.mu.RLock()
		h.persist(s)
		h.mu.RUnlock()
		h.Emit("warn", "session", s.Project, "agent %s (#%d) -> offline (implant terminated)", ShortID(s.ID), s.Num)
	}
}

// Remove deletes a session from memory and history (ctx-menu delete). The
// allocated display number is NOT returned to the counter pool.
func (h *Hub) Remove(agentID string) bool {
	h.mu.Lock()
	s, ok := h.sessions[agentID]
	if ok {
		delete(h.sessions, agentID)
	}
	store := h.store
	h.mu.Unlock()
	if !ok {
		return false
	}
	if store != nil {
		_ = store.DeleteSession(agentID)
	}
	h.Emit("warn", "session", s.Project, "session %s (#%d) deleted by operator", ShortID(agentID), s.Num)
	return true
}

// persist writes the session history row; caller must not hold session.mu
// (except its fields are read here for safety under the same lock ordering).
func (h *Hub) persist(s *Session) {
	if h.store == nil {
		return
	}
	_ = h.store.UpsertSession(s.ID, s.Project, s.Info, s.FirstSeen, s.LastSeen, s.Seq, s.Status, s.Num)
}

// Key returns the session key for an agent.
func (h *Hub) Key(agentID string) (*protocol.SessionKey, bool) {
	h.mu.RLock()
	s, ok := h.sessions[agentID]
	h.mu.RUnlock()
	if !ok {
		return nil, false
	}
	s.mu.Lock()
	key := s.Key
	s.mu.Unlock()
	// Restored offline history carries no key: it must never be treated as a
	// live session, or sealed envelopes would be opened with a nil key.
	if key == nil {
		return nil, false
	}
	return key, true
}

// GraceKey returns the superseded session key while its rekey window is open
// (P6: frames sealed with the old key can still be opened right after a rotate).
func (h *Hub) GraceKey(agentID string) (*protocol.SessionKey, bool) {
	h.mu.RLock()
	s, ok := h.sessions[agentID]
	h.mu.RUnlock()
	if !ok {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.prevKey == nil || !time.Now().Before(s.prevUntil) {
		return nil, false
	}
	return s.prevKey, true
}

// Project returns a session's project.
func (h *Hub) Project(agentID string) string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if s, ok := h.sessions[agentID]; ok {
		return s.Project
	}
	return ""
}

// Checkin records a heartbeat and pops at most one pending task.
func (h *Hub) Checkin(agentID string, hb protocol.Heartbeat) (*protocol.Task, string, bool) {
	h.mu.Lock()
	s, ok := h.sessions[agentID]
	h.mu.Unlock()
	if !ok {
		return nil, "", false
	}
	s.mu.Lock()
	s.LastSeen = time.Now()
	if s.Status != protocol.StatusOnline {
		s.Status = protocol.StatusOnline
	}
	if hb.Seq > s.Seq {
		s.Seq = hb.Seq
	}
	var task *protocol.Task
	if len(s.pending) > 0 {
		t := s.pending[0]
		s.pending = s.pending[1:]
		task = &t
	}
	proj := s.Project
	s.mu.Unlock()
	if task != nil {
		h.mu.Lock()
		if rec, ok := h.tasks[task.ID]; ok {
			rec.Status = protocol.TaskSent
			rec.Updated = time.Now().Unix()
			if h.store != nil {
				_ = h.store.TaskStatus(task.ID, protocol.TaskSent, "", 0)
			}
		}
		h.mu.Unlock()
	}
	if h.store != nil {
		h.mu.RLock()
		h.persist(s)
		h.mu.RUnlock()
	}
	return task, proj, true
}

// NewTaskID generates an opaque task id.
func NewTaskID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Enqueue queues a task for an agent.
func (h *Hub) Enqueue(agentID string, cmd uint32, args any) (*TaskRecord, error) {
	var raw []byte
	if args != nil {
		b, err := marshalJSON(args)
		if err != nil {
			return nil, err
		}
		raw = b
	}
	task := protocol.Task{ID: NewTaskID(), Cmd: cmd, Args: raw, Created: time.Now().Unix()}
	h.mu.Lock()
	s, ok := h.sessions[agentID]
	if !ok {
		h.mu.Unlock()
		return nil, fmt.Errorf("unknown session %q", agentID)
	}
	now := time.Now().Unix()
	rec := &TaskRecord{Task: task, SessionID: agentID, Project: s.Project, Status: protocol.TaskPending, Updated: now}
	s.mu.Lock()
	s.pending = append(s.pending, task)
	s.mu.Unlock()
	h.tasks[task.ID] = rec
	store := h.store
	h.mu.Unlock()
	if store != nil {
		_ = store.TaskCreated(task.ID, agentID, rec.Project, cmd, raw)
	}
	h.Emit("info", "task", rec.Project, "queued task %s (cmd=%d) for %s", task.ID, cmd, ShortID(agentID))
	return rec, nil
}

// Complete stores a result for a previously sent task.
func (h *Hub) Complete(agentID string, res protocol.TaskResult) error {
	h.mu.Lock()
	rec, ok := h.tasks[res.TaskID]
	if !ok {
		h.mu.Unlock()
		return fmt.Errorf("unknown task %q", res.TaskID)
	}
	if rec.SessionID != agentID {
		h.mu.Unlock()
		return fmt.Errorf("task %q belongs to another session", res.TaskID)
	}
	rec.Result = &res
	level := "ok"
	status := protocol.TaskCompleted
	if !res.OK {
		level, status = "warn", protocol.TaskFailed
	}
	rec.Status = status
	rec.Updated = time.Now().Unix()
	killAck := res.OK && (rec.Task.Cmd == protocol.CmdClientKill || rec.Task.Cmd == protocol.CmdExit)
	store := h.store
	h.mu.Unlock()
	if killAck {
		h.MarkOffline(agentID) // implant said bye: mark offline immediately
	}
	if store != nil {
		_ = store.TaskStatus(res.TaskID, status, res.Output, res.Exit)
	}
	h.Emit(level, "task", rec.Project, "task %s %s exit=%d (%d bytes out)", res.TaskID, status, res.Exit, len(res.Output))
	return nil
}

// ShortID truncates for log lines without assuming wire-length validity.
func ShortID(s string) string {
	if len(s) <= 8 {
		return s
	}
	return s[:8]
}

// SessionView is the API projection of a Session (never exposes key material).
type SessionView struct {
	Num       int                 `json:"num"`
	ID        string              `json:"id"`
	Project   string              `json:"project"`
	Listener  string              `json:"listener"`
	Status    string              `json:"status"`
	LastSeen  time.Time           `json:"last_seen"`
	FirstSeen time.Time           `json:"first_seen"`
	Seq       uint64              `json:"seq"`
	Pending   int                 `json:"pending"`
	Info      protocol.SystemInfo `json:"info"`
	Caps      []string            `json:"caps,omitempty"`
}

// Sessions snapshots sessions, optionally filtered by project.
func (h *Hub) Sessions(project string) []SessionView {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]SessionView, 0, len(h.sessions))
	for _, s := range h.sessions {
		if project != "" && s.Project != project {
			continue
		}
		s.mu.Lock()
		out = append(out, SessionView{
			Num: s.Num, ID: s.ID, Project: s.Project, Listener: s.Listener, Status: s.Status,
			LastSeen: s.LastSeen, FirstSeen: s.FirstSeen, Seq: s.Seq,
			Pending: len(s.pending), Info: s.Info, Caps: append([]string(nil), s.Caps...),
		})
		s.mu.Unlock()
	}
	return out
}

// ListenerCount: sessions currently online on a listener.
func (h *Hub) ListenerCount(listenerID string) int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	n := 0
	for _, s := range h.sessions {
		if s.Listener == listenerID && s.Status == protocol.StatusOnline {
			n++
		}
	}
	return n
}

// Tasks lists task records filtered by session/project ("" = all).
func (h *Hub) Tasks(sessionID, project string) []TaskRecord {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]TaskRecord, 0, len(h.tasks))
	for _, r := range h.tasks {
		if sessionID != "" && r.SessionID != sessionID {
			continue
		}
		if project != "" && r.Project != project {
			continue
		}
		out = append(out, *r)
	}
	return out
}
