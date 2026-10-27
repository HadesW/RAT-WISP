package orchestration

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wispp/protocol"
	"wispp/server/internal/core"
	"wispp/server/internal/db"
)

func setup(t *testing.T) (*Engine, *core.Hub, *db.Store) {
	t.Helper()
	store, err := db.Open(filepath.Join(t.TempDir(), "o.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.DB.Close() })
	hub := core.NewHub(store)
	sk, _ := protocol.NewSessionKey()
	hub.Register("goalagent1", "default", "l1", sk, protocol.SystemInfo{Hostname: "H1"})
	return New(hub, store, nil), hub, store
}

// fakeAgent drains queues answering with canned output until test end.
func fakeAgent(t *testing.T, hub *core.Hub, out string) chan struct{} {
	done := make(chan struct{})
	go func() {
		var seq uint64
		for {
			select {
			case <-done:
				return
			default:
			}
			for _, s := range hub.Sessions("") {
				seq++
				if task, _, ok := hub.Checkin(s.ID, protocol.Heartbeat{Seq: seq}); ok && task != nil {
					_ = hub.Complete(s.ID, protocol.TaskResult{TaskID: task.ID, OK: true, Output: out})
				}
			}
			time.Sleep(60 * time.Millisecond)
		}
	}()
	return done
}

func waitGoal(t *testing.T, store *db.Store, id string, statuses ...string) db.GoalRow {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		g, err := store.GoalGet(id)
		if err == nil {
			for _, want := range statuses {
				if g.Status == want {
					return *g
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	g, _ := store.GoalGet(id)
	steps, _ := store.Steps(id)
	t.Fatalf("goal %s stuck at %s steps=%+v", id, g.Status, steps)
	return db.GoalRow{}
}

func TestTaskChainAndGate(t *testing.T) {
	e, hub, store := setup(t)
	stop := fakeAgent(t, hub, "fin\\admin")
	defer close(stop)

	g, err := e.CreateGoal("default", "侦察链", []StepSpec{
		{Name: "记录", Kind: "note", Text: "开始"},
		{Name: "whoami", Kind: "task", Session: "goalagent1", Cmd: "shell", Command: "whoami"},
		{Name: "确认破坏动作", Kind: "gate"},
		{Name: "再跑", Kind: "task", Session: "goalagent1", Cmd: "shell", Command: "whoami"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Start(g.ID); err != nil {
		t.Fatal(err)
	}
	waitGoal(t, store, g.ID, "awaiting")
	steps, _ := store.Steps(g.ID)
	if steps[1].Status != "done" || !strings.Contains(steps[1].Result, "admin") {
		t.Fatalf("task step: %+v", steps[1])
	}
	if steps[2].Kind != "gate" || steps[2].Status != "awaiting" {
		t.Fatalf("gate step: %+v", steps[2])
	}
	// approve gate → chain completes
	if err := e.Decide(steps[2].ID, true); err != nil {
		t.Fatal(err)
	}
	waitGoal(t, store, g.ID, "done")
	steps, _ = store.Steps(g.ID)
	if steps[3].Status != "done" {
		t.Fatalf("post-gate step: %+v", steps[3])
	}
}

func TestGateRejectHalts(t *testing.T) {
	e, _, store := setup(t)
	g, _ := e.CreateGoal("default", "会被拒绝", []StepSpec{
		{Name: "gate", Kind: "gate"},
		{Name: "never", Kind: "task", Session: "x", Cmd: "shell", Command: "id"},
	})
	_ = e.Start(g.ID)
	waitGoal(t, store, g.ID, "awaiting")
	steps, _ := store.Steps(g.ID)
	_ = e.Decide(steps[0].ID, false)
	waitGoal(t, store, g.ID, "failed")
	steps, _ = store.Steps(g.ID)
	if steps[1].Status != "pending" {
		t.Fatalf("step after rejected gate should not run: %+v", steps[1])
	}
}

func TestFailureHaltsChain(t *testing.T) {
	e, _, store := setup(t)
	// no fake agent → task times out... too slow; instead: unknown session enqueue fails fast
	g, _ := e.CreateGoal("default", "坏步骤", []StepSpec{
		{Name: "bad", Kind: "task", Session: "nosuch", Cmd: "shell", Command: "id"},
		{Name: "next", Kind: "note"},
	})
	_ = e.Start(g.ID)
	waitGoal(t, store, g.ID, "failed")
	steps, _ := store.Steps(g.ID)
	if steps[1].Status != "pending" {
		t.Fatalf("halt must skip rest: %+v", steps[1])
	}
}
