package ai

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"wispp/protocol"
	"wispp/server/internal/core"
	"wispp/server/internal/db"
)

func setup(t *testing.T) (*Runtime, *core.Hub, *db.Store) {
	t.Helper()
	store, err := db.Open(t.TempDir() + "/ai.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.DB.Close() })
	hub := core.NewHub(nil)
	for _, id := range []string{"s1a2b3c4d5e6f7a8", "s2a2b3c4d5e6f7a8"} {
		sk, _ := protocol.NewSessionKey()
		hub.Register(id, "default", "tst", sk, protocol.SystemInfo{Hostname: id[:2], OS: "windows", User: "u"})
	}
	rt := &Runtime{Hub: hub, Store: store, TaskWait: 8 * time.Second}
	rt.Configure(Config{Enabled: true, Active: "m", Profiles: []Profile{{Name: "m", Provider: "mock"}}})
	return rt, hub, store
}

// fakeAgent drains the task queue and posts success, like a live implant.
func fakeAgent(ctx context.Context, hub *core.Hub, out string) {
	go func() {
		var seq uint64
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			for _, s := range hub.Sessions("") {
				seq++
				if task, _, ok := hub.Checkin(s.ID, protocol.Heartbeat{Seq: seq}); ok && task != nil {
					_ = hub.Complete(s.ID, protocol.TaskResult{TaskID: task.ID, OK: true, Output: out})
				}
			}
			time.Sleep(80 * time.Millisecond)
		}
	}()
}

func TestMockDoDLoop(t *testing.T) {
	rt, hub, _ := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fakeAgent(ctx, hub, `desktop\u`)

	var evs []Event
	if err := rt.ChatStream(ctx, "", "default", "对所有会话跑 whoami 并汇总", "zh", func(e Event) { evs = append(evs, e) }); err != nil {
		t.Fatal(err)
	}
	var conv, apprID string
	var sawList, sawApproval bool
	for _, e := range evs {
		switch e.Type {
		case "tool":
			if e.Name == "list_sessions" && *e.OK {
				sawList = true
			}
		case "approval":
			sawApproval, apprID = true, e.ID
			if !strings.Contains(e.Args, "__ALL__") {
				t.Fatalf("approval args: %s", e.Args)
			}
		case "done":
			conv = e.ID
		}
	}
	if !sawList || !sawApproval || conv == "" {
		t.Fatalf("events: %+v", evs)
	}

	out, err := rt.Decide(ctx, apprID, true)
	if err != nil {
		t.Fatal(err)
	}
	var toolRes, summary string
	for _, e := range out {
		if e.Type == "tool" && e.Name == "run_task" {
			toolRes = e.Content
		}
		if e.Type == "token" {
			summary += e.Content
		}
	}
	var res []struct {
		Session string `json:"session"`
		Status  string `json:"status"`
		Output  string `json:"output"`
	}
	if err := json.Unmarshal([]byte(toolRes), &res); err != nil || len(res) != 2 {
		t.Fatalf("run_task result: %v %s", err, toolRes)
	}
	for _, r := range res {
		if r.Status != "completed" || r.Output != "desktop\\u" {
			t.Fatalf("per-session result: %+v", r)
		}
	}
	if !strings.Contains(summary, "2/2") {
		t.Fatalf("summary missing counts: %q", summary)
	}
}

func TestRejectPath(t *testing.T) {
	rt, _, _ := setup(t)
	var evs []Event
	_ = rt.ChatStream(context.Background(), "", "default", "对所有会话跑 whoami", "zh", func(e Event) { evs = append(evs, e) })
	var apprID string
	for _, e := range evs {
		if e.Type == "approval" {
			apprID = e.ID
		}
	}
	out, err := rt.Decide(context.Background(), apprID, false)
	if err != nil {
		t.Fatal(err)
	}
	var sawRejectNote bool
	for _, e := range out {
		if e.Type == "tool" && strings.Contains(e.Content, "拒绝") {
			sawRejectNote = true
		}
		if e.Type == "token" && !strings.Contains(e.Content, "批量执行完成") {
			sawRejectNote = true // mock summarizer must NOT fire on rejection
		}
	}
	if !sawRejectNote {
		t.Fatalf("reject events: %+v", out)
	}
	// double-decide must fail
	if _, err := rt.Decide(context.Background(), apprID, true); err == nil {
		t.Fatal("approval was decided twice")
	}
}

func TestDisabledByDefault(t *testing.T) {
	rt, _, _ := setup(t)
	rt.Configure(Config{Enabled: false, Active: "m", Profiles: []Profile{{Name: "m", Provider: "mock"}}})
	if err := rt.ChatStream(context.Background(), "c", "default", "hi", "", func(Event) {}); err != ErrDisabled {
		t.Fatal("disabled runtime answered")
	}
}
