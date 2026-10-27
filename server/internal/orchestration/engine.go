// Package orchestration runs goal step-chains (plan §7-M6.5): ordered steps
// (task / plugin / gate / wait / note) executed by a per-goal worker; gate
// steps block on operator approval; failures halt the chain.
package orchestration

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"wispp/protocol"
	"wispp/server/internal/ai"
	"wispp/server/internal/core"
	"wispp/server/internal/db"
)

type Engine struct {
	Hub   *core.Hub
	Store *db.Store
	AI    *ai.Runtime

	mu      sync.Mutex
	running map[string]chan struct{} // goalID → pause signal
}

func New(hub *core.Hub, store *db.Store, aiRT *ai.Runtime) *Engine {
	return &Engine{Hub: hub, Store: store, AI: aiRT, running: map[string]chan struct{}{}}
}

func genID() string {
	b := make([]byte, 5)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (e *Engine) emit(level, project, format string, args ...any) {
	e.Hub.Emit(level, "goal", project, format, args...)
}

// CreateGoal stores a goal with its steps (status draft).
func (e *Engine) CreateGoal(project, title string, steps []StepSpec) (*db.GoalRow, error) {
	g := &db.GoalRow{ID: genID(), Project: orDef(project, "default"), Title: title, Status: "draft", Created: time.Now().Unix()}
	if err := e.Store.GoalInsert(g); err != nil {
		return nil, err
	}
	for i, sp := range steps {
		args, _ := json.Marshal(sp)
		if err := e.Store.StepInsert(&db.StepRow{ID: genID(), Goal: g.ID, Seq: i + 1, Name: sp.Name, Kind: sp.Kind, Args: string(args), Status: "pending"}); err != nil {
			return nil, err
		}
	}
	e.emit("info", g.Project, "goal #%s created (%d steps)", g.ID, len(steps))
	return g, nil
}

// StepSpec is one planned step (API/AI shape).
type StepSpec struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"` // task|plugin|gate|wait|note
	Session string `json:"session,omitempty"`
	Cmd     string `json:"cmd,omitempty"`
	Command string `json:"command,omitempty"`
	Plugin  string `json:"plugin,omitempty"`
	A       int    `json:"a,omitempty"`
	B       int    `json:"b,omitempty"`
	Seconds int    `json:"seconds,omitempty"`
	Text    string `json:"text,omitempty"`
}

// Start launches the worker (draft/paused/failed → running).
func (e *Engine) Start(goalID string) error {
	if _, err := e.Store.GoalGet(goalID); err != nil {
		return err
	}
	e.mu.Lock()
	if _, busy := e.running[goalID]; busy {
		e.mu.Unlock()
		return errors.New("goal already running")
	}
	pause := make(chan struct{})
	e.running[goalID] = pause
	e.mu.Unlock()
	go e.run(goalID, pause)
	return e.Store.GoalStatus(goalID, "running")
}

// Pause signals the worker to stop after the current step.
func (e *Engine) Pause(goalID string) {
	e.mu.Lock()
	if ch, ok := e.running[goalID]; ok {
		close(ch)
		delete(e.running, goalID)
	}
	e.mu.Unlock()
	_ = e.Store.GoalStatus(goalID, "paused")
}

// Decide resolves a gate step.
func (e *Engine) Decide(stepID string, approve bool) error {
	st, err := e.Store.StepGet(stepID)
	if err != nil {
		return err
	}
	if st.Kind != "gate" || st.Status != "awaiting" {
		return errors.New("step is not an awaiting gate")
	}
	res := "approved"
	status := "done"
	if !approve {
		res, status = "rejected", "skipped"
	}
	_ = e.Store.StepUpdate(stepID, status, res)
	e.emit("info", "default", "gate %s %s (goal %s)", stepID, res, st.Goal)
	return nil
}

func (e *Engine) run(goalID string, pause chan struct{}) {
	defer func() {
		e.mu.Lock()
		delete(e.running, goalID)
		e.mu.Unlock()
	}()
	steps, _ := e.Store.Steps(goalID)
	finished := true
	for _, st := range steps {
		select {
		case <-pause:
			return
		default:
		}
		if st.Status == "done" || st.Status == "skipped" {
			continue
		}
		_ = e.Store.StepUpdate(st.ID, "running", "")
		e.emit("info", "default", "goal %s step %d/%s ▶ %s", goalID, st.Seq, st.Kind, st.Name)
		switch st.Kind {
		case "note":
			_ = e.Store.StepUpdate(st.ID, "done", st.Name)
			e.emit("ok", "default", "goal %s step %d ✓ %s", goalID, st.Seq, st.Name)
		case "wait":
			var sp StepSpec
			_ = json.Unmarshal([]byte(st.Args), &sp)
			slept := 0
			for i := 0; i < sp.Seconds; i++ {
				select {
				case <-pause:
					_ = e.Store.StepUpdate(st.ID, "pending", "")
					return
				case <-time.After(time.Second):
					slept++
				}
			}
			_ = e.Store.StepUpdate(st.ID, "done", fmt.Sprintf("waited %ds", slept))
			e.emit("ok", "default", "goal %s step %d ✓ waited %ds", goalID, st.Seq, slept)
		case "gate":
			_ = e.Store.StepUpdate(st.ID, "awaiting", "等待操作员批准")
			_ = e.Store.GoalStatus(goalID, "awaiting")
			for {
				select {
				case <-pause:
					_ = e.Store.StepUpdate(st.ID, "pending", "")
					return
				case <-time.After(700 * time.Millisecond):
				}
				cur, err := e.Store.StepGet(st.ID)
				if err != nil {
					return
				}
				if cur.Status == "done" {
					_ = e.Store.GoalStatus(goalID, "running")
					break
				}
				if cur.Status == "skipped" {
					_ = e.Store.GoalStatus(goalID, "failed")
					e.emit("warn", "default", "goal %s halted: gate rejected", goalID)
					return
				}
			}
		case "task", "plugin":
			res, ok := e.execStep(&st)
			status := "done"
			if !ok {
				status = "failed"
			}
			_ = e.Store.StepUpdate(st.ID, status, trunc(res, 800))
			if ok {
				e.emit("ok", "default", "goal %s step %d/%s ✓ %s", goalID, st.Seq, st.Kind, st.Name)
			}
			if !ok {
				_ = e.Store.GoalStatus(goalID, "failed")
				e.emit("err", "default", "goal %s halted at step %d (%s)", goalID, st.Seq, st.Name)
				return
			}
		default:
			_ = e.Store.StepUpdate(st.ID, "failed", "unknown kind")
			_ = e.Store.GoalStatus(goalID, "failed")
			return
		}
	}
	if finished {
		_ = e.Store.GoalStatus(goalID, "done")
		e.emit("ok", "default", "goal %s completed", goalID)
	}
}

// execStep runs one task/plugin step synchronously (reuses Type1 queue).
func (e *Engine) execStep(st *db.StepRow) (string, bool) {
	var sp StepSpec
	if err := json.Unmarshal([]byte(st.Args), &sp); err != nil {
		return err.Error(), false
	}
	// Session resolution: empty = first session; prefix allowed; unknown =
	// fail fast (NEVER silently redirect a step to another agent).
	sid := strings.TrimSpace(sp.Session)
	all := e.Hub.Sessions("")
	if sid == "" {
		if len(all) == 0 {
			return "no sessions available", false
		}
		sid = all[0].ID
	} else if !contains(all, sid) {
		if m := matchPrefix(all, sid); m != "" {
			sid = m
		} else if n, err := strconv.Atoi(strings.TrimPrefix(sid, "#")); err == nil {
			// "#59" / "59": AI loves session numbers, resolve them too
			found := ""
			for _, x := range all {
				if x.Num == n {
					found = x.ID
					break
				}
			}
			if found == "" {
				return fmt.Sprintf("unknown session number %q", sid), false
			}
			sid = found
		} else {
			return fmt.Sprintf("unknown session %q", sid), false
		}
	}
	var cmd uint32
	var args any
	if sp.Kind == "plugin" {
		cmd = protocol.CmdPluginExec
		args = protocol.PluginExecArgs{ID: sp.Plugin, Entry: "exec", A: int32(sp.A), B: int32(sp.B)}
	} else {
		switch sp.Cmd {
		case "sysinfo", "pwd":
			cmd = cmdID(sp.Cmd)
		default:
			cmd = protocol.CmdShell
			args = protocol.ShellArgs{Command: sp.Command, TimeoutMS: 15000}
		}
	}
	rec, err := e.Hub.Enqueue(sid, cmd, args)
	if err != nil {
		return err.Error(), false
	}
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		for _, t := range e.Hub.Tasks(sid, "") {
			if t.Task.ID == rec.Task.ID && (t.Status == "completed" || t.Status == "failed") {
				out := ""
				if t.Result != nil {
					out = t.Result.Output
				}
				return out, t.Status == "completed"
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return "timeout (agent offline?)", false
}

func cmdID(n string) uint32 {
	switch n {
	case "sysinfo":
		return protocol.CmdSysinfo
	case "pwd":
		return protocol.CmdPwd
	}
	return protocol.CmdShell
}

func contains(ss []core.SessionView, id string) bool {
	for _, s := range ss {
		if s.ID == id {
			return true
		}
	}
	return false
}

func matchPrefix(ss []core.SessionView, p string) string {
	for _, s := range ss {
		if p != "" && len(s.ID) >= len(p) && s.ID[:len(p)] == p {
			return s.ID
		}
	}
	return ""
}

// ---- AI planning ----

var jsonRe = regexp.MustCompile(`(?s)\[[\s\S]*\]`)

// Plan asks the model for a step chain from an operator prompt + live data.
func (e *Engine) Plan(prompt string) ([]StepSpec, error) {
	if e.AI == nil || !e.AI.On() {
		return nil, errors.New("AI 未启用：无法自动规划（可手工添加步骤）")
	}
	snap := e.Hub.Sessions("")
	var lines []string
	for _, s := range snap {
		lines = append(lines, fmt.Sprintf("#%d %s id=%s %s@%s %s", s.Num, s.Info.Hostname, s.ID, s.Info.User, s.Info.OS, s.Status))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := e.AI.Generate(ctx, fmt.Sprintf(
		"操作员目标：%s\n\n当前会话：\n%s\n\n请输出 JSON 数组（仅 JSON，无解释）规划 2-6 个步骤，元素字段：name,kind(task|plugin|gate|wait|note),session(会话id),cmd(shell|sysinfo|pwd),command,gate用于人工确认点。开头第一步若为写操作前需 gate。",
		prompt, joinLines(lines)))
	if err != nil {
		return nil, err
	}
	m := jsonRe.FindString(out)
	if m == "" {
		return nil, errors.New("模型未返回 JSON 步骤数组")
	}
	var steps []StepSpec
	if err := json.Unmarshal([]byte(m), &steps); err != nil {
		return nil, err
	}
	for i := range steps {
		if steps[i].Kind == "" {
			steps[i].Kind = "task"
		}
	}
	return steps, nil
}

func joinLines(l []string) string {
	out := ""
	for _, x := range l {
		out += x + "\n"
	}
	return out
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func orDef(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
