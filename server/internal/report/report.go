// Package report assembles operator-facing action reports (plan §7-M6.5):
// a deterministic markdown snapshot built from live teamserver state, plus
// optional AI rewriting when a model is configured.
package report

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"wispp/protocol"
	"wispp/server/internal/ai"
	"wispp/server/internal/core"
	"wispp/server/internal/db"
	"wispp/server/internal/listener"
)

// Gen wires the report generator into teamserver state.
type Gen struct {
	Hub   *core.Hub
	Store *db.Store
	AI    *ai.Runtime
	Mgr   *listener.Manager
}

func genID() string {
	b := make([]byte, 5)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Snapshot builds the deterministic data dump (works with AI disabled).
func (g *Gen) Snapshot(project string) string {
	var b strings.Builder
	now := time.Now().Format("2006-01-02 15:04:05")
	fmt.Fprintf(&b, "# WISP++ 行动报告\n\n- 生成时间：%s\n- 项目：%s\n\n", now, orDef(project, "default"))

	fmt.Fprintf(&b, "## 监听器\n\n| 名称 | 类型 | 地址 | 状态 |\n|---|---|---|---|\n")
	if g.Mgr != nil {
		for _, l := range g.Mgr.List() {
			run := "已停止"
			if l.Running {
				run = "运行中"
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", l.Name, l.Kind, l.Addr, run)
		}
	}

	sessions := g.Hub.Sessions(project)
	fmt.Fprintf(&b, "\n## 会话（%d）\n\n| # | 主机 | 用户 | 系统 | 状态 |\n|---|---|---|---|---|\n", len(sessions))
	for _, s := range sessions {
		fmt.Fprintf(&b, "| %d | %s | %s | %s/%s | %s |\n", s.Num, s.Info.Hostname, s.Info.User, s.Info.OS, s.Info.Arch, s.Status)
	}

	tasks := g.Hub.Tasks("", project)
	byCmd := map[uint32]int{}
	done, failed := 0, 0
	for _, t := range tasks {
		byCmd[t.Task.Cmd]++
		switch t.Status {
		case protocol.TaskCompleted:
			done++
		case protocol.TaskFailed:
			failed++
		}
	}
	cmds := make([]int, 0, len(byCmd))
	for c := range byCmd {
		cmds = append(cmds, int(c))
	}
	sort.Ints(cmds)
	var parts []string
	for _, c := range cmds {
		parts = append(parts, fmt.Sprintf("%s×%d", cmdName(uint32(c)), byCmd[uint32(c)]))
	}
	fmt.Fprintf(&b, "\n## 任务统计\n\n- 总计 %d：完成 %d，失败 %d\n- 按类型：%s\n", len(tasks), done, failed, strings.Join(parts, "、"))

	if g.Store != nil {
		if caps, err := g.Store.PluginList(); err == nil && len(caps) > 0 {
			fmt.Fprintf(&b, "\n## 插件\n\n")
			for _, c := range caps {
				fmt.Fprintf(&b, "- %s@%s（%s）\n", c.ID, c.Version, c.Capabilities)
			}
		}
		if jobs, err := g.Store.FileJobs(project); err == nil && len(jobs) > 0 {
			fmt.Fprintf(&b, "\n## 文件传输\n\n| 作业 | 方向 | 路径 | 状态 |\n|---|---|---|---|\n")
			for _, j := range jobs {
				fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", j.ID, j.Mode, j.Remote, j.Status)
			}
		}
	}
	g.mitre(&b, project, sessions, tasks)
	g.evidence(&b, sessions, tasks)

	fmt.Fprintf(&b, "\n---\n*由 WISP++ teamserver 自动生成；仅限授权行动使用。*\n")
	return b.String()
}

// ---- MITRE ATT&CK coverage (plan §7-M6.5) ----

type tech struct {
	ID, Name, Tactic string
}

var (
	tExecUnix = tech{"T1059.004", "Command and Scripting Interpreter: Unix Shell", "Execution"}
	tExecWin  = tech{"T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution"}
	tDiscSys  = tech{"T1082", "System Information Discovery", "Discovery"}
	tDiscFile = tech{"T1083", "File and Directory Discovery", "Discovery"}
	tCapture  = tech{"T1113", "Screen Capture", "Collection"}
	tCollect  = tech{"T1005", "Data from Local System", "Collection"}
	tExfilC2  = tech{"T1041", "Exfiltration Over C2 Channel", "Exfiltration"}
	tTransfer = tech{"T1105", "Ingress Tool Transfer", "Command and Control"}
	tTunnel   = tech{"T1572", "Protocol Tunneling", "Command and Control"}
	tC2Web    = tech{"T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control"}
	tC2Nonapp = tech{"T1095", "Non-Application Layer Protocol", "Command and Control"}
	tRemove   = tech{"T1070", "Indicator Removal", "Defense Evasion"}
	tCodeLoad = tech{"T1059.006", "Command and Scripting Interpreter: Python/WASM workloads", "Execution"}
)

// mitre renders observed techniques: task→technique mapping is OS-aware
// (shell on windows counts PowerShell), file jobs split push(ingress)/grab
// (egress), listeners map to their C2 protocol technique.
func (g *Gen) mitre(b *strings.Builder, project string, sessions []core.SessionView, tasks []core.TaskRecord) {
	osOf := map[string]string{}
	for _, s := range sessions {
		osOf[s.ID] = s.Info.OS
	}
	counts := map[tech]int{}
	add := func(t tech, n int) {
		if n > 0 {
			counts[t] += n
		}
	}
	nShell, nSys, nFile, nShot, nPlugin, nKill, nTunnel := 0, 0, 0, 0, 0, 0, 0
	nShellWin := 0
	for _, t := range tasks {
		switch t.Task.Cmd {
		case protocol.CmdShell:
			if osOf[t.SessionID] == "windows" {
				nShellWin++
			} else {
				nShell++
			}
		case protocol.CmdSysinfo:
			nSys++
		case protocol.CmdPwd, protocol.CmdLsJSON:
			nFile++
		case protocol.CmdScreenshot:
			nShot++
		case protocol.CmdPluginLoad, protocol.CmdPluginExec:
			nPlugin++
		case protocol.CmdClientKill:
			nKill++
		case protocol.CmdRCPConnect:
			nTunnel++
		}
	}
	add(tExecUnix, nShell)
	add(tExecWin, nShellWin)
	add(tDiscSys, nSys)
	add(tDiscFile, nFile)
	add(tCapture, nShot)
	add(tCodeLoad, nPlugin)
	add(tRemove, nKill)
	add(tTunnel, nTunnel)
	nUp, nDown := 0, 0
	if g.Store != nil {
		if jobs, err := g.Store.FileJobs(project); err == nil {
			for _, j := range jobs {
				if j.Mode == "up" {
					nUp++
				} else {
					nDown++
				}
			}
		}
	}
	add(tCollect, nUp+nDown)
	add(tExfilC2, nUp)
	add(tTransfer, nDown)
	nWeb, nRaw := 0, 0
	if g.Mgr != nil {
		for _, l := range g.Mgr.List() {
			switch l.Kind {
			case "http", "https":
				nWeb++
			case "tcp", "kcp":
				nRaw++
			}
		}
	}
	add(tC2Web, nWeb)
	add(tC2Nonapp, nRaw)

	if len(counts) == 0 {
		return
	}
	fmt.Fprintf(b, "\n## MITRE ATT&CK 覆盖\n\n| 战术 | 技术 | 名称 | 观测次数 |\n|---|---|---|---|\n")
	rows := make([]tech, 0, len(counts))
	for t := range counts {
		rows = append(rows, t)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	for _, t := range rows {
		fmt.Fprintf(b, "| %s | %s | %s | %d |\n", t.Tactic, t.ID, t.Name, counts[t])
	}
}

// Create generates and persists a report; useAI rewrites via the configured
// model (falls back to the snapshot on any AI error).
func (g *Gen) Create(ctx context.Context, project string, useAI bool) (*db.ReportRow, error) {
	snap := g.Snapshot(project)
	md, model := snap, "template"
	if useAI && g.AI != nil {
		ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
		defer cancel()
		out, err := g.AI.Generate(ctx, "基于以下红队行动数据生成正式行动报告（Markdown，含：概述/资产清单/行动记录/MITRE ATT&CK 技术分析/风险与建议），保留数据中的 MITRE 表格与证据附录里的截图 Markdown 图片链接，补充技战术叙述，不要虚构数据：\n\n"+snap)
		if err == nil && strings.TrimSpace(out) != "" {
			md, model = out, g.AI.ModelName()
		} else if err != nil {
			g.Hub.Emit("warn", "report", orDef(project, "default"), "AI rewrite failed (%v) — template used", err)
		}
	}
	title := "行动报告 " + time.Now().Format("2006-01-02 15:04")
	r := &db.ReportRow{ID: genID(), Project: orDef(project, "default"), Title: title, Markdown: md, Model: model, Created: time.Now().Unix()}
	if g.Store != nil {
		if err := g.Store.ReportInsert(r); err != nil {
			return nil, err
		}
	}
	g.Hub.Emit("ok", "report", r.Project, "report %s generated (%s)", r.ID, model)
	return r, nil
}

func cmdName(c uint32) string {
	if n, ok := map[uint32]string{
		protocol.CmdShell: "shell", protocol.CmdSysinfo: "sysinfo", protocol.CmdPwd: "pwd",
		protocol.CmdLsJSON: "ls", protocol.CmdScreenshot: "screenshot", protocol.CmdSleep: "sleep",
		protocol.CmdClientKill: "kill", protocol.CmdPluginLoad: "plugin.load", protocol.CmdPluginExec: "plugin.exec",
	}[c]; ok {
		return n
	}
	return fmt.Sprintf("cmd#%d", c)
}

func orDef(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// evidence renders the audit appendix: every task with a sanitized output
// excerpt, grouped by session (plan §7-M6.5 "证据附录").
func (g *Gen) evidence(b *strings.Builder, sessions []core.SessionView, tasks []core.TaskRecord) {
	done := make([]core.TaskRecord, 0, len(tasks))
	for _, t := range tasks {
		if t.Status == protocol.TaskCompleted || t.Status == protocol.TaskFailed {
			done = append(done, t)
		}
	}
	if len(done) == 0 {
		return
	}
	if len(done) > 60 {
		done = done[len(done)-60:]
	}
	bySess := map[string][]core.TaskRecord{}
	for _, t := range done {
		bySess[t.SessionID] = append(bySess[t.SessionID], t)
	}
	numOf := map[string]string{}
	for _, s := range sessions {
		numOf[s.ID] = fmt.Sprintf("#%d %s (%s@%s)", s.Num, s.Info.Hostname, s.Info.User, s.Info.OS)
	}
	imgs := 0
	fmt.Fprintf(b, "\n## 证据附录（最近 %d 条任务）\n", len(done))
	ids := make([]string, 0, len(bySess))
	for id := range bySess {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		head := numOf[id]
		if head == "" {
			head = "会话 " + id[:min(12, len(id))]
		}
		fmt.Fprintf(b, "\n### %s\n\n", head)
		for _, t := range bySess[id] {
			ts := time.Unix(t.Task.Created, 0).Format("01-02 15:04:05")
			c := cmdName(t.Task.Cmd)
			var argsh struct {
				Command string `json:"command"`
			}
			if json.Unmarshal(t.Task.Args, &argsh) == nil && argsh.Command != "" {
				c = fmt.Sprintf("shell: %s", sanitizeLine(argsh.Command, 120))
			}
			st := "✓"
			if t.Status == protocol.TaskFailed {
				st = "✗"
			}
			fmt.Fprintf(b, "- `%s` %s **%s**", ts, st, c)
			if t.Result != nil && t.Result.Exit != 0 {
				fmt.Fprintf(b, " (exit=%d)", t.Result.Exit)
			}
			fmt.Fprintln(b)
			if img := shotData(resultOutput(t)); img != "" && imgs < 4 {
				fmt.Fprintf(b, "  ![screenshot](%s)\n", img)
				imgs++
			} else if out := sanitize(resultOutput(t), 400); out != "" {
				fmt.Fprintf(b, "  ```\n  %s\n  ```\n", strings.ReplaceAll(out, "\n", "\n  "))
			}
		}
	}
}

// sanitize strips ANSI/control noise and caps length for report embedding.
func sanitize(s string, max int) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range s {
		if r == '\n' || r == '\t' || r >= 32 {
			b.WriteRune(r)
		}
	}
	s = collapse(b.String())
	rs := []rune(s)
	if len(rs) > max {
		s = string(rs[:max]) + " …"
	}
	return strings.TrimSpace(s)
}

func collapse(s string) string {
	var b strings.Builder
	prevSpace := false
	for _, r := range s {
		if r == ' ' || r == '\t' {
			if !prevSpace {
				b.WriteRune(' ')
			}
			prevSpace = true
			continue
		}
		prevSpace = false
		b.WriteRune(r)
	}
	return b.String()
}

func sanitizeLine(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	rs := []rune(s)
	if len(rs) > max {
		return string(rs[:max]) + "…"
	}
	return s
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func resultOutput(t core.TaskRecord) string {
	if t.Result == nil {
		return ""
	}
	return t.Result.Output
}

// shotData extracts an embedded data-URL image from a screenshot task result
// (size-capped so reports stay lean).
func shotData(out string) string {
	if !strings.HasPrefix(out, `{"img":"data:image`) {
		return ""
	}
	var o struct {
		Img string `json:"img"`
	}
	if json.Unmarshal([]byte(out), &o) != nil || !strings.HasPrefix(o.Img, "data:image") {
		return ""
	}
	if len(o.Img) > 900_000 {
		return ""
	}
	return o.Img
}
