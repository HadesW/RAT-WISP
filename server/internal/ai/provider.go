// Package ai: server-side AI agent runtime (plan §7-M6). Providers speak
// tool-calling; read tools auto-execute, write tools REQUIRE operator
// approval before running. The mock provider keeps the whole loop testable
// without any API key.
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// ---- wire types ----

type Call struct {
	ID   string          `json:"id"`
	Name string          `json:"name"`
	Args json.RawMessage `json:"arguments"`
}

type Msg struct {
	Role       string `json:"role"` // system|user|assistant|tool
	Content    string `json:"content,omitempty"`
	ToolCalls  []Call `json:"tool_calls,omitempty"`
	ToolCallID string `json:"tool_call_id,omitempty"`
	Name       string `json:"name,omitempty"`
}

type ToolSpec struct {
	Name   string          `json:"name"`
	Desc   string          `json:"description"`
	Params json.RawMessage `json:"parameters"`
	Write  bool            `json:"-"` // true => approval gate before execution
}

// CompleteOpts carries per-call generation knobs.
type CompleteOpts struct {
	Effort string // reasoning effort: "" | off | minimal | low | medium | high
}

type Provider interface {
	Name() string
	Model() string
	Complete(ctx context.Context, msgs []Msg, tools []ToolSpec, opts CompleteOpts) (Msg, error)
}

// ---- OpenAI-compatible provider ----

type OpenAICompat struct {
	Endpoint  string
	APIKey    string
	ModelName string
	Client    *http.Client
}

func (o *OpenAICompat) Name() string  { return "openai-compat" }
func (o *OpenAICompat) Model() string { return o.ModelName }

type oaMsg struct {
	Role       string   `json:"role"`
	Content    string   `json:"content,omitempty"`
	ToolCalls  []oaCall `json:"tool_calls,omitempty"`
	ToolCallID string   `json:"tool_call_id,omitempty"`
	Name       string   `json:"name,omitempty"`
}

type oaCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

func (o *OpenAICompat) Complete(ctx context.Context, msgs []Msg, tools []ToolSpec, opts CompleteOpts) (Msg, error) {
	om := make([]oaMsg, 0, len(msgs))
	for _, m := range msgs {
		x := oaMsg{Role: m.Role, Content: m.Content, ToolCallID: m.ToolCallID, Name: m.Name}
		for _, c := range m.ToolCalls {
			call := oaCall{ID: c.ID, Type: "function"}
			call.Function.Name = c.Name
			call.Function.Arguments = string(c.Args)
			x.ToolCalls = append(x.ToolCalls, call)
		}
		om = append(om, x)
	}
	oat := make([]map[string]any, 0, len(tools))
	for _, t := range tools {
		oat = append(oat, map[string]any{"type": "function", "function": map[string]any{
			"name": t.Name, "description": t.Desc, "parameters": json.RawMessage(t.Params)}})
	}
	params := map[string]any{"model": o.ModelName, "messages": om, "tools": oat, "tool_choice": "auto"}
	if opts.Effort != "" && opts.Effort != "off" {
		params["reasoning_effort"] = opts.Effort // honored by OpenAI-compatible reasoning endpoints
	}
	if opts.Effort == "off" {
		params["enable_thinking"] = false // dashscope-compatible toggle
	}
	body, _ := json.Marshal(params)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(o.Endpoint, "/")+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return Msg{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if o.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+o.APIKey)
	}
	resp, err := o.Client.Do(req)
	if err != nil {
		return Msg{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		return Msg{}, fmt.Errorf("ai provider HTTP %d: %s", resp.StatusCode, string(raw[:min(len(raw), 300)]))
	}
	var out struct {
		Choices []struct {
			Message oaMsg `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || len(out.Choices) == 0 {
		return Msg{}, fmt.Errorf("ai provider bad response: %s", string(raw[:min(len(raw), 300)]))
	}
	m := out.Choices[0].Message
	msg := Msg{Role: m.Role, Content: m.Content}
	for _, c := range m.ToolCalls {
		msg.ToolCalls = append(msg.ToolCalls, Call{ID: c.ID, Name: c.Function.Name, Args: json.RawMessage(c.Function.Arguments)})
	}
	return msg, nil
}

// ---- mock provider: deterministic, offline, exercises the FULL loop ----

type Mock struct{ ModelName string }

func (m *Mock) Name() string  { return "mock" }
func (m *Mock) Model() string { return orDefault(m.ModelName, "wispp-mock") }

var reWho = regexp.MustCompile(`(?i)(whoami|id|命令|执行|跑|检查|看看|收集|uname|sysinfo|汇总|提权|权限)`)

func (m *Mock) Complete(_ context.Context, msgs []Msg, _ []ToolSpec, _ CompleteOpts) (Msg, error) {
	var user string
	var toolResults []Msg
	sawSessions := false
	sawTaskResults := false
	for _, x := range msgs {
		switch x.Role {
		case "user":
			user = x.Content
		case "tool":
			toolResults = append(toolResults, x)
			if x.Name == "list_sessions" {
				sawSessions = true
			}
			if x.Name == "run_task" {
				sawTaskResults = true
			}
		}
	}

	if sawTaskResults {
		last := toolResults[len(toolResults)-1].Content
		if strings.Contains(last, "\"rejected\"") || strings.Contains(last, "\"pending_approval\"") {
			return Msg{Role: "assistant", Content: "操作员未批准该操作，未执行任何变更。需要我换一个更稳妥的方案吗？"}, nil
		}
		// summarize executed batch (last tool message holds the results JSON)
		var res []struct {
			Session string `json:"session"`
			Status  string `json:"status"`
			Output  string `json:"output"`
		}
		_ = json.Unmarshal([]byte(last), &res)
		var b strings.Builder
		ok := 0
		for _, r := range res {
			if r.Status == "completed" {
				ok++
			}
		}
		fmt.Fprintf(&b, "批量执行完成：%d/%d 个会话成功返回。\n\n", ok, len(res))
		for _, r := range res {
			out := r.Output
			if len(out) > 60 {
				out = out[:60] + "…"
			}
			fmt.Fprintf(&b, "- 会话 %s → [%s] %s\n", short(r.Session), r.Status, strings.ReplaceAll(out, "\n", " | "))
		}
		b.WriteString("\n需要我基于这些结果继续规划下一步（例如横向/提权建议）吗？")
		return Msg{Role: "assistant", Content: b.String()}, nil
	}

	if sawSessions && reWho.MatchString(user) {
		// propose batch run_task (WRITE → will hit the approval gate)
		cmd := "whoami"
		if strings.Contains(user, "sysinfo") || strings.Contains(user, "信息") {
			cmd = "sysinfo"
		}
		args, _ := json.Marshal(map[string]any{
			"sessions": []string{"__ALL__"},
			"cmd":      "shell",
			"command":  cmd,
			"note":     fmt.Sprintf("批量 shell: %s", cmd),
		})
		return Msg{Role: "assistant", Content: "我先枚举了在线会话，建议对这些会话批量下发命令，需要操作员审批。", ToolCalls: []Call{
			{ID: "call_batch_1", Name: "run_task", Args: args}}}, nil
	}

	if reWho.MatchString(user) {
		return Msg{Role: "assistant", Content: "收到，先查看当前会话清单。", ToolCalls: []Call{
			{ID: "call_ls_1", Name: "list_sessions", Args: json.RawMessage(`{}`)}}}, nil
	}

	return Msg{Role: "assistant", Content: fmt.Sprintf(
		"(mock 模式) 已收到：%q。试试「对所有会话跑 whoami 并汇总」——我会列会话、申请审批、执行并总结。在配置管理中接入 OpenAI 兼容接口后此处由真实模型回答。", user)}, nil
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func short(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

func NewHTTPClient() *http.Client { return &http.Client{Timeout: 60 * time.Second} }
