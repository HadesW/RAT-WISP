package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"wispp/server/internal/ai"
)

func (a *DebugAPI) aiStatus(w http.ResponseWriter, _ *http.Request) {
	if a.AI == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	st := a.AI.Redacted()
	if pend, err := a.AI.PendingApprovals(); err == nil {
		st["pending"] = len(pend)
	}
	writeJSON(w, http.StatusOK, st)
}

func (a *DebugAPI) aiHistory(w http.ResponseWriter, r *http.Request) {
	if a.AI == nil || !a.AI.On() {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	msgs, _ := a.AI.History(r.URL.Query().Get("conv"), 200)
	writeJSON(w, http.StatusOK, msgs)
}

// aiChat streams assistant/tool events as Server-Sent Events.
func (a *DebugAPI) aiChat(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Conv    string `json:"conv"`
		Text    string `json:"text"`
		Lang    string `json:"lang"`
		Project string `json:"project"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Text == "" {
		http.Error(w, "text required", http.StatusBadRequest)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	emit := func(ev ai.Event) {
		b, _ := json.Marshal(ev)
		_, _ = w.Write([]byte("data: "))
		_, _ = w.Write(b)
		_, _ = w.Write([]byte("\n\n"))
		flusher.Flush()
	}
	if a.AI == nil {
		emit(ai.Event{Type: "error", Content: "AI 未启用：在「设置」页配置并开启"})
		emit(ai.Event{Type: "done"})
		return
	}
	if req.Project == "" {
		req.Project = "default"
	}
	if err := a.AI.ChatStream(r.Context(), req.Conv, req.Project, req.Text, req.Lang, emit); err != nil {
		if errors.Is(err, ai.ErrDisabled) {
			emit(ai.Event{Type: "error", Content: "AI 未启用"})
		}
	}
}

// approvalsList: pending write-tool approvals across the teamserver.
func (a *DebugAPI) aiApprovals(w http.ResponseWriter, _ *http.Request) {
	if a.AI == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	pend, _ := a.AI.PendingApprovals()
	writeJSON(w, http.StatusOK, pend)
}

// aiDecide approves/rejects an approval and streams the follow-up as SSE.
func (a *DebugAPI) aiDecide(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Approve bool `json:"approve"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	flusher, _ := w.(http.Flusher)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	emit := func(ev ai.Event) {
		if flusher == nil {
			return
		}
		b, _ := json.Marshal(ev)
		_, _ = w.Write([]byte("data: "))
		_, _ = w.Write(b)
		_, _ = w.Write([]byte("\n\n"))
		flusher.Flush()
	}
	if a.AI == nil {
		emit(ai.Event{Type: "error", Content: "AI 未启用"})
		return
	}
	evs, err := a.AI.Decide(r.Context(), r.PathValue("id"), req.Approve)
	for _, e := range evs {
		emit(e)
	}
	if err != nil {
		emit(ai.Event{Type: "error", Content: err.Error()})
	}
	emit(ai.Event{Type: "done"})
}

// ---- 设置页 AI 配置端点 ----

// cfgAIGet returns the AI config with the secret masked.
func (a *DebugAPI) cfgAIGet(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.AI.Redacted())
}

// cfgAIPut hot-applies the full config (enabled/active/profiles[]) and persists.
func (a *DebugAPI) cfgAIPut(w http.ResponseWriter, r *http.Request) {
	var c ai.Config
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if len(c.Profiles) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "at least one profile required"})
		return
	}
	a.AI.Configure(c)
	if err := a.AI.Save(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "in-memory ok, disk write failed: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, a.AI.Redacted())
}

// cfgAIActive switches the active profile (model quick-picker).
func (a *DebugAPI) cfgAIActive(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}
	if err := a.AI.SetActive(req.Name); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	_ = a.AI.Save()
	writeJSON(w, http.StatusOK, a.AI.Redacted())
}

// cfgAITest probes one profile (form values may be unsaved; empty api_key
// falls back to the stored profile key).
func (a *DebugAPI) cfgAITest(w http.ResponseWriter, r *http.Request) {
	var probe ai.Profile
	_ = json.NewDecoder(r.Body).Decode(&probe)
	if probe.Provider == "" {
		if p, ok := a.AI.Conf().Pick(a.AI.Conf().Active); ok {
			probe = p
		}
	}
	t0 := time.Now()
	if err := a.AI.Test(probe); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "ms": time.Since(t0).Milliseconds(), "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "ms": time.Since(t0).Milliseconds()})
}

// cfgAIModels proxies GET {endpoint}/models for the model picker.
func (a *DebugAPI) cfgAIModels(w http.ResponseWriter, r *http.Request) {
	ids, err := a.AI.ListModels(r.URL.Query().Get("endpoint"), r.URL.Query().Get("key"), r.URL.Query().Get("profile"))
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"models": ids})
}

// ---- conversations (新建/切换/重命名/删除) ----

func (a *DebugAPI) aiConversations(w http.ResponseWriter, r *http.Request) {
	if a.AI == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	writeJSON(w, http.StatusOK, a.AI.Conversations(r.URL.Query().Get("project")))
}

func (a *DebugAPI) aiRename(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Title string `json:"title"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Title == "" {
		http.Error(w, "title required", http.StatusBadRequest)
		return
	}
	if err := a.AI.RenameConversation(r.PathValue("id"), req.Title); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *DebugAPI) aiDelete(w http.ResponseWriter, r *http.Request) {
	if err := a.AI.DeleteConversation(r.PathValue("id")); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
