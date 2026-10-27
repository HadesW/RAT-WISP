package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"wispp/server/internal/db"
	"wispp/server/internal/orchestration"
)

func (a *DebugAPI) goalsList(w http.ResponseWriter, r *http.Request) {
	rows, err := a.Store.GoalList(r.URL.Query().Get("project"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func (a *DebugAPI) goalGet(w http.ResponseWriter, r *http.Request) {
	g, err := a.Store.GoalGet(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	steps, _ := a.Store.Steps(g.ID)
	writeJSON(w, http.StatusOK, map[string]any{"goal": g, "steps": steps})
}

func (a *DebugAPI) goalCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Project string                   `json:"project"`
		Title   string                   `json:"title"`
		Steps   []orchestration.StepSpec `json:"steps"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Title == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "title+steps required"})
		return
	}
	g, err := a.Goals.CreateGoal(req.Project, req.Title, req.Steps)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, g)
}

// goalPlan asks the AI for a draft step chain (not yet a goal).
func (a *DebugAPI) goalPlan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Prompt string `json:"prompt"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	steps, err := a.Goals.Plan(req.Prompt)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"steps": steps})
}

func (a *DebugAPI) goalStart(w http.ResponseWriter, r *http.Request) {
	if err := a.Goals.Start(r.PathValue("id")); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *DebugAPI) goalPause(w http.ResponseWriter, r *http.Request) {
	a.Goals.Pause(r.PathValue("id"))
	w.WriteHeader(http.StatusNoContent)
}

func (a *DebugAPI) goalDelete(w http.ResponseWriter, r *http.Request) {
	a.Goals.Pause(r.PathValue("id"))
	if err := a.Store.GoalDelete(r.PathValue("id")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// stepDecide approves/rejects a gate; stepEdit handles add/move/remove on drafts.
func (a *DebugAPI) stepPatch(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	st, err := a.Store.StepGet(id)
	if err != nil || st == nil {
		http.Error(w, "unknown step", http.StatusNotFound)
		return
	}
	g, err := a.Store.GoalGet(st.Goal)
	if err != nil || g == nil {
		http.Error(w, "unknown goal", http.StatusNotFound)
		return
	}
	if g.Status != "draft" && g.Status != "paused" {
		http.Error(w, "steps editable only while draft/paused", http.StatusConflict)
		return
	}
	var req struct {
		Name *string         `json:"name"`
		Args *map[string]any `json:"args"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	name, args := "", ""
	if req.Name != nil && *req.Name != "" {
		name = *req.Name
	}
	if req.Args != nil {
		merged := map[string]any{}
		_ = json.Unmarshal([]byte(st.Args), &merged)
		for k, v := range *req.Args {
			merged[k] = v
		}
		if b, err := json.Marshal(merged); err == nil {
			args = string(b)
		}
	}
	if name == "" && args == "" {
		http.Error(w, "nothing to patch", http.StatusBadRequest)
		return
	}
	if err := a.Store.StepPatch(id, name, args); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": "patched"})
}

func (a *DebugAPI) stepDecide(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Approve bool `json:"approve"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if err := a.Goals.Decide(r.PathValue("id"), req.Approve); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *DebugAPI) stepAdd(w http.ResponseWriter, r *http.Request) {
	var sp orchestration.StepSpec
	if err := json.NewDecoder(r.Body).Decode(&sp); err != nil {
		http.Error(w, "bad step", http.StatusBadRequest)
		return
	}
	goalID := r.PathValue("id")
	steps, _ := a.Store.Steps(goalID)
	args, _ := json.Marshal(sp)
	name := sp.Name
	if name == "" {
		name = sp.Kind
	}
	b := make([]byte, 5)
	_, _ = rand.Read(b)
	err := a.Store.StepInsert(&db.StepRow{ID: hex.EncodeToString(b), Goal: goalID, Seq: len(steps) + 1, Name: name, Kind: sp.Kind, Args: string(args), Status: "pending"})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (a *DebugAPI) stepDelete(w http.ResponseWriter, r *http.Request) {
	st, err := a.Store.StepGet(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if st.Status == "running" || st.Status == "awaiting" {
		http.Error(w, "step active; pause goal first", http.StatusConflict)
		return
	}
	_ = a.Store.StepDelete(r.PathValue("id"))
	// renumber
	steps, _ := a.Store.Steps(st.Goal)
	for i, x := range steps {
		_ = a.Store.StepMove(x.ID, i+1)
	}
	w.WriteHeader(http.StatusNoContent)
}
