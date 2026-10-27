package api

import (
	"encoding/json"
	"net/http"
)

func (a *DebugAPI) reportsList(w http.ResponseWriter, r *http.Request) {
	rows, err := a.Store.ReportList(r.URL.Query().Get("project"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func (a *DebugAPI) reportCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Project string `json:"project"`
		AI      bool   `json:"ai"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	row, err := a.Reports.Create(r.Context(), req.Project, req.AI)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": row.ID, "title": row.Title, "model": row.Model})
}

func (a *DebugAPI) reportGet(w http.ResponseWriter, r *http.Request) {
	row, err := a.Store.ReportGet(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if r.URL.Query().Get("raw") == "md" {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="report-`+row.ID+`.md"`)
		_, _ = w.Write([]byte(row.Markdown))
		return
	}
	writeJSON(w, http.StatusOK, row)
}

func (a *DebugAPI) reportDelete(w http.ResponseWriter, r *http.Request) {
	if err := a.Store.ReportDelete(r.PathValue("id")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
