package api

import (
	"encoding/json"
	"net/http"
	"path/filepath"

	"wispp/server/internal/core"
	"wispp/server/internal/db"
)

// ---- Type3 file transfer endpoints (plan §2.4) ----

func (a *DebugAPI) fileJobs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.Files.Jobs(r.URL.Query().Get("project")))
}

type createFileJobReq struct {
	Mode   string `json:"mode"` // up | down
	Remote string `json:"remote"`
	Inbox  string `json:"inbox,omitempty"` // operator upload id (down mode)
}

func (a *DebugAPI) createFileJob(w http.ResponseWriter, r *http.Request) {
	var req createFileJobReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	var (
		job *db.FileJob
		err error
	)
	switch req.Mode {
	case "up":
		job, err = a.Files.Grab(r.PathValue("id"), a.projectOf(r.PathValue("id")), req.Remote)
	case "down":
		src := a.Files.InboxPath(req.Inbox)
		if req.Inbox == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "inbox id required (upload first)"})
			return
		}
		job, err = a.Files.Push(r.PathValue("id"), a.projectOf(r.PathValue("id")), src, req.Remote)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "mode must be up|down"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, job)
}

func (a *DebugAPI) retryFileJob(w http.ResponseWriter, r *http.Request) {
	if err := a.Files.Retry(r.PathValue("job")); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"ok": true})
}

// fileDownload streams a finished up-job file to the operator (Range-aware).
func (a *DebugAPI) fileDownload(w http.ResponseWriter, r *http.Request) {
	jobs, err := a.Files.Store().FileJobs("")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, j := range jobs {
		if j.ID == r.PathValue("job") {
			if j.Status != "done" || j.Local == "" {
				http.Error(w, "job not completed", http.StatusConflict)
				return
			}
			name := filepath.Base(j.Remote)
			w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
			http.ServeFile(w, r, j.Local)
			return
		}
	}
	http.NotFound(w, r)
}

// fileUpload stores an operator file into the inbox (raw body); the returned
// id feeds a subsequent "down" job creation.
func (a *DebugAPI) fileUpload(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	id := core.NewTaskID()
	if _, err := a.Files.SaveInbox(r.Body, id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"inbox": id, "name": r.URL.Query().Get("name")})
}
