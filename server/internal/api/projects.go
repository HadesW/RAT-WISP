package api

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
)

var projectIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

type projectReq struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Color string `json:"color"`
}

// projectCreate adds a project row (id immutable, used by sessions/listeners).
func (a *DebugAPI) projectCreate(w http.ResponseWriter, r *http.Request) {
	var req projectReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	id := strings.TrimSpace(req.ID)
	if !projectIDPattern.MatchString(id) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id must match [A-Za-z0-9_-]{1,32}"})
		return
	}
	if a.Store == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "storage unavailable"})
		return
	}
	if rows, err := a.Store.Projects(); err == nil {
		for _, row := range rows {
			if row[0] == id {
				writeJSON(w, http.StatusConflict, map[string]string{"error": "project already exists"})
				return
			}
		}
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = id
	}
	color := strings.TrimSpace(req.Color)
	if color == "" {
		color = "#8B93A7"
	}
	if err := a.Store.EnsureProject(id, name, color); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"ID": id, "Name": name, "Color": color})
}

// projectUpdate renames/recolors an existing project (id stays immutable).
func (a *DebugAPI) projectUpdate(w http.ResponseWriter, r *http.Request) {
	var req projectReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if a.Store == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "storage unavailable"})
		return
	}
	id := r.PathValue("id")
	rows, err := a.Store.Projects()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	var name, color string
	found := false
	for _, row := range rows {
		if row[0] == id {
			name, color, found = row[1], row[2], true
			break
		}
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown project"})
		return
	}
	if n := strings.TrimSpace(req.Name); n != "" {
		name = n
	}
	if c := strings.TrimSpace(req.Color); c != "" {
		color = c
	}
	if err := a.Store.EnsureProject(id, name, color); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ID": id, "Name": name, "Color": color})
}
