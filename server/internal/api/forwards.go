package api

import (
	"encoding/json"
	"net/http"
	"strings"
)

func (a *DebugAPI) fwdList(w http.ResponseWriter, _ *http.Request) {
	rows := a.Forwards.List()
	out := rows[:0]
	for _, r := range rows {
		if !strings.HasPrefix(r.Target, "socks5://") {
			out = append(out, r)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *DebugAPI) fwdCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Session string `json:"session"`
		Listen  string `json:"listen"`
		Target  string `json:"target"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Session == "" || req.Target == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session+target required"})
		return
	}
	if !strings.Contains(req.Listen, ":") || strings.HasSuffix(req.Listen, ":") {
		req.Listen = "127.0.0.1:0"
	}
	id, bound, err := a.Forwards.Start(req.Session, req.Listen, req.Target)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": id, "listen": bound, "target": req.Target})
}

func (a *DebugAPI) fwdStop(w http.ResponseWriter, r *http.Request) {
	if err := a.Forwards.Stop(r.PathValue("id")); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
