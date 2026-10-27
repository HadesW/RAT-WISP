package api

import (
	"encoding/json"
	"net/http"
	"strings"
)

func (a *DebugAPI) socksList(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.Socks.List())
}

func (a *DebugAPI) socksCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Session string `json:"session"`
		Listen  string `json:"listen"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Session == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session required"})
		return
	}
	if req.Listen == "" || !strings.Contains(req.Listen, ":") || strings.HasSuffix(req.Listen, ":") {
		req.Listen = "127.0.0.1:0"
	}
	id, bound, err := a.Socks.Start(req.Session, req.Listen)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": id, "listen": bound})
}

func (a *DebugAPI) socksStop(w http.ResponseWriter, r *http.Request) {
	if err := a.Socks.Stop(r.PathValue("id")); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
