package api

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"wispp/server/internal/payload"
)

func (a *DebugAPI) payloadPlatforms(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.Payloads.Platforms())
}

// payloadCapabilities exposes the P0 generation matrix: available combos plus
// planned options with their phase, so the builder never offers a dead end.
func (a *DebugAPI) payloadCapabilities(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.Payloads.Capabilities())
}

func (a *DebugAPI) payloadsList(w http.ResponseWriter, r *http.Request) {
	list := a.Payloads.List()
	if project := r.URL.Query().Get("project"); project != "" {
		out := make([]payload.Meta, 0, len(list))
		for _, m := range list {
			if m.Project == project {
				out = append(out, m)
			}
		}
		list = out
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *DebugAPI) payloadCreate(w http.ResponseWriter, r *http.Request) {
	var spec payload.Spec
	if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	m, err := a.Payloads.Create(spec)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, m)
}

func (a *DebugAPI) payloadDownload(w http.ResponseWriter, r *http.Request) {
	m, err := a.Payloads.Resolve(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data, err := os.ReadFile(m.Path)
	if err != nil {
		http.Error(w, "artifact missing", http.StatusGone)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+m.Name+`"`)
	_, _ = w.Write(data)
}

func (a *DebugAPI) payloadDelete(w http.ResponseWriter, r *http.Request) {
	if err := a.Payloads.Delete(r.PathValue("id")); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type payloadPushReq struct {
	Session string `json:"session"`
	Remote  string `json:"remote,omitempty"`
}

// payloadPush delivers a generated artifact straight to an online agent over
// Type3 (no round-trip through the operator's browser downloads folder).
func (a *DebugAPI) payloadPush(w http.ResponseWriter, r *http.Request) {
	var req payloadPushReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.Session == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session required"})
		return
	}
	m, err := a.Payloads.Resolve(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	if proj := a.projectOf(req.Session); m.Project != "" && m.Project != proj {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": "payload belongs to project " + m.Project + ", session project is " + proj,
		})
		return
	}
	remote := strings.TrimSpace(req.Remote)
	if remote == "" {
		if m.OS == "windows" {
			remote = `C:\Windows\Temp\` + m.Name
		} else {
			remote = "/tmp/" + m.Name
		}
	}
	// The console builds a launcher command around this path; reject characters
	// that would break out of either the cmd.exe or /bin/sh quoting.
	if strings.ContainsAny(remote, "\x00\r\n\"'`$") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "remote path contains unsupported characters"})
		return
	}
	job, err := a.Files.Push(req.Session, a.projectOf(req.Session), m.Path, remote)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"job": job, "remote": remote})
}

func (a *DebugAPI) payloadTemplates(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.Payloads.Templates())
}

type payloadRearmReq struct {
	StageTTLSeconds int `json:"stage_ttl_seconds,omitempty"`
	StageUses       int `json:"stage_uses,omitempty"`
}

// payloadRearm restores the fetch allowance of an existing staged artifact
// (same token, no re-download needed).
func (a *DebugAPI) payloadRearm(w http.ResponseWriter, r *http.Request) {
	var req payloadRearmReq
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}
	m, err := a.Payloads.Rearm(r.PathValue("id"), req.StageTTLSeconds, req.StageUses)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, m)
}
