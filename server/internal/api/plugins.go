package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"wispp/protocol"
	"wispp/server/internal/pluginstore"
)

func (a *DebugAPI) pluginsList(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.Plugins.List())
}

// pluginInstall body: {manifest, module_b64, sig} (sig = ed25519 over
// manifest||module, hex or base64).
func (a *DebugAPI) pluginInstall(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Manifest  string `json:"manifest"`
		ModuleB64 string `json:"module_b64"`
		Sig       string `json:"sig"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	module, err := decodeB64(req.ModuleB64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "module: " + err.Error()})
		return
	}
	m, err := a.Plugins.Install(req.Manifest, module, req.Sig)
	if err != nil {
		code := http.StatusBadRequest
		if err == pluginstore.ErrBadSig {
			code = http.StatusForbidden
		}
		writeJSON(w, code, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, m)
}

func (a *DebugAPI) pluginEnable(w http.ResponseWriter, r *http.Request) {
	var req struct {
		On bool `json:"on"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if err := a.Plugins.SetEnabled(r.PathValue("id"), req.On); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *DebugAPI) pluginDelete(w http.ResponseWriter, r *http.Request) {
	if err := a.Plugins.Delete(r.PathValue("id")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// pluginDeploy queues CmdPluginLoad to the given sessions ("online" = all).
// Small modules travel base64'd; native DLLs go through the Type4 stage
// endpoint so multi-megabyte modules never hit task-payload limits.
func (a *DebugAPI) pluginDeploy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Sessions []string `json:"sessions"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	man, err := a.Plugins.ManifestOf(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	var args *protocol.PluginLoadArgs
	if man.Kind == "native-dll" {
		args, err = a.Plugins.LoadArgsStaged(man.ID, a.anyOrigin())
	} else {
		args, err = a.Plugins.LoadArgs(man.ID)
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	ids := req.Sessions
	if len(ids) == 1 && ids[0] == "online" {
		ids = nil
		for _, s := range a.Hub.Sessions("") {
			if s.Status == protocol.StatusOnline {
				ids = append(ids, s.ID)
			}
		}
	}
	var queued []map[string]string
	for _, sid := range ids {
		rec, err := a.Hub.Enqueue(sid, protocol.CmdPluginLoad, args)
		if err != nil {
			continue
		}
		a.Plugins.RecordCall(sid, args.ID, "load", "queued")
		queued = append(queued, map[string]string{"session": sid, "task": rec.Task.ID})
	}
	writeJSON(w, http.StatusAccepted, queued)
}

// anyOrigin returns the most reachable Type1 origin for stage URLs.
func (a *DebugAPI) anyOrigin() string {
	if a.Manager == nil {
		return ""
	}
	sp, ok := a.Manager.AnyHTTP()
	if !ok {
		return ""
	}
	servers, _, err := a.Manager.ServersFor(sp.ID)
	if err != nil || len(servers) == 0 {
		return ""
	}
	return servers[0]
}

// pluginExec queues one plugin call (ABI v0: a/b ints; ABI v1: args JSON).
func (a *DebugAPI) pluginExec(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Session string          `json:"session"`
		Entry   string          `json:"entry"`
		A       int             `json:"a"`
		B       int             `json:"b"`
		Args    json.RawMessage `json:"args"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Session == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session required"})
		return
	}
	rec, err := a.Hub.Enqueue(req.Session, protocol.CmdPluginExec, protocol.PluginExecArgs{
		ID: r.PathValue("id"), Entry: req.Entry, A: int32(req.A), B: int32(req.B), Args: req.Args})
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	a.Plugins.RecordCall(req.Session, r.PathValue("id"), req.Entry, "queued")
	writeJSON(w, http.StatusAccepted, rec)
}

func (a *DebugAPI) pluginCalls(w http.ResponseWriter, _ *http.Request) {
	rows, _ := a.Store.PluginCalls(50)
	writeJSON(w, http.StatusOK, rows)
}

func decodeB64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
