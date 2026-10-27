package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/coder/websocket"

	"wispp/protocol"

	"wispp/server/internal/rcp"
)

// RCPConnect asks (over Type1) the agent to dial its Type2 channel now —
// remote-control is on-demand: right-click → connect, close → destroy.
func (a *DebugAPI) RCPConnect(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	if a.Manager == nil {
		http.Error(w, "no listener manager", http.StatusInternalServerError)
		return
	}
	addr := a.Manager.RCPAdvertised()
	if addr == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no running rcp listener"})
		return
	}
	if a.RCP.Online(agentID) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "already-online"})
		return
	}
	_, err := a.Hub.Enqueue(agentID, protocol.CmdRCPConnect, map[string]string{
		"addr": addr, "token": protocol.RCPToken(a.RCP.PSK, agentID),
	})
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()}) // Type1 offline
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "dialing", "addr": addr})
}

// RCPDisconnect tells the agent (Type1) to drop Type2 and severs it server-side now.
func (a *DebugAPI) RCPDisconnect(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	_, _ = a.Hub.Enqueue(agentID, protocol.CmdRCPDisconnect, nil) // best-effort: agent may be Type1-offline
	a.RCP.Drop(agentID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "dropped"})
}

// RCPChannel bridges one browser socket to one RCP logical channel
// (plan §2.3: WS <-> RCP frame relay for terminal / desktop).
// GET /api/rcp/{id}/channel?kind=shell|view  (token via auth middleware)
func (a *DebugAPI) RCPChannel(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	kind := r.URL.Query().Get("kind")
	if kind != "shell" && kind != "view" {
		http.Error(w, "kind must be shell|view", http.StatusBadRequest)
		return
	}
	if kind == "view" {
		if ready, queued := a.ensurePluginCap(agentID, "rdp"); !ready {
			if queued {
				writeJSON(w, http.StatusServiceUnavailable,
					map[string]string{"error": "rdp plugin loading — retry in a few seconds"})
			} else {
				writeJSON(w, http.StatusServiceUnavailable,
					map[string]string{"error": "rdp feature unavailable (no rdp plugin installed / agent offline)"})
			}
			return
		}
	}
	ch, err := a.RCP.Open(agentID, kind, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway) // agent offline or gone
		return
	}
	defer a.RCP.Close(agentID, ch.ID, "client closed")

	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// same-origin dev console; operator token already validated upstream
		InsecureSkipVerify: true, //nolint:gosec // localhost surface, token-gated
	})
	if err != nil {
		return
	}
	defer ws.CloseNow()
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// agent -> browser
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case d, ok := <-ch.Sub():
				if !ok {
					ws.Close(websocket.StatusNormalClosure, "channel closed")
					cancel()
					return
				}
				if d.Ctrl {
					// Shell control messages (hello/resize) reach the console as
					// text frames; the view channel keeps its legacy JSON input
					// path, which never produces control frames agent-side.
					if err := ws.Write(ctx, websocket.MessageText, d.Data); err != nil {
						cancel()
						return
					}
					continue
				}
				if err := ws.Write(ctx, websocket.MessageBinary, d.Data); err != nil {
					cancel()
					return
				}
			}
		}
	}()

	// browser -> agent: shell text frames are JSON control (resize), binary
	// frames are terminal input. View channels carry raw JSON input events.
	for {
		typ, data, err := ws.Read(ctx)
		if err != nil {
			return
		}
		if typ != websocket.MessageBinary && typ != websocket.MessageText {
			continue
		}
		if kind == "shell" && typ == websocket.MessageText {
			_ = a.RCP.SendCtrl(agentID, ch.ID, data)
			continue
		}
		_ = a.RCP.Input(agentID, ch.ID, data)
	}
}

// RCPStatus: is an agent's Type2 path live?
func (a *DebugAPI) RCPStatus(w http.ResponseWriter, r *http.Request) {
	on := a.RCP.Online(r.PathValue("id"))
	b, _ := json.Marshal(map[string]bool{"online": on})
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

var _ = rcp.ErrNotOnline

// ensurePluginCap reports whether the session already advertises cap. When an
// installed plugin offers it but the session lacks it, the plugin is deployed
// (queued=true) and the caller answers 503 so the operator retries.
func (a *DebugAPI) ensurePluginCap(agentID, cap string) (ready, queued bool) {
	for _, sv := range a.Hub.Sessions("") {
		if sv.ID != agentID {
			continue
		}
		for _, c := range sv.Caps {
			if c == cap {
				return true, false
			}
		}
	}
	for _, row := range a.Plugins.List() {
		if !row.Enabled {
			continue
		}
		var caps []string
		if json.Unmarshal([]byte(row.Capabilities), &caps) != nil {
			continue
		}
		has := false
		for _, c := range caps {
			if c == cap {
				has = true
				break
			}
		}
		if !has {
			continue
		}
		man, err := a.Plugins.ManifestOf(row.ID)
		if err != nil {
			continue
		}
		var args *protocol.PluginLoadArgs
		if man.Kind == "native-dll" {
			args, err = a.Plugins.LoadArgsStaged(row.ID, a.anyOrigin())
		} else {
			args, err = a.Plugins.LoadArgs(row.ID)
		}
		if err != nil {
			continue
		}
		if _, err := a.Hub.Enqueue(agentID, protocol.CmdPluginLoad, args); err != nil {
			return false, false
		}
		a.Plugins.RecordCall(agentID, args.ID, "load", "auto-view")
		return false, true
	}
	return false, false
}
