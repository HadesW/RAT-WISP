package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"wispp/protocol"
)

// transfer orchestrates an agent<->agent lateral file move (mothership):
// the teamserver only coordinates over Type1 — serve binds a one-shot
// listener on src, fetch pulls from it on dst. Data never touches us.
func (a *DebugAPI) transfer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Src     string `json:"src"`
		Dst     string `json:"dst"`
		SrcPath string `json:"src_path"`
		DstPath string `json:"dst_path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Src == "" || req.Dst == "" || req.SrcPath == "" || req.DstPath == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "src/dst/src_path/dst_path required"})
		return
	}
	if req.Src == req.Dst {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "src and dst must differ"})
		return
	}
	nb := make([]byte, 8)
	_, _ = rand.Read(nb)
	nonce := hex.EncodeToString(nb)

	serve, err := a.Hub.Enqueue(req.Src, protocol.CmdXferServe, protocol.XferServeArgs{Addr: ":0", Path: req.SrcPath, Nonce: nonce})
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "src: " + err.Error()})
		return
	}
	// wait for the bound address (serve returns right after bind)
	var addr string
	deadline := time.Now().Add(25 * time.Second)
	for addr == "" && time.Now().Before(deadline) {
		time.Sleep(400 * time.Millisecond)
		for _, t := range a.Hub.Tasks(req.Src, "") {
			if t.Task.ID != serve.Task.ID || t.Status != protocol.TaskCompleted || t.Result == nil {
				continue
			}
			var sr protocol.XferServeResult
			if json.Unmarshal([]byte(t.Result.Output), &sr) == nil {
				addr = sr.Addr
			}
		}
	}
	if addr == "" {
		writeJSON(w, http.StatusGatewayTimeout, map[string]string{"error": "src did not bind in 25s"})
		return
	}
	fetch, err := a.Hub.Enqueue(req.Dst, protocol.CmdXferFetch, protocol.XferFetchArgs{Addr: addr, Nonce: nonce, Local: req.DstPath})
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "dst: " + err.Error()})
		return
	}
	a.Hub.Emit("warn", "security", a.projectOf(req.Dst), "lateral transfer %s:%s -> %s:%s via %s (one-shot listener, agent-to-agent)",
		req.Src[:min(8, len(req.Src))], req.SrcPath, req.Dst[:min(8, len(req.Dst))], req.DstPath, addr)
	writeJSON(w, http.StatusAccepted, map[string]string{"serve_task": serve.Task.ID, "fetch_task": fetch.Task.ID, "via": addr})
}
