package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"wispp/protocol"
)

// p2pBridge relays a browser SDP offer to the agent over Type1 and waits for
// its answer (docs/P2P_DESIGN.md). PSK-bound proof rides back to the browser
// so the agent can authenticate the data channel.
func (a *DebugAPI) p2pBridge(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	var req struct {
		Offer string `json:"offer"` // base64 SDP
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Offer == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "offer required"})
		return
	}
	nb := make([]byte, 8)
	_, _ = rand.Read(nb)
	nonce := hex.EncodeToString(nb)
	rec, err := a.Hub.Enqueue(agentID, protocol.CmdP2PBridge, protocol.P2PBridgeArgs{Offer: req.Offer, Nonce: nonce})
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "type1 offline: " + err.Error()})
		return
	}
	deadline := time.Now().Add(35 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(400 * time.Millisecond)
		for _, t := range a.Hub.Tasks(agentID, "") {
			if t.Task.ID != rec.Task.ID {
				continue
			}
			switch t.Status {
			case protocol.TaskFailed:
				out := ""
				if t.Result != nil {
					out = t.Result.Output
				}
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": "agent refused: " + out})
				return
			case protocol.TaskCompleted:
				var br protocol.P2PBridgeResult
				if t.Result == nil || json.Unmarshal([]byte(t.Result.Output), &br) != nil || br.Answer == "" {
					writeJSON(w, http.StatusBadGateway, map[string]string{"error": "bad answer from agent"})
					return
				}
				a.Hub.Emit("warn", "security", rec.Project, "P2P bridge UP for %s — operator IP now directly visible to the target", agentID[:min(8, len(agentID))])
				writeJSON(w, http.StatusOK, map[string]string{
					"answer": br.Answer,
					"proof":  protocol.P2PProof(a.RCP.PSK, nonce),
					"nonce":  nonce,
				})
				return
			}
		}
	}
	writeJSON(w, http.StatusGatewayTimeout, map[string]string{"error": "agent did not answer in 35s (check Type1 sleep/jitter)"})
}

// p2pStop tears the bridge down via Type1 (agent also self-destructs on
// DTLS close, so this is belt-and-braces).
func (a *DebugAPI) p2pStop(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	if _, err := a.Hub.Enqueue(agentID, protocol.CmdP2PStop, nil); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
