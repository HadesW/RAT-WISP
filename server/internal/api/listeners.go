package api

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"wispp/protocol"
	"wispp/protocol/malleable"
	"wispp/server/internal/listener"
)

func (a *DebugAPI) listenersList(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.Manager.List())
}

func (a *DebugAPI) listenerCreate(w http.ResponseWriter, r *http.Request) {
	var spec listener.Spec
	if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	view, err := a.Manager.Create(spec)
	if err != nil {
		code := http.StatusBadRequest
		if err == listener.ErrExists {
			code = http.StatusConflict
		}
		writeJSON(w, code, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, view)
}

func (a *DebugAPI) listenerUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name *string `json:"name"`
		Host *string `json:"host"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || (req.Name == nil && req.Host == nil) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name or host required"})
		return
	}
	if err := a.Manager.UpdateMeta(r.PathValue("id"), listener.MetaUpdate{Name: req.Name, Host: req.Host}); err != nil {
		code := http.StatusInternalServerError
		if err == listener.ErrNotFound {
			code = http.StatusNotFound
		}
		writeJSON(w, code, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *DebugAPI) listenerCertSet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CertPEM string `json:"cert_pem"`
		KeyPEM  string `json:"key_pem"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.CertPEM == "" || req.KeyPEM == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cert_pem and key_pem required"})
		return
	}
	err := a.Manager.SetCert(r.PathValue("id"), []byte(req.CertPEM), []byte(req.KeyPEM))
	if err != nil {
		code := http.StatusBadRequest
		if err == listener.ErrNotFound {
			code = http.StatusNotFound
		}
		writeJSON(w, code, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *DebugAPI) listenerCertClear(w http.ResponseWriter, r *http.Request) {
	err := a.Manager.ClearCert(r.PathValue("id"))
	if err != nil {
		code := http.StatusBadRequest
		if err == listener.ErrNotFound {
			code = http.StatusNotFound
		}
		writeJSON(w, code, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *DebugAPI) listenerStop(w http.ResponseWriter, r *http.Request) {
	a.listenerAction(w, r, a.Manager.Stop)
}
func (a *DebugAPI) listenerStart(w http.ResponseWriter, r *http.Request) {
	a.listenerAction(w, r, a.Manager.Start)
}
func (a *DebugAPI) listenerDelete(w http.ResponseWriter, r *http.Request) {
	a.listenerAction(w, r, a.Manager.Delete)
}

func (a *DebugAPI) listenerAction(w http.ResponseWriter, r *http.Request, fn func(string) error) {
	if err := fn(r.PathValue("id")); err != nil {
		code := http.StatusInternalServerError
		if err == listener.ErrNotFound {
			code = http.StatusNotFound
		}
		http.Error(w, err.Error(), code)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- malleable profiles ----

func (a *DebugAPI) profilesList(w http.ResponseWriter, _ *http.Request) {
	type row struct {
		Name    string `json:"name"`
		Body    string `json:"body"`
		Builtin bool   `json:"builtin"`
	}
	out := []row{}
	for _, p := range protocol.BuiltinProfiles() {
		b, _ := json.MarshalIndent(p, "", "  ")
		out = append(out, row{Name: p.Name, Body: string(b), Builtin: true})
	}
	if a.Store != nil {
		rows, _ := a.Store.ProfileList()
		for _, p := range rows {
			builtin := false
			for _, o := range out {
				if o.Name == p.Name {
					builtin = true
				}
			}
			if !builtin {
				out = append(out, row{Name: p.Name, Body: p.Body})
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *DebugAPI) profilePut(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		Body string `json:"body"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name+body required"})
		return
	}
	if err := lintProfile(req.Body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := a.Store.ProfileUpsert(req.Name, req.Body); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.Hub.Emit("info", "listener", "", "malleable profile %s saved", req.Name)
	w.WriteHeader(http.StatusNoContent)
}

func (a *DebugAPI) profileDelete(w http.ResponseWriter, r *http.Request) {
	if err := a.Store.ProfileDelete(r.PathValue("name")); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *DebugAPI) profileValidate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Body string `json:"body"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if err := lintProfile(req.Body); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// profileImport compiles a Malleable C2 profile (plan P4 subset) into the
// runtime JSON profile; it never saves — the console shows the result and
// stores it through the existing PUT endpoint.
func (a *DebugAPI) profileImport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Text) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "text required"})
		return
	}
	if req.Name == "" {
		req.Name = "imported"
	}
	p, err := malleable.Compile(req.Name, req.Text)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	b, _ := json.MarshalIndent(p, "", "  ")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "name": p.Name, "body": string(b)})
}

func lintProfile(body string) error {
	p := &protocol.Profile{}
	if err := json.Unmarshal([]byte(body), p); err != nil {
		return err
	}
	return p.Validate()
}

// netIPs exposes non-loopback IPv4 addresses so the console can suggest an
// advertised listener host instead of leaving 0.0.0.0 in payload configs.
func (a *DebugAPI) netIPs(w http.ResponseWriter, _ *http.Request) {
	ips := []string{}
	ifaces, err := net.Interfaces()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil && !ipnet.IP.IsLoopback() {
				ips = append(ips, ipnet.IP.String())
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ips": ips})
}
