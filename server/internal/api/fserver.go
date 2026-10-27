package api

import (
	"encoding/json"
	"net/http"
	"time"

	"wispp/server/internal/fserver"
)

func (a *DebugAPI) fserverGet(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.FServer.Status())
}

func (a *DebugAPI) fserverPut(w http.ResponseWriter, r *http.Request) {
	var cfg fserver.Config
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := a.FServer.Apply(cfg); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, a.FServer.Status())
}

func (a *DebugAPI) fserverCert(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CertPEM string `json:"cert_pem"`
		KeyPEM  string `json:"key_pem"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.CertPEM == "" || req.KeyPEM == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cert_pem and key_pem required"})
		return
	}
	if err := a.FServer.SetCertPEM([]byte(req.CertPEM), []byte(req.KeyPEM)); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, a.FServer.Status())
}

// ---- delivery links -------------------------------------------------------

type deliveryCreateReq struct {
	PayloadID    string `json:"payload_id"`
	Name         string `json:"name,omitempty"`
	TTLSeconds   int    `json:"ttl_seconds,omitempty"`
	MaxDownloads int    `json:"max_downloads,omitempty"`
	ContentType  string `json:"content_type,omitempty"`
	Project      string `json:"project,omitempty"`
}

func (a *DebugAPI) deliveriesList(w http.ResponseWriter, r *http.Request) {
	list, err := a.FServer.Deliveries(r.URL.Query().Get("project"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *DebugAPI) deliveryCreate(w http.ResponseWriter, r *http.Request) {
	var req deliveryCreateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PayloadID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "payload_id required"})
		return
	}
	meta, err := a.Payloads.Resolve(req.PayloadID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	project := req.Project
	if project == "" {
		project = meta.Project
	}
	view, err := a.FServer.CreateDelivery(meta.ID, req.Name, meta.Path, project,
		req.TTLSeconds, req.MaxDownloads, req.ContentType)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, view)
}

func (a *DebugAPI) deliveryPatch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ExpiresIn    *int    `json:"expires_in_seconds"`
		MaxDownloads *int    `json:"max_downloads"`
		ContentType  *string `json:"content_type"`
		Revoked      *bool   `json:"revoked"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	var expiresAt *int64
	if req.ExpiresIn != nil {
		v := expiresAtFrom(*req.ExpiresIn)
		expiresAt = &v
	}
	if err := a.FServer.PatchDelivery(r.PathValue("id"), expiresAt, req.MaxDownloads, req.ContentType, req.Revoked); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *DebugAPI) deliveryDelete(w http.ResponseWriter, r *http.Request) {
	if err := a.FServer.DeleteDelivery(r.PathValue("id")); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- shares ---------------------------------------------------------------

func (a *DebugAPI) sharesList(w http.ResponseWriter, r *http.Request) {
	list, err := a.FServer.Shares(r.URL.Query().Get("project"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *DebugAPI) shareFiles(w http.ResponseWriter, _ *http.Request) {
	files, err := a.FServer.RootFiles()
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, files)
}

func (a *DebugAPI) shareCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		File         string `json:"file"`
		Name         string `json:"name,omitempty"`
		TTLSeconds   int    `json:"ttl_seconds,omitempty"`
		MaxDownloads int    `json:"max_downloads,omitempty"`
		Password     string `json:"password,omitempty"`
		Project      string `json:"project,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.File == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "file required"})
		return
	}
	view, err := a.FServer.CreateShare(req.File, req.Name, req.Project,
		req.TTLSeconds, req.MaxDownloads, req.Password)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, view)
}

func (a *DebugAPI) sharePatch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ExpiresIn    *int    `json:"expires_in_seconds"`
		MaxDownloads *int    `json:"max_downloads"`
		Password     *string `json:"password"`
		Revoked      *bool   `json:"revoked"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	var expiresAt *int64
	if req.ExpiresIn != nil {
		v := expiresAtFrom(*req.ExpiresIn)
		expiresAt = &v
	}
	if err := a.FServer.PatchShare(r.PathValue("id"), expiresAt, req.MaxDownloads, req.Password, req.Revoked); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *DebugAPI) shareDelete(w http.ResponseWriter, r *http.Request) {
	if err := a.FServer.DeleteShare(r.PathValue("id")); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func expiresAtFrom(seconds int) int64 {
	if seconds <= 0 {
		return 0
	}
	return time.Now().Add(time.Duration(seconds) * time.Second).Unix()
}
