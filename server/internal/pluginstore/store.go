// Package pluginstore is the teamserver plugin repository (plan §5.3):
// manifest schema, Ed25519 signature enforcement, on-disk layout, DB rows,
// deploy/exec plumbing and call auditing.
package pluginstore

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"wispp/protocol"
	"wispp/server/internal/core"
	"wispp/server/internal/db"
	"wispp/server/internal/stage"
)

// Manifest is plugin.json (plan §5.2).
type Manifest struct {
	ID           string   `json:"id"`
	Version      string   `json:"version"`
	Agent        string   `json:"agent"`            // go | rs
	Kind         string   `json:"kind"`             // wat | wasm | native-dll
	Target       string   `json:"target,omitempty"` // native-dll target, e.g. windows_amd64
	Entry        string   `json:"entry"`            // exported function name
	Capabilities []string `json:"capabilities"`
	Mitre        []string `json:"mitre,omitempty"`
	Author       string   `json:"author,omitempty"`
	Description  string   `json:"description,omitempty"`
}

type Store struct {
	Dir    string
	Pubkey ed25519.PublicKey // nil → dynamic plugins disabled entirely
	DB     *db.Store
	Hub    *core.Hub
	Stage  *stage.Service // optional: large native modules travel via Type4
}

var ErrBadSig = errors.New("pluginstore: signature verification FAILED")

func (s *Store) emit(level, format string, args ...any) {
	if s.Hub != nil {
		s.Hub.Emit(level, "plugin", "default", format, args...)
	}
}

// Install verifies the detached signature over manifest||module, then stores
// files + DB row.
func (s *Store) Install(manifestRaw string, module []byte, sigB64 string) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal([]byte(manifestRaw), &m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if m.ID == "" || m.Version == "" || m.Entry == "" {
		return nil, errors.New("manifest: id/version/entry required")
	}
	switch m.Kind {
	case "", "wat", "wasm", "native-dll":
	default:
		return nil, fmt.Errorf("manifest: unknown kind %q", m.Kind)
	}
	if m.Kind == "native-dll" && m.Target == "" {
		return nil, errors.New("manifest: native-dll requires target (e.g. windows_amd64)")
	}
	sig, err := decodeSig(sigB64)
	if err != nil {
		return nil, err
	}
	if s.Pubkey == nil {
		return nil, errors.New("plugin signing pubkey not configured (data/keys/plugin.pub) — installs disabled")
	}
	msg := append(append([]byte(nil), []byte(manifestRaw)...), module...)
	if !ed25519.Verify(s.Pubkey, msg, sig) {
		s.emit("err", "plugin %s@%s install REJECTED: bad signature (audit)", m.ID, m.Version)
		return nil, ErrBadSig
	}
	sum := sha256.Sum256(module)
	dir := filepath.Join(s.Dir, m.ID, m.Version)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifestRaw), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "module.bin"), module, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "sig.hex"), []byte(hex.EncodeToString(sig)), 0o600); err != nil {
		return nil, err
	}
	if s.DB != nil {
		caps, _ := json.Marshal(m.Capabilities)
		if err := s.DB.PluginUpsert(m.ID, m.Version, string(caps), dir, hex.EncodeToString(sum[:]), true); err != nil {
			return nil, err
		}
	}
	s.emit("ok", "plugin %s@%s installed (sha %s…)", m.ID, m.Version, hex.EncodeToString(sum[:])[:12])
	return &m, nil
}

func (s *Store) List() []db.PluginRow {
	if s.DB == nil {
		return nil
	}
	out, _ := s.DB.PluginList()
	return out
}

func (s *Store) SetEnabled(id string, on bool) error {
	if s.DB == nil {
		return errors.New("no db")
	}
	return s.DB.PluginSetEnabled(id, on)
}

func (s *Store) Delete(id string) error {
	if s.DB != nil {
		if err := s.DB.PluginDelete(id); err != nil {
			return err
		}
	}
	return os.RemoveAll(filepath.Join(s.Dir, id))
}

// decodeSig accepts the detached signature as hex (plugin_sign output) or
// base64; both encodings of the same 64 bytes are valid.
func decodeSig(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if b, err := hex.DecodeString(s); err == nil && len(b) == ed25519.SignatureSize {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == ed25519.SignatureSize {
		return b, nil
	}
	return nil, errors.New("pluginstore: bad signature encoding (hex or base64, 64 bytes)")
}

// LoadArgs assembles the task payload for CmdPluginLoad (small modules travel
// base64'd inside the task).
func (s *Store) LoadArgs(id string) (*protocol.PluginLoadArgs, error) {
	args, mod, err := s.loadArgsBase(id)
	if err != nil {
		return nil, err
	}
	args.ModuleB64 = base64.StdEncoding.EncodeToString(mod)
	return &args, nil
}

// LoadArgsStaged is LoadArgs for large native modules: the DLL travels through
// the one-time Type4 stage endpoint (`<origin><stage-path>/<token>?b64=1`)
// instead of the task payload; Sha256 lets the agent verify integrity again.
func (s *Store) LoadArgsStaged(id, origin string) (*protocol.PluginLoadArgs, error) {
	if s.Stage == nil {
		return nil, errors.New("pluginstore: no stage service")
	}
	if origin == "" {
		return nil, errors.New("pluginstore: no listener origin for stage URL")
	}
	args, mod, err := s.loadArgsBase(id)
	if err != nil {
		return nil, err
	}
	if args.Kind != "native-dll" {
		return nil, fmt.Errorf("pluginstore: %s is not a native-dll plugin", id)
	}
	token, err := stage.NewToken()
	if err != nil {
		return nil, err
	}
	if err := s.Stage.IssueEx(token, mod, "", 15*time.Minute, 2); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(mod)
	args.StageURL = strings.TrimRight(origin, "/") + s.Stage.Path + "/" + token + "?b64=1"
	args.Sha256 = hex.EncodeToString(sum[:])
	return &args, nil
}

func (s *Store) loadArgsBase(id string) (protocol.PluginLoadArgs, []byte, error) {
	var zero protocol.PluginLoadArgs
	if s.DB == nil {
		return zero, nil, errors.New("no db")
	}
	row, err := s.DB.PluginGet(id)
	if err != nil {
		return zero, nil, err
	}
	if !row.Enabled {
		return zero, nil, errors.New("plugin disabled")
	}
	man, err := os.ReadFile(filepath.Join(row.Path, "manifest.json"))
	if err != nil {
		return zero, nil, err
	}
	mod, err := os.ReadFile(filepath.Join(row.Path, "module.bin"))
	if err != nil {
		return zero, nil, err
	}
	sigB, err := os.ReadFile(filepath.Join(row.Path, "sig.hex"))
	if err != nil {
		return zero, nil, errors.New("plugin has no stored signature; reinstall")
	}
	var m Manifest
	_ = json.Unmarshal(man, &m)
	return protocol.PluginLoadArgs{
		ID: row.ID, Version: row.Version, Kind: m.Kind, Manifest: string(man),
		Sig: strings.TrimSpace(string(sigB)),
	}, mod, nil
}

// ManifestOf returns the stored manifest for an installed plugin (deploy path
// branches on Kind before touching the module bytes).
func (s *Store) ManifestOf(id string) (Manifest, error) {
	var m Manifest
	if s.DB == nil {
		return m, errors.New("no db")
	}
	row, err := s.DB.PluginGet(id)
	if err != nil {
		return m, err
	}
	man, err := os.ReadFile(filepath.Join(row.Path, "manifest.json"))
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(man, &m); err != nil {
		return m, err
	}
	return m, nil
}

// Sign attaches the server-side signature (dev convenience when the operator
// signed with plugin_sign already this is unnecessary; kept for completeness).
func (s *Store) SignDir(dir, manifestRaw string, module []byte, privHex string) error {
	seed, err := hex.DecodeString(strings.TrimSpace(privHex))
	if err != nil || len(seed) != ed25519.SeedSize {
		return errors.New("bad private key")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	msg := append(append([]byte(nil), []byte(manifestRaw)...), module...)
	sig := ed25519.Sign(priv, msg)
	return os.WriteFile(filepath.Join(dir, "sig.hex"), []byte(hex.EncodeToString(sig)), 0o600)
}

// RecordCall audits one exec/deploy.
func (s *Store) RecordCall(agent, plugin, entry, result string) {
	if s.DB != nil {
		_ = s.DB.PluginCall(agent, plugin, entry, result)
	}
	s.emit("info", "plugin %s exec on %s… (%s)", plugin, agent[:min(8, len(agent))], entry)
}

// Caps for the AI list_plugin_caps tool.
func (s *Store) Caps() []map[string]any {
	out := []map[string]any{}
	for _, r := range s.List() {
		var caps []string
		_ = json.Unmarshal([]byte(r.Capabilities), &caps)
		out = append(out, map[string]any{"id": r.ID, "version": r.Version, "capabilities": caps, "enabled": r.Enabled})
	}
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
