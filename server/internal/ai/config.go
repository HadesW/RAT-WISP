package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// ---- operator-editable config: multiple provider profiles, one active ----

type Profile struct {
	Name     string `json:"name"`
	Provider string `json:"provider"` // openai (any OpenAI-compatible) | mock
	Endpoint string `json:"endpoint"`
	Model    string `json:"model"`
	APIKey   string `json:"api_key,omitempty"`
}

type Config struct {
	Enabled  bool      `json:"enabled"`
	Active   string    `json:"active"`
	Thinking string    `json:"thinking,omitempty"` // reasoning effort: off|minimal|low|medium|high
	Profiles []Profile `json:"profiles"`
}

// legacy flat file ({provider,endpoint,model,api_key}) → one profile named 默认.
type legacyConfig struct {
	Enabled  bool   `json:"enabled"`
	Provider string `json:"provider"`
	Endpoint string `json:"endpoint"`
	Model    string `json:"model"`
	APIKey   string `json:"api_key"`
}

func ParseConfig(b []byte) Config {
	var flat legacyConfig
	if json.Unmarshal(b, &flat) == nil && (flat.Provider != "" || flat.Endpoint != "") {
		name := "默认"
		return Config{Enabled: flat.Enabled, Active: name,
			Profiles: []Profile{{Name: name, Provider: flat.Provider, Endpoint: flat.Endpoint, Model: flat.Model, APIKey: flat.APIKey}}}
	}
	var c Config
	_ = json.Unmarshal(b, &c)
	return c
}

func (r *Runtime) active() (Profile, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, p := range r.conf.Profiles {
		if p.Name == r.conf.Active {
			return p, true
		}
	}
	if len(r.conf.Profiles) > 0 {
		return r.conf.Profiles[0], true
	}
	return Profile{}, false
}

func buildProvider(p Profile) Provider {
	key := p.APIKey
	if key == "" { // env fallback keeps secrets off disk
		key = os.Getenv("WISP_AI_KEY")
	}
	switch p.Provider {
	case "mock", "":
		return &Mock{ModelName: p.Model}
	default:
		return &OpenAICompat{Endpoint: p.Endpoint, APIKey: key, ModelName: p.Model, Client: NewHTTPClient()}
	}
}

// Configure hot-swaps the whole config; empty api_key on an existing profile
// keeps the stored secret (masked-UI round-trip safety).
func (r *Runtime) Configure(c Config) {
	r.mu.Lock()
	for i := range c.Profiles {
		if c.Profiles[i].APIKey != "" {
			continue
		}
		for _, old := range r.conf.Profiles {
			// keep the stored secret when the entry is the same profile, even
			// if the operator renamed it in the dialog (match by endpoint+provider)
			if (old.Name == c.Profiles[i].Name ||
				(old.Endpoint == c.Profiles[i].Endpoint && old.Provider == c.Profiles[i].Provider)) && old.APIKey != "" {
				c.Profiles[i].APIKey = old.APIKey
				break
			}
		}
	}
	if c.Active == "" && len(c.Profiles) > 0 {
		c.Active = c.Profiles[0].Name
	}
	r.conf = c
	if p, ok := c.Pick(c.Active); ok && c.Enabled {
		r.provider = buildProvider(p)
		r.enabled = true
	} else {
		r.provider, r.enabled = nil, false
	}
	r.mu.Unlock()
}

func (c Config) Pick(name string) (Profile, bool) {
	for _, p := range c.Profiles {
		if p.Name == name {
			return p, true
		}
	}
	if len(c.Profiles) > 0 {
		return c.Profiles[0], true
	}
	return Profile{}, false
}

func (r *Runtime) On() bool {
	_, on := r.snapshot()
	return on
}

func (r *Runtime) Conf() Config {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.conf
}

// SetActive switches the profile used by the chat loop (model picker).
func (r *Runtime) SetActive(name string) error {
	c := r.Conf()
	if _, ok := c.Pick(name); !ok {
		return fmt.Errorf("unknown profile %q", name)
	}
	c.Active = name
	r.Configure(c)
	return nil
}

// Redacted: everything the console may show; secrets never leave the server.
func (r *Runtime) Redacted() map[string]any {
	c := r.Conf()
	profs := make([]map[string]any, 0, len(c.Profiles))
	for _, p := range c.Profiles {
		profs = append(profs, map[string]any{
			"name": p.Name, "provider": orDefault(p.Provider, "mock"),
			"endpoint": p.Endpoint, "model": p.Model, "has_key": p.APIKey != "" || os.Getenv("WISP_AI_KEY") != "",
		})
	}
	return map[string]any{"enabled": c.Enabled, "active": c.Active, "thinking": c.Thinking, "profiles": profs}
}

// Save writes the config JSON (0600). Env-injected keys are never persisted.
func (r *Runtime) Save() error {
	if r.SavePath == "" {
		return nil
	}
	c := r.Conf()
	envKey := os.Getenv("WISP_AI_KEY")
	if envKey != "" {
		for i := range c.Profiles {
			if c.Profiles[i].APIKey == envKey {
				c.Profiles[i].APIKey = ""
			}
		}
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(r.SavePath, append(b, '\n'), 0o600)
}

// Test probes one profile (form values may override the stored profile).
func (r *Runtime) Test(probe Profile) error {
	if probe.APIKey == "" {
		for _, p := range r.Conf().Profiles {
			if p.Name == probe.Name || len(r.Conf().Profiles) == 1 {
				probe.APIKey = p.APIKey
				break
			}
		}
	}
	p := buildProvider(probe)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	msg, err := p.Complete(ctx, []Msg{{Role: "user", Content: "ping"}}, nil, CompleteOpts{Effort: r.Conf().Thinking})
	if err != nil {
		return err
	}
	if msg.Content == "" && len(msg.ToolCalls) == 0 {
		return fmt.Errorf("empty completion")
	}
	return nil
}

// ListModels proxies GET {endpoint}/models (CORS-free for the console).
// Empty key falls back to the named stored profile, else any stored key.
func (r *Runtime) ListModels(endpoint, key, profileName string) ([]string, error) {
	if key == "" {
		if p, ok := r.Conf().Pick(profileName); ok && p.APIKey != "" {
			key = p.APIKey
		}
	}
	if key == "" {
		key = os.Getenv("WISP_AI_KEY")
	}
	if key == "" {
		for _, p := range r.Conf().Profiles {
			if p.APIKey != "" {
				key = p.APIKey
				break
			}
		}
	}
	if endpoint == "" {
		return nil, fmt.Errorf("endpoint required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(endpoint, "/")+"/models", nil)
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := NewHTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %.200s", resp.StatusCode, body)
	}
	var out struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(out.Data))
	for _, d := range out.Data {
		if d.ID != "" {
			ids = append(ids, d.ID)
		}
	}
	return ids, nil
}
