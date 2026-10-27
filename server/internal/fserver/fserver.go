// Package fserver hosts the standalone delivery/share HTTP(S) service
// (plan P3): /p/<token> serves generated payload links, /s/<token> serves
// registered files under root_dir. There is no directory browser.
package fserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"wispp/server/internal/db"
)

const settingKey = "file_server"

// Modes supported by the service.
const (
	ModeDelivery = "delivery"
	ModeShare    = "share"
	ModeBoth     = "both"
)

// Config is the persisted file-server configuration.
type Config struct {
	RootDir string `json:"root_dir"`
	Port    int    `json:"port"`
	Addr    string `json:"addr,omitempty"` // bind address, e.g. ":8888" or "0.0.0.0:8888"
	Host    string `json:"host"`           // advertised host; empty = first LAN IP
	UseTLS  bool   `json:"use_tls"`
	Enabled bool   `json:"enabled"`
	Mode    string `json:"mode"` // delivery|share|both

	CertFile string `json:"cert_file,omitempty"`
	KeyFile  string `json:"key_file,omitempty"`

	NoLanding bool `json:"no_landing,omitempty"` // hide the /s/<token> landing page
}

// Status is the console view.
type Status struct {
	Running    bool   `json:"running"`
	URL        string `json:"url"`
	Host       string `json:"host"`
	RootDir    string `json:"root_dir"`
	Addr       string `json:"addr"`
	Port       int    `json:"port"`
	UseTLS     bool   `json:"use_tls"`
	Mode       string `json:"mode"`
	TLS        bool   `json:"tls"`
	Deliveries int    `json:"deliveries"`
	Shares     int    `json:"shares"`
	Error      string `json:"error,omitempty"`
}

// Svc owns the file-server lifecycle.
type Svc struct {
	Store   *db.Store
	Emit    func(level, text string)
	DataDir string

	mu      sync.Mutex
	srv     *http.Server
	cfg     Config
	lastErr string
}

func New(store *db.Store, emit func(string, string), dataDir string) *Svc {
	return &Svc{Store: store, Emit: emit, DataDir: dataDir}
}

// Apply persists and (re)starts the server per cfg.
func (s *Svc) Apply(cfg Config) error {
	switch cfg.Mode {
	case "", ModeDelivery, ModeShare, ModeBoth:
	default:
		return fmt.Errorf("bad mode %q (want delivery|share|both)", cfg.Mode)
	}
	cfg = normalizeConfig(cfg)
	if err := validateConfig(cfg); err != nil {
		return err
	}
	s.stop()
	if s.Store != nil {
		b, _ := json.Marshal(cfg)
		_ = s.Store.SettingSet(settingKey, string(b))
	}
	if !cfg.Enabled {
		s.cfg = cfg
		s.Emit("warn", "file server stopped")
		return nil
	}
	return s.start(cfg)
}

func normalizeConfig(cfg Config) Config {
	cfg.Mode = strings.ToLower(strings.TrimSpace(cfg.Mode))
	switch cfg.Mode {
	case ModeDelivery, ModeShare, ModeBoth:
	case "":
		cfg.Mode = ModeBoth
	default:
		cfg.Mode = ModeBoth
	}
	if cfg.Addr == "" && cfg.Port > 0 {
		cfg.Addr = fmt.Sprintf(":%d", cfg.Port)
	}
	if p := portOf(cfg.Addr); p > 0 {
		cfg.Port = p
	}
	return cfg
}

func validateConfig(cfg Config) error {
	if !cfg.Enabled {
		return nil
	}
	if cfg.Addr == "" {
		return errors.New("addr or port required")
	}
	if _, err := net.ResolveTCPAddr("tcp", cfg.Addr); err != nil {
		return fmt.Errorf("bad addr: %w", err)
	}
	if cfg.Mode == ModeShare || cfg.Mode == ModeBoth {
		if cfg.RootDir == "" {
			return errors.New("root_dir required for share mode")
		}
		if st, err := os.Stat(cfg.RootDir); err != nil || !st.IsDir() {
			return fmt.Errorf("root_dir not a directory: %v", err)
		}
	}
	if (cfg.CertFile == "") != (cfg.KeyFile == "") {
		return errors.New("cert_file and key_file must be set together")
	}
	if cfg.CertFile != "" {
		if _, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile); err != nil {
			return fmt.Errorf("TLS cert: %w", err)
		}
	}
	return nil
}

func (s *Svc) start(cfg Config) error {
	srv := &http.Server{Addr: cfg.Addr, Handler: s.handler(), ReadHeaderTimeout: 10 * time.Second}
	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		s.lastErr = err.Error()
		return err
	}
	var crt, key string
	if cfg.UseTLS {
		crt, key, err = s.tlsCert(cfg)
		if err != nil {
			_ = ln.Close()
			s.lastErr = err.Error()
			return err
		}
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	s.mu.Lock()
	s.srv = srv
	s.cfg = cfg
	s.lastErr = ""
	s.mu.Unlock()
	go func() {
		var err error
		if cfg.UseTLS {
			err = srv.ServeTLS(ln, crt, key)
		} else {
			err = srv.Serve(ln)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.mu.Lock()
			s.lastErr = err.Error()
			s.mu.Unlock()
			if s.Emit != nil {
				s.Emit("err", "file server died: "+err.Error())
			}
		}
	}()
	if s.Emit != nil {
		s.Emit("ok", fmt.Sprintf("file server on %s mode=%s", s.statusURL(cfg), cfg.Mode))
	}
	return nil
}

func (s *Svc) stop() {
	s.mu.Lock()
	srv := s.srv
	s.srv = nil
	s.mu.Unlock()
	if srv != nil {
		_ = srv.Close()
	}
}

// Restore re-applies persisted config at boot.
func (s *Svc) Restore() {
	if s.Store == nil {
		return
	}
	raw, ok := s.Store.SettingGet(settingKey)
	if !ok {
		return
	}
	var cfg Config
	if json.Unmarshal([]byte(raw), &cfg) == nil && cfg.Enabled {
		if err := s.Apply(cfg); err != nil {
			s.mu.Lock()
			s.lastErr = err.Error()
			s.mu.Unlock()
		}
	}
}

// Config returns the running/persisted configuration.
func (s *Svc) Config() Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

// Status reports runtime state + link counts.
func (s *Svc) Status() Status {
	s.mu.Lock()
	cfg, running, lastErr := s.cfg, s.srv != nil, s.lastErr
	s.mu.Unlock()
	st := Status{Running: running, Host: cfg.Host, RootDir: cfg.RootDir, Addr: cfg.Addr,
		Port: cfg.Port, UseTLS: cfg.UseTLS, Mode: cfg.Mode, TLS: cfg.UseTLS, Error: lastErr}
	if running {
		st.URL = s.statusURL(cfg)
	}
	if s.Store != nil {
		if list, err := s.Store.Deliveries(""); err == nil {
			st.Deliveries = len(list)
		}
		if list, err := s.Store.Shares(""); err == nil {
			st.Shares = len(list)
		}
	}
	return st
}

func (s *Svc) statusURL(cfg Config) string {
	host := cfg.Host
	if host == "" {
		host = lanIP()
	}
	scheme := "http"
	if cfg.UseTLS {
		scheme = "https"
	}
	port := cfg.Port
	if port == 0 {
		port = portOf(cfg.Addr)
	}
	if port > 0 {
		return fmt.Sprintf("%s://%s:%d", scheme, host, port)
	}
	return fmt.Sprintf("%s://%s", scheme, host)
}

func (s *Svc) baseURL() string {
	return s.statusURL(s.Config())
}

// SetCertPEM imports an operator-provided certificate/key pair and restarts
// the service when it is running.
func (s *Svc) SetCertPEM(certPEM, keyPEM []byte) error {
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return fmt.Errorf("invalid certificate/key: %w", err)
	}
	crt := filepath.Join(s.DataDir, "fserver-imported.crt")
	key := filepath.Join(s.DataDir, "fserver-imported.key")
	if err := os.MkdirAll(s.DataDir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(crt, certPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(key, keyPEM, 0o600); err != nil {
		return err
	}
	cfg := s.Config()
	cfg.CertFile, cfg.KeyFile = crt, key
	return s.Apply(cfg)
}

// tlsCert returns the operator-provided pair or generates a long-lived
// self-signed ECDSA P-256 certificate on first use.
func (s *Svc) tlsCert(cfg Config) (string, string, error) {
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		return cfg.CertFile, cfg.KeyFile, nil
	}
	crt := filepath.Join(s.DataDir, "fserver.crt")
	key := filepath.Join(s.DataDir, "fserver.key")
	if _, err := os.Stat(crt); err == nil {
		if _, err := os.Stat(key); err == nil {
			return crt, key, nil
		}
	}
	if err := generateTLSCert(crt, key, cfg.Host); err != nil {
		return "", "", err
	}
	if s.Emit != nil {
		s.Emit("warn", "file server: generated self-signed TLS certificate at "+crt)
	}
	return crt, key, nil
}

func generateTLSCert(crtPath, keyPath, advertise string) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "wisp file server"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	if host, err := os.Hostname(); err == nil && host != "" {
		tmpl.DNSNames = append(tmpl.DNSNames, host)
	}
	if ip := lanIP(); ip != "" {
		if parsed := net.ParseIP(ip); parsed != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, parsed)
		}
	}
	if advertise != "" {
		if parsed := net.ParseIP(advertise); parsed != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, parsed)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, advertise)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(crtPath), 0o700); err != nil {
		return err
	}
	crtPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(crtPath, crtPEM, 0o600); err != nil {
		return err
	}
	return os.WriteFile(keyPath, keyPEM, 0o600)
}

func lanIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}
	fallback := ""
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP.IsLoopback() || ipn.IP.To4() == nil || ipn.IP.IsLinkLocalUnicast() {
			continue
		}
		// Prefer RFC1918 addresses over APIPA/other odd interfaces.
		if ipn.IP.IsPrivate() {
			return ipn.IP.String()
		}
		if fallback == "" {
			fallback = ipn.IP.String()
		}
	}
	if fallback != "" {
		return fallback
	}
	return "127.0.0.1"
}

func portOf(addr string) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	var n int
	for i := 0; i < len(p); i++ {
		if p[i] < '0' || p[i] > '9' {
			return 0
		}
		n = n*10 + int(p[i]-'0')
	}
	return n
}
