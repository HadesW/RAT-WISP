package services

// FileServerService hosts a read-only HTTP/HTTPS static file server on an
// independent port. Operators pick a local directory as the web root (for
// hosting payloads such as the agent binary); the service persists its config
// in the database and restores it on server startup.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// fileServerSettingKey is the settings-table key holding the JSON config.
const fileServerSettingKey = "file_server"

// FileServerConfig is the persisted configuration.
type FileServerConfig struct {
	RootDir string `json:"root_dir"`
	Port    int    `json:"port"`
	UseTLS  bool   `json:"use_tls"`
	Enabled bool   `json:"enabled"`
	// Host is the address used in download URLs. Empty means auto-pick the
	// machine's LAN address. Set it (e.g. a public IP or a domain name) when
	// the files must be reachable from the internet.
	Host string `json:"host"`
}

// FileEntry describes one file served from the root directory.
type FileEntry struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	ModTime string `json:"mod_time"`
	URL     string `json:"url"`
}

// FileServerStatus is returned to the frontend.
type FileServerStatus struct {
	Running bool        `json:"running"`
	URL     string      `json:"url"`
	Host    string      `json:"host"`
	RootDir string      `json:"root_dir"`
	Port    int         `json:"port"`
	UseTLS  bool        `json:"use_tls"`
	Files   []FileEntry `json:"files"`
}

// FileServerService manages the static file server lifecycle.
type FileServerService struct {
	serverSvc *ServerService

	mu      sync.Mutex
	httpSrv *http.Server
	running bool
	rootDir string
	port    int
	useTLS  bool
	host    string
}

// NewFileServerService creates the service.
func NewFileServerService(serverSvc *ServerService) *FileServerService {
	return &FileServerService{serverSvc: serverSvc}
}

// Restore reloads the persisted config and resumes the server if it was enabled.
func (fs *FileServerService) Restore() error {
	raw, err := fs.serverSvc.GetDB().GetSetting(fileServerSettingKey)
	if err != nil || raw == "" {
		return nil
	}
	var cfg FileServerConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return nil // corrupt config: ignore and require manual start
	}
	if !cfg.Enabled || cfg.RootDir == "" {
		return nil
	}
	return fs.StartFileServer(cfg.RootDir, cfg.Port, cfg.UseTLS, cfg.Host)
}

// StartFileServer validates the root dir and starts serving on the given port.
// host is used in the download URLs: leave it empty to auto-pick the machine's
// LAN address, or set a public IP / domain to make it reachable externally.
func (fs *FileServerService) StartFileServer(rootDir string, port int, useTLS bool, host string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if fs.running {
		fs.stopLocked()
	}

	abs, err := filepath.Abs(rootDir)
	if err != nil {
		return fmt.Errorf("invalid root dir: %w", err)
	}
	st, err := os.Stat(abs)
	if err != nil || !st.IsDir() {
		return fmt.Errorf("root directory is not accessible: %v", err)
	}
	if port <= 0 || port > 65535 {
		return fmt.Errorf("invalid port: %d", port)
	}

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir(abs)))

	srv := &http.Server{Addr: fmt.Sprintf(":%d", port), Handler: mux}
	if useTLS {
		cert, err := fs.serverSvc.GetServer().GetTLSCertificate()
		if err != nil {
			return fmt.Errorf("load TLS certificate: %w", err)
		}
		srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	}

	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	go func() {
		var serveErr error
		if useTLS {
			// Certificates are already configured in TLSConfig.
			serveErr = srv.ServeTLS(ln, "", "")
		} else {
			serveErr = srv.Serve(ln)
		}
		if serveErr != nil && serveErr != http.ErrServerClosed {
			fmt.Printf("[FileServer] serve error: %v\n", serveErr)
		}
	}()

	fs.httpSrv = srv
	fs.rootDir = abs
	fs.port = port
	fs.useTLS = useTLS
	fs.host = host
	fs.running = true
	fs.persistLocked(true)

	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	display := host
	if display == "" {
		display = pickServerHost()
	}
	fmt.Printf("[FileServer] listening on %s://%s:%d (root: %s)\n", scheme, display, port, abs)
	return nil
}

// StopFileServer stops the server and marks the config disabled.
func (fs *FileServerService) StopFileServer() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.stopLocked()
	fs.persistLocked(false)
	return nil
}

func (fs *FileServerService) stopLocked() {
	if fs.httpSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = fs.httpSrv.Shutdown(ctx)
		fs.httpSrv = nil
	}
	fs.running = false
}

// GetFileServerStatus returns the current state plus the file listing.
func (fs *FileServerService) GetFileServerStatus() (FileServerStatus, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	st := FileServerStatus{Running: fs.running, RootDir: fs.rootDir, Port: fs.port, UseTLS: fs.useTLS, Host: fs.host}
	if !fs.running {
		return st, nil
	}
	st.URL = fs.urlLocked()

	entries, err := os.ReadDir(fs.rootDir)
	if err != nil {
		return st, fmt.Errorf("read root dir: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		st.Files = append(st.Files, FileEntry{
			Name:    e.Name(),
			Size:    info.Size(),
			ModTime: info.ModTime().Format("2006-01-02 15:04:05"),
			URL:     fs.urlLocked() + e.Name(),
		})
	}
	return st, nil
}

// urlLocked builds the base URL (must hold fs.mu). A configured host wins;
// otherwise pick the machine's LAN address, skipping APIPA (169.254/16).
// "0.0.0.0" means "listen on all interfaces" and is treated as auto too.
func (fs *FileServerService) urlLocked() string {
	scheme := "http"
	if fs.useTLS {
		scheme = "https"
	}
	host := fs.host
	if host == "" || host == "0.0.0.0" {
		host = pickServerHost()
	}
	return fmt.Sprintf("%s://%s:%d/", scheme, host, fs.port)
}

func (fs *FileServerService) persistLocked(enabled bool) {
	cfg := FileServerConfig{RootDir: fs.rootDir, Port: fs.port, UseTLS: fs.useTLS, Enabled: enabled, Host: fs.host}
	data, _ := json.Marshal(cfg)
	_ = fs.serverSvc.GetDB().SetSetting(fileServerSettingKey, string(data))
}

// pickServerHost returns a real, routable IPv4 for the machine. Link-local
// APIPA addresses (169.254.0.0/16) and loopback are skipped; a LAN address is
// preferred so the URL works from other machines on the network.
func pickServerHost() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}
	fallback := ""
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipnet.IP.To4()
		if ip4 == nil || ip4.IsLoopback() {
			continue
		}
		if ip4[0] == 169 && ip4[1] == 254 { // APIPA: not routable
			continue
		}
		if fallback == "" {
			fallback = ip4.String()
		}
		// Prefer a private LAN range (192.168/16, 10/8, 172.16-31/12)
		if (ip4[0] == 192 && ip4[1] == 168) || ip4[0] == 10 || (ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) {
			return ip4.String()
		}
	}
	if fallback != "" {
		return fallback
	}
	return "127.0.0.1"
}
