package services

import (
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/user/wisp/internal/db"
	"github.com/user/wisp/internal/server"
	"github.com/wailsapp/wails/v3/pkg/application"
)

// ServerService manages the core server lifecycle.
type ServerService struct {
	app            *application.App
	db             *db.Database
	server         *server.Server
	sessionService *SessionService

	evMu     sync.RWMutex
	listener map[string][]func(name string, data ...any)

	cmdMu       sync.RWMutex
	cmdResolver CommandResolver
}

// CommandResolver rewrites an operator-typed command before it is sent to an
// agent (script-registered aliases / pre-hooks).
type CommandResolver func(command, args string) (string, string, bool)

// SetCommandResolver installs the alias/pre-hook resolver (wired by the script
// service). May be nil to disable rewriting.
func (s *ServerService) SetCommandResolver(r CommandResolver) {
	s.cmdMu.Lock()
	s.cmdResolver = r
	s.cmdMu.Unlock()
}

// resolveCommand applies the installed resolver, returning rewritten command.
func (s *ServerService) resolveCommand(command, args string) (string, string, bool) {
	s.cmdMu.RLock()
	r := s.cmdResolver
	s.cmdMu.RUnlock()
	if r == nil {
		return command, args, false
	}
	return r(command, args)
}

// NewServerService creates a new ServerService.
func NewServerService() *ServerService {
	return &ServerService{listener: map[string][]func(name string, data ...any){}}
}

// AddEventListener registers an internal listener (used by the script engine
// and other server-side components). Returns an unregister function.
func (s *ServerService) AddEventListener(name string, fn func(name string, data ...any)) func() {
	s.evMu.Lock()
	s.listener[name] = append(s.listener[name], fn)
	s.evMu.Unlock()
	return func() {
		s.evMu.Lock()
		defer s.evMu.Unlock()
		ls := s.listener[name]
		for i, f := range ls {
			if &f == &fn {
				ls = append(ls[:i], ls[i+1:]...)
				break
			}
		}
		s.listener[name] = ls
	}
}

// SetApp sets the Wails application reference.
func (s *ServerService) SetApp(app *application.App) {
	s.app = app
}

// dataDirOverride lets headless/CLI callers pin the data directory instead of
// the default (next to the executable). Empty means default behaviour.
var dataDirOverride string

// exePath returns the running executable's path.
func exePath() string {
	execPath, _ := os.Executable()
	if execPath == "" {
		execPath = "wisp"
	}
	return execPath
}

// SetDataDir pins the data directory used by Initialize.
func (s *ServerService) SetDataDir(dir string) {
	dataDirOverride = dir
}

// Initialize sets up the database and server engine.
func (s *ServerService) Initialize() error {
	// Data directory next to executable, or the operator-pinned override.
	dataDir := filepath.Join(filepath.Dir(exePath()), "data")
	if dataDirOverride != "" {
		dataDir = dataDirOverride
	}

	database, err := db.Open(dataDir)
	if err != nil {
		return err
	}
	s.db = database

	srv, err := server.New(database, s)
	if err != nil {
		return err
	}
	s.server = srv

	// Start the server engine
	if err := srv.Start(); err != nil {
		return err
	}

	log.Println("[Service] Server initialized")
	return nil
}

// EmitEvent implements server.EventEmitter, forwarding events to the frontend
// and to internal listeners.
func (s *ServerService) EmitEvent(name string, data ...any) {
	// Internal listeners (script engine hooks etc.)
	s.evMu.RLock()
	ls := s.listener[name]
	s.evMu.RUnlock()
	for _, fn := range ls {
		fn(name, data...)
	}
	// Frontend delivery (existing behaviour)
	if s.app != nil {
		s.app.Event.Emit(name, data...)
	}
}

// GetDB returns the database instance.
func (s *ServerService) GetDB() *db.Database {
	return s.db
}

// GetServer returns the server engine.
func (s *ServerService) GetServer() *server.Server {
	return s.server
}

// GetApp returns the Wails application (may be nil before SetApp is called).
func (s *ServerService) GetApp() *application.App {
	return s.app
}

// Shutdown gracefully shuts down the server.
func (s *ServerService) Shutdown() {
	if s.server != nil {
		s.server.Stop()
	}
	if s.db != nil {
		s.db.Close()
	}
}

// GetSessionService returns the session service (lazily created).
func (s *ServerService) GetSessionService() *SessionService {
	if s.sessionService == nil {
		s.sessionService = NewSessionService(s)
	}
	return s.sessionService
}

// GetRSAPublicKey returns the RSA public key PEM for payload generation.
func (s *ServerService) GetRSAPublicKey() string {
	if s.server == nil {
		return ""
	}
	return string(s.server.GetRSAPublicKeyPEM())
}
