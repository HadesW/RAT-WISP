package services

import (
	"log"
	"os"
	"path/filepath"

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
}

// NewServerService creates a new ServerService.
func NewServerService() *ServerService {
	return &ServerService{}
}

// SetApp sets the Wails application reference.
func (s *ServerService) SetApp(app *application.App) {
	s.app = app
}

// Initialize sets up the database and server engine.
func (s *ServerService) Initialize() error {
	// Data directory next to executable
	execPath, _ := os.Executable()
	dataDir := filepath.Join(filepath.Dir(execPath), "data")

	// For development, use current directory
	if _, err := os.Stat(dataDir); os.IsNotExist(err) {
		dataDir = filepath.Join(".", "data")
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

// EmitEvent implements server.EventEmitter, forwarding events to the frontend.
func (s *ServerService) EmitEvent(name string, data ...any) {
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
