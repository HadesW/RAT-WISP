package services

import (
	"fmt"

	"github.com/user/wisp/internal/db"
	"github.com/user/wisp/shared/protocol"
)

// ListenerService handles listener CRUD operations for the frontend.
type ListenerService struct {
	serverSvc *ServerService
}

// NewListenerService creates a new ListenerService.
func NewListenerService(serverSvc *ServerService) *ListenerService {
	return &ListenerService{serverSvc: serverSvc}
}

// ListenerInfo is the data exposed to the frontend.
type ListenerInfo struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Host     string `json:"host"` // callback address agents connect to
	BindHost string `json:"bind_host"`
	BindPort int    `json:"bind_port"`
	UseTLS   bool   `json:"use_tls"`
	Status   string `json:"status"`
	PSK      string `json:"psk"`
}

// Create creates a new listener configuration (Cobalt Strike style: the Host
// is the callback address baked into payloads, while bindHost is the local
// address the server listens on). When host is empty the machine's LAN IP is
// auto-detected so payloads work from other machines out of the box.
// proto must be one of: tcp, http, https. psk is an optional pre-shared key:
// agents built against this listener must present it during registration.
func (ls *ListenerService) Create(name, proto, host, bindHost string, port int, useTLS bool, psk string, profile ...string) (*ListenerInfo, error) {
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if proto == "" {
		proto = protocol.ProtocolTCP
	}
	if !isSupportedProtocol(proto) {
		return nil, fmt.Errorf("unsupported protocol: %s", proto)
	}
	// https implies TLS; reject explicit mismatch
	if proto == protocol.ProtocolHTTPS && !useTLS {
		useTLS = true
	}
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port: %d", port)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = pickServerHost()
	}
	if bindHost == "" {
		bindHost = "0.0.0.0"
	}

	row, err := ls.serverSvc.GetDB().CreateListener(name, proto, bindHost, port, useTLS, psk, host)
	if err != nil {
		return nil, err
	}

	// Optional Malleable profile baked in at creation time (the Cobalt-Strike
	// style "pick a profile, create the listener, it just works" flow). No
	// separate SetProfile call needed; the listener is born with the profile.
	if len(profile) > 0 && profile[0] != "" {
		if err := ls.serverSvc.GetDB().SetListenerProfile(row.ID, profile[0]); err != nil {
			return nil, err
		}
	}

	return rowToInfo(row), nil
}

// GetSupportedProtocols returns the listener protocols the server supports.
func (ls *ListenerService) GetSupportedProtocols() []string {
	return protocol.SupportedListenerProtocols()
}

// SetProfile stores a Malleable profile JSON on a listener. Restart the
// listener for URI/header changes to take effect.
func (ls *ListenerService) SetProfile(id, profileJSON string) error {
	if id == "" {
		return fmt.Errorf("listener id is required")
	}
	if _, err := ls.serverSvc.GetDB().GetListener(id); err != nil {
		return fmt.Errorf("listener not found: %w", err)
	}
	return ls.serverSvc.GetDB().SetListenerProfile(id, profileJSON)
}

func isSupportedProtocol(p string) bool {
	for _, s := range protocol.SupportedListenerProtocols() {
		if s == p {
			return true
		}
	}
	return false
}

// Start starts a listener by ID.
func (ls *ListenerService) Start(id string) error {
	return ls.serverSvc.GetServer().StartListener(id)
}

// Stop stops a listener by ID.
func (ls *ListenerService) Stop(id string) error {
	return ls.serverSvc.GetServer().StopListener(id)
}

// Delete removes a listener. It must be stopped first.
func (ls *ListenerService) Delete(id string) error {
	row, err := ls.serverSvc.GetDB().GetListener(id)
	if err != nil {
		return err
	}
	if row.Status == "running" {
		return fmt.Errorf("stop the listener before deleting")
	}
	return ls.serverSvc.GetDB().DeleteListener(id)
}

// List returns all listeners.
func (ls *ListenerService) List() ([]ListenerInfo, error) {
	rows, err := ls.serverSvc.GetDB().ListListeners()
	if err != nil {
		return nil, err
	}

	result := make([]ListenerInfo, len(rows))
	for i, r := range rows {
		result[i] = *rowToInfo(&r)
	}
	return result, nil
}

func rowToInfo(r *db.ListenerRow) *ListenerInfo {
	return &ListenerInfo{
		ID:       r.ID,
		Name:     r.Name,
		Protocol: r.Protocol,
		Host:     r.Host,
		BindHost: r.BindHost,
		BindPort: r.BindPort,
		UseTLS:   r.UseTLS,
		Status:   r.Status,
		PSK:      r.PSK,
	}
}
