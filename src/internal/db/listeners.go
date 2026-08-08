package db

import (
	"time"

	"github.com/google/uuid"
)

// ListenerRow represents a listener record in the database.
// Host is the callback address agents connect to (Cobalt Strike style), while
// BindHost is the local address the server binds on (usually 0.0.0.0).
type ListenerRow struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Protocol  string    `json:"protocol"`
	Host      string    `json:"host"`      // callback address baked into payloads
	BindHost  string    `json:"bind_host"` // address the server listens on
	BindPort  int       `json:"bind_port"`
	UseTLS    bool      `json:"use_tls"`
	Status    string    `json:"status"`
	PSK       string    `json:"psk"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateListener inserts a new listener with an optional pre-shared key.
// host (variadic) is the callback address agents connect to; when omitted it
// falls back to bindHost so legacy callers keep working.
func (d *Database) CreateListener(name, protocol, bindHost string, bindPort int, useTLS bool, psk string, host ...string) (*ListenerRow, error) {
	id := uuid.New().String()
	now := time.Now()
	tlsInt := 0
	if useTLS {
		tlsInt = 1
	}

	cbHost := ""
	if len(host) > 0 {
		cbHost = host[0]
	}
	if cbHost == "" || cbHost == "0.0.0.0" || cbHost == "::" {
		cbHost = bindHost
	}

	// Store the pre-shared key encrypted, like other sensitive fields
	encPSK, err := d.encryptField(psk)
	if err != nil {
		return nil, err
	}
	_, err = d.db.Exec(
		`INSERT INTO listeners (id, name, protocol, host, bind_host, bind_port, use_tls, status, psk, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'stopped', ?, ?)`,
		id, name, protocol, cbHost, bindHost, bindPort, tlsInt, encPSK, now,
	)
	if err != nil {
		return nil, err
	}

	return &ListenerRow{
		ID:        id,
		Name:      name,
		Protocol:  protocol,
		Host:      cbHost,
		BindHost:  bindHost,
		BindPort:  bindPort,
		UseTLS:    useTLS,
		Status:    "stopped",
		PSK:       psk,
		CreatedAt: now,
	}, nil
}

// UpdateListenerStatus updates the status of a listener.
func (d *Database) UpdateListenerStatus(id, status string) error {
	_, err := d.db.Exec(`UPDATE listeners SET status = ? WHERE id = ?`, status, id)
	return err
}

// DeleteListener removes a listener by ID.
func (d *Database) DeleteListener(id string) error {
	_, err := d.db.Exec(`DELETE FROM listeners WHERE id = ?`, id)
	return err
}

// GetListener retrieves a single listener by ID.
func (d *Database) GetListener(id string) (*ListenerRow, error) {
	row := d.db.QueryRow(`SELECT id, name, protocol, host, bind_host, bind_port, use_tls, status, psk, created_at FROM listeners WHERE id = ?`, id)
	l := &ListenerRow{}
	var tlsInt int
	if err := row.Scan(&l.ID, &l.Name, &l.Protocol, &l.Host, &l.BindHost, &l.BindPort, &tlsInt, &l.Status, &l.PSK, &l.CreatedAt); err != nil {
		return nil, err
	}
	l.UseTLS = tlsInt == 1
	l.PSK = d.decryptField(l.PSK)
	return l, nil
}

// ListListeners returns all listeners.
func (d *Database) ListListeners() ([]ListenerRow, error) {
	rows, err := d.db.Query(`SELECT id, name, protocol, host, bind_host, bind_port, use_tls, status, psk, created_at FROM listeners ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []ListenerRow
	for rows.Next() {
		l := ListenerRow{}
		var tlsInt int
		if err := rows.Scan(&l.ID, &l.Name, &l.Protocol, &l.Host, &l.BindHost, &l.BindPort, &tlsInt, &l.Status, &l.PSK, &l.CreatedAt); err != nil {
			return nil, err
		}
		l.UseTLS = tlsInt == 1
		l.PSK = d.decryptField(l.PSK)
		result = append(result, l)
	}
	return result, nil
}
