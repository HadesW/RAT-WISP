package db

import (
	"time"

	"github.com/google/uuid"
)

// TargetRow is one row in the targets table.
type TargetRow struct {
	ID        string
	IP        string
	Hostname  string
	OS        string
	Note      string
	CreatedAt time.Time
}

// CredRow is one row in the credentials table.
type CredRow struct {
	ID        string
	Target    string
	Username  string
	Password  string
	Secret    string
	Kind      string
	Note      string
	CreatedAt time.Time
}

// LootRow is one row in the loot table.
type LootRow struct {
	ID        string
	SessionID string
	Name      string
	Kind      string
	Data      string
	CreatedAt time.Time
}

// AddTarget inserts a target (upsert by IP).
func (d *Database) AddTarget(ip, hostname, os, note string) (*TargetRow, error) {
	id := uuid.New().String()
	now := time.Now()
	if _, err := d.db.Exec(
		`INSERT INTO targets (id, ip, hostname, os, note, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		id, ip, hostname, os, note, now); err != nil {
		return nil, err
	}
	return &TargetRow{ID: id, IP: ip, Hostname: hostname, OS: os, Note: note, CreatedAt: now}, nil
}

// ListTargets returns all targets.
func (d *Database) ListTargets() ([]TargetRow, error) {
	rows, err := d.db.Query(`SELECT id, ip, hostname, os, note, created_at FROM targets ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TargetRow
	for rows.Next() {
		var r TargetRow
		if err := rows.Scan(&r.ID, &r.IP, &r.Hostname, &r.OS, &r.Note, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteTarget removes a target.
func (d *Database) DeleteTarget(id string) error {
	_, err := d.db.Exec(`DELETE FROM targets WHERE id = ?`, id)
	return err
}

// AddCredential inserts a credential row.
func (d *Database) AddCredential(target, username, password, secret, kind, note string) (*CredRow, error) {
	id := uuid.New().String()
	now := time.Now()
	// Credentials are sensitive: encrypt at rest like other secret fields.
	encPw, err := d.encryptField(password)
	if err != nil {
		return nil, err
	}
	encSecret, err := d.encryptField(secret)
	if err != nil {
		return nil, err
	}
	if _, err := d.db.Exec(
		`INSERT INTO credentials (id, target, username, password, secret, kind, note, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, target, username, encPw, encSecret, kind, note, now); err != nil {
		return nil, err
	}
	return &CredRow{ID: id, Target: target, Username: username, Password: password, Secret: secret, Kind: kind, Note: note, CreatedAt: now}, nil
}

// ListCredentials returns all credentials with secrets decrypted.
func (d *Database) ListCredentials() ([]CredRow, error) {
	rows, err := d.db.Query(`SELECT id, target, username, password, secret, kind, note, created_at FROM credentials ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CredRow
	for rows.Next() {
		var r CredRow
		var encPw, encSecret string
		if err := rows.Scan(&r.ID, &r.Target, &r.Username, &encPw, &encSecret, &r.Kind, &r.Note, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.Password = d.decryptField(encPw)
		r.Secret = d.decryptField(encSecret)
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteCredential removes a credential.
func (d *Database) DeleteCredential(id string) error {
	_, err := d.db.Exec(`DELETE FROM credentials WHERE id = ?`, id)
	return err
}

// AddLoot inserts a loot item.
func (d *Database) AddLoot(sessionID, name, kind, data string) (*LootRow, error) {
	id := uuid.New().String()
	now := time.Now()
	if _, err := d.db.Exec(
		`INSERT INTO loot (id, session_id, name, kind, data, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		id, sessionID, name, kind, data, now); err != nil {
		return nil, err
	}
	return &LootRow{ID: id, SessionID: sessionID, Name: name, Kind: kind, Data: data, CreatedAt: now}, nil
}

// ListLoot returns all loot items.
func (d *Database) ListLoot(limit int) ([]LootRow, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := d.db.Query(`SELECT id, session_id, name, kind, data, created_at FROM loot ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LootRow
	for rows.Next() {
		var r LootRow
		if err := rows.Scan(&r.ID, &r.SessionID, &r.Name, &r.Kind, &r.Data, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteLoot removes a loot item.
func (d *Database) DeleteLoot(id string) error {
	_, err := d.db.Exec(`DELETE FROM loot WHERE id = ?`, id)
	return err
}
