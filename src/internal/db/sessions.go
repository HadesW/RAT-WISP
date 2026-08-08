package db

import (
	"database/sql"
	"strconv"
	"strings"
	"time"
)

// SessionRow represents an agent session in the database.
type SessionRow struct {
	ID            string    `json:"id"`
	Seq           int       `json:"seq"`
	ListenerID    string    `json:"listener_id"`
	Protocol      string    `json:"protocol"` // listener protocol (tcp/kcp/http/https), via JOIN
	ExternalIP    string    `json:"external_ip"`
	InternalIP    string    `json:"internal_ip"`
	Hostname      string    `json:"hostname"`
	Username      string    `json:"username"`
	Domain        string    `json:"domain"`
	OS            string    `json:"os"`
	Arch          string    `json:"arch"`
	PID           int       `json:"pid"`
	ProcessName   string    `json:"process_name"`
	IsElevated    bool      `json:"is_elevated"`
	SleepInterval int       `json:"sleep_interval"`
	Jitter        int       `json:"jitter"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	Status        string    `json:"status"`
	Note          string    `json:"note"`
}

// settingSessionSeq is the settings key holding the next session sequence
// number. It is monotonic and never reused after a session is deleted.
const settingSessionSeq = "session_seq"

// NextSessionSeq allocates the next stable session sequence number. The
// counter lives in the settings table so deleting a session does not cause
// numbers to be reused.
func (d *Database) NextSessionSeq() (int, error) {
	tx, err := d.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	cur := 0
	var val string
	err = tx.QueryRow(`SELECT value FROM settings WHERE key = ?`, settingSessionSeq).Scan(&val)
	switch {
	case err == sql.ErrNoRows:
	case err != nil:
		return 0, err
	default:
		if n, perr := strconv.Atoi(strings.TrimSpace(val)); perr == nil {
			cur = n
		}
	}
	cur++
	if _, err := tx.Exec(
		`INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		settingSessionSeq, strconv.Itoa(cur),
	); err != nil {
		return 0, err
	}
	return cur, tx.Commit()
}

// CreateSession inserts a new agent session.
func (d *Database) CreateSession(s *SessionRow) error {
	elevated := 0
	if s.IsElevated {
		elevated = 1
	}
	_, err := d.db.Exec(
		`INSERT OR REPLACE INTO sessions (id, seq, listener_id, external_ip, internal_ip, hostname, username, domain, os, arch, pid, process_name, is_elevated, sleep_interval, jitter, first_seen, last_seen, status, note)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.ID, s.Seq, s.ListenerID, s.ExternalIP, s.InternalIP, s.Hostname, s.Username, s.Domain,
		s.OS, s.Arch, s.PID, s.ProcessName, elevated, s.SleepInterval, s.Jitter,
		s.FirstSeen, s.LastSeen, s.Status, s.Note,
	)
	return err
}

// UpdateSessionLastSeen updates the last_seen timestamp.
func (d *Database) UpdateSessionLastSeen(id string, t time.Time) error {
	_, err := d.db.Exec(`UPDATE sessions SET last_seen = ? WHERE id = ?`, t, id)
	return err
}

// UpdateSessionStatus updates the status of a session.
func (d *Database) UpdateSessionStatus(id, status string) error {
	_, err := d.db.Exec(`UPDATE sessions SET status = ? WHERE id = ?`, status, id)
	return err
}

// UpdateSessionSleep updates sleep interval and jitter.
func (d *Database) UpdateSessionSleep(id string, sleep, jitter int) error {
	_, err := d.db.Exec(`UPDATE sessions SET sleep_interval = ?, jitter = ? WHERE id = ?`, sleep, jitter, id)
	return err
}

// sessionSelect returns the SELECT column list used by every session query. The
// listener protocol is pulled in through a LEFT JOIN so callers can display the
// transport (tcp/kcp/http/https) an agent came in on without extra lookups.
const sessionSelect = `SELECT s.id, s.seq, s.listener_id, s.external_ip, s.internal_ip, s.hostname, s.username, s.domain, s.os, s.arch, s.pid, s.process_name, s.is_elevated, s.sleep_interval, s.jitter, s.first_seen, s.last_seen, s.status, s.note, COALESCE(l.protocol, '')`

const sessionFrom = ` FROM sessions s LEFT JOIN listeners l ON s.listener_id = l.id`

// scanSessionRow scans one row produced by sessionSelect. The column order MUST
// match sessionSelect exactly: the listener protocol is the last column.
func (d *Database) scanSessionRow(row scannable) (*SessionRow, error) {
	s := &SessionRow{}
	var elevated int
	if err := row.Scan(&s.ID, &s.Seq, &s.ListenerID, &s.ExternalIP, &s.InternalIP, &s.Hostname, &s.Username, &s.Domain, &s.OS, &s.Arch, &s.PID, &s.ProcessName, &elevated, &s.SleepInterval, &s.Jitter, &s.FirstSeen, &s.LastSeen, &s.Status, &s.Note, &s.Protocol); err != nil {
		return nil, err
	}
	s.IsElevated = elevated == 1
	s.Note = d.decryptField(s.Note)
	return s, nil
}

// GetSession retrieves a single session by ID.
func (d *Database) GetSession(id string) (*SessionRow, error) {
	row := d.db.QueryRow(sessionSelect+sessionFrom+` WHERE s.id = ?`, id)
	return d.scanSessionRow(row)
}

// ListSessions returns all sessions, optionally filtered by status.
func (d *Database) ListSessions(statusFilter string) ([]SessionRow, error) {
	var rows *sql.Rows
	var err error
	if statusFilter == "" {
		rows, err = d.db.Query(sessionSelect + sessionFrom + ` ORDER BY s.last_seen DESC`)
	} else {
		rows, err = d.db.Query(sessionSelect+sessionFrom+` WHERE s.status = ? ORDER BY s.last_seen DESC`, statusFilter)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []SessionRow
	for rows.Next() {
		s, err := d.scanSessionRow(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, *s)
	}
	return result, nil
}

// DeleteSession removes a session and all records that reference it.
// tasks has a FK to sessions (foreign_keys=ON), so child rows must be removed
// first inside a transaction to avoid "FOREIGN KEY constraint failed".
func (d *Database) DeleteSession(id string) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	children := []string{
		`DELETE FROM tasks WHERE session_id = ?`,
		`DELETE FROM console_logs WHERE session_id = ?`,
		`DELETE FROM file_transfers WHERE session_id = ?`,
	}
	for _, stmt := range children {
		if _, err := tx.Exec(stmt, id); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`DELETE FROM sessions WHERE id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// UpdateSessionNote updates the operator note of a session.
func (d *Database) UpdateSessionNote(id, note string) error {
	encNote, err := d.encryptField(note)
	if err != nil {
		return err
	}
	_, err = d.db.Exec(`UPDATE sessions SET note = ? WHERE id = ?`, encNote, id)
	return err
}

// SearchSessions returns sessions filtered by status, listener ID and a free
// text query matched against hostname, username, external/internal IP and ID.
func (d *Database) SearchSessions(status, listenerID, query string) ([]SessionRow, error) {
	sqlQuery := sessionSelect + sessionFrom + ` WHERE 1=1`
	var args []any

	if status != "" {
		sqlQuery += ` AND s.status = ?`
		args = append(args, status)
	}
	if listenerID != "" {
		sqlQuery += ` AND s.listener_id = ?`
		args = append(args, listenerID)
	}
	if query != "" {
		like := "%" + query + "%"
		sqlQuery += ` AND (s.hostname LIKE ? OR s.username LIKE ? OR s.external_ip LIKE ? OR s.internal_ip LIKE ? OR s.id LIKE ?)`
		args = append(args, like, like, like, like, like)
	}
	sqlQuery += ` ORDER BY s.last_seen DESC`

	rows, err := d.db.Query(sqlQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []SessionRow
	for rows.Next() {
		s, err := d.scanSessionRow(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, *s)
	}
	return result, nil
}

type scannable interface {
	Scan(dest ...any) error
}

func (d *Database) scanSession(row scannable) (*SessionRow, error) {
	return d.scanSessionRow(row)
}
