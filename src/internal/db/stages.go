package db

import (
	"database/sql"
)

// StageRow is the persisted form of a stage-2 payload so a stager keeps
// working across server restarts. The payload bytes are the sRDI-packed agent
// (already encrypted on download); only the key and blob are stored.
type StageRow struct {
	Token   string
	Key     []byte
	Payload []byte
	XOR     bool
	OneTime bool
	Expires sql.NullTime
}

// SaveStage persists (or replaces) a stage.
func (d *Database) SaveStage(s StageRow) error {
	_, err := d.db.Exec(
		`INSERT INTO stages(token, key, payload, xor, one_time, expires) VALUES(?,?,?,?,?,?)
		 ON CONFLICT(token) DO UPDATE SET key=excluded.key, payload=excluded.payload,
		 xor=excluded.xor, one_time=excluded.one_time, expires=excluded.expires`,
		s.Token, s.Key, s.Payload, boolInt(s.XOR), boolInt(s.OneTime), nullableTime(s.Expires),
	)
	return err
}

// LoadStages returns every persisted stage (used to restore the stage store on
// startup so already-issued stagers keep working after a server restart).
func (d *Database) LoadStages() ([]StageRow, error) {
	rows, err := d.db.Query(`SELECT token, key, payload, xor, one_time, expires FROM stages`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []StageRow
	for rows.Next() {
		var s StageRow
		var xor, oneTime int
		var expires sql.NullTime
		if err := rows.Scan(&s.Token, &s.Key, &s.Payload, &xor, &oneTime, &expires); err != nil {
			return nil, err
		}
		s.XOR = xor != 0
		s.OneTime = oneTime != 0
		s.Expires = expires
		out = append(out, s)
	}
	return out, rows.Err()
}

// DeleteStage removes a consumed / expired stage.
func (d *Database) DeleteStage(token string) error {
	_, err := d.db.Exec(`DELETE FROM stages WHERE token = ?`, token)
	return err
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullableTime(t sql.NullTime) any {
	if !t.Valid {
		return nil
	}
	return t.Time
}
