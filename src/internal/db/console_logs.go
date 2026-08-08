package db

import "time"

// ConsoleLogEntry represents one console log row.
type ConsoleLogEntry struct {
	ID        int64     `json:"id"`
	SessionID string    `json:"session_id"`
	Type      string    `json:"type"` // "input" or "output"
	Content   string    `json:"content"`
	Timestamp time.Time `json:"timestamp"`
}

// InsertConsoleLog appends a console log entry for a session.
func (d *Database) InsertConsoleLog(sessionID, logType, content string) error {
	_, err := d.db.Exec(
		`INSERT INTO console_logs (session_id, type, content) VALUES (?, ?, ?)`,
		sessionID, logType, content,
	)
	return err
}

// ListConsoleLogs returns the most recent console logs for a session in
// chronological order.
func (d *Database) ListConsoleLogs(sessionID string, limit int) ([]ConsoleLogEntry, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := d.db.Query(
		`SELECT id, session_id, type, content, timestamp FROM console_logs
		 WHERE session_id = ? ORDER BY id DESC LIMIT ?`,
		sessionID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []ConsoleLogEntry
	for rows.Next() {
		var l ConsoleLogEntry
		if err := rows.Scan(&l.ID, &l.SessionID, &l.Type, &l.Content, &l.Timestamp); err != nil {
			return nil, err
		}
		logs = append(logs, l)
	}
	// Reverse to chronological order
	for i, j := 0, len(logs)-1; i < j; i, j = i+1, j-1 {
		logs[i], logs[j] = logs[j], logs[i]
	}
	return logs, nil
}

// ListAllConsoleLogs returns the most recent console logs across all sessions
// (used by the audit Log page) in chronological order.
func (d *Database) ListAllConsoleLogs(limit int) ([]ConsoleLogEntry, error) {
	if limit <= 0 {
		limit = 500
	}
	rows, err := d.db.Query(
		`SELECT id, session_id, type, content, timestamp FROM console_logs
		 ORDER BY id DESC LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []ConsoleLogEntry
	for rows.Next() {
		var l ConsoleLogEntry
		if err := rows.Scan(&l.ID, &l.SessionID, &l.Type, &l.Content, &l.Timestamp); err != nil {
			return nil, err
		}
		logs = append(logs, l)
	}
	// Reverse to chronological order
	for i, j := 0, len(logs)-1; i < j; i, j = i+1, j-1 {
		logs[i], logs[j] = logs[j], logs[i]
	}
	return logs, nil
}

// ClearConsoleLogs removes all console logs for a session.
func (d *Database) ClearConsoleLogs(sessionID string) error {
	_, err := d.db.Exec(`DELETE FROM console_logs WHERE session_id = ?`, sessionID)
	return err
}
