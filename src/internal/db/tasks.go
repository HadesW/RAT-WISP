package db

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

// TaskRow represents a task record in the database.
type TaskRow struct {
	ID          string     `json:"id"`
	SessionID   string     `json:"session_id"`
	CommandID   int        `json:"command_id"`
	Args        string     `json:"args"`
	Status      string     `json:"status"`
	Result      string     `json:"result"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// CreateTask inserts a new task.
func (d *Database) CreateTask(sessionID string, commandID int, args string) (*TaskRow, error) {
	id := uuid.New().String()
	now := time.Now()

	_, err := d.db.Exec(
		`INSERT INTO tasks (id, session_id, command_id, args, status, created_at) VALUES (?, ?, ?, ?, 'pending', ?)`,
		id, sessionID, commandID, args, now,
	)
	if err != nil {
		return nil, err
	}

	return &TaskRow{
		ID:        id,
		SessionID: sessionID,
		CommandID: commandID,
		Args:      args,
		Status:    "pending",
		CreatedAt: now,
	}, nil
}

// GetPendingTasks returns all pending tasks for a session.
func (d *Database) GetPendingTasks(sessionID string) ([]TaskRow, error) {
	rows, err := d.db.Query(
		`SELECT id, session_id, command_id, args, status, result, created_at, completed_at FROM tasks WHERE session_id = ? AND status = 'pending' ORDER BY created_at ASC`,
		sessionID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []TaskRow
	for rows.Next() {
		t := TaskRow{}
		var resultStr sql.NullString
		if err := rows.Scan(&t.ID, &t.SessionID, &t.CommandID, &t.Args, &t.Status, &resultStr, &t.CreatedAt, &t.CompletedAt); err != nil {
			return nil, err
		}
		t.Result = d.decryptField(resultStr.String)
		result = append(result, t)
	}
	return result, nil
}

// ListTasks returns the most recent tasks across all sessions (newest first).
func (d *Database) ListTasks(limit int) ([]TaskRow, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := d.db.Query(
		`SELECT id, session_id, command_id, args, status, result, created_at, completed_at FROM tasks
		 ORDER BY created_at DESC LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []TaskRow
	for rows.Next() {
		t := TaskRow{}
		var resultStr sql.NullString
		if err := rows.Scan(&t.ID, &t.SessionID, &t.CommandID, &t.Args, &t.Status, &resultStr, &t.CreatedAt, &t.CompletedAt); err != nil {
			return nil, err
		}
		t.Result = d.decryptField(resultStr.String)
		result = append(result, t)
	}
	return result, nil
}

// DeleteTask removes a task by ID.
func (d *Database) DeleteTask(id string) error {
	_, err := d.db.Exec(`DELETE FROM tasks WHERE id = ?`, id)
	return err
}

// ClearTasksForSession removes all tasks for a session.
func (d *Database) ClearTasksForSession(sessionID string) error {
	_, err := d.db.Exec(`DELETE FROM tasks WHERE session_id = ?`, sessionID)
	return err
}

// GetTask returns a single task by ID.
func (d *Database) GetTask(id string) (*TaskRow, error) {
	row := d.db.QueryRow(
		`SELECT id, session_id, command_id, args, status, result, created_at, completed_at FROM tasks WHERE id = ?`,
		id,
	)
	t := TaskRow{}
	var resultStr sql.NullString
	if err := row.Scan(&t.ID, &t.SessionID, &t.CommandID, &t.Args, &t.Status, &resultStr, &t.CreatedAt, &t.CompletedAt); err != nil {
		return nil, err
	}
	t.Result = d.decryptField(resultStr.String)
	return &t, nil
}

// CompleteTask marks a task as completed with its result.
func (d *Database) CompleteTask(id, result, status string) error {
	encResult, err := d.encryptField(result)
	if err != nil {
		return err
	}
	now := time.Now()
	_, err = d.db.Exec(
		`UPDATE tasks SET status = ?, result = ?, completed_at = ? WHERE id = ?`,
		status, encResult, now, id,
	)
	return err
}

// MarkTasksSent marks tasks as sent.
func (d *Database) MarkTasksSent(ids []string) error {
	for _, id := range ids {
		if _, err := d.db.Exec(`UPDATE tasks SET status = 'sent' WHERE id = ?`, id); err != nil {
			return err
		}
	}
	return nil
}

// ListTasksForSession returns all tasks for a session.
func (d *Database) ListTasksForSession(sessionID string) ([]TaskRow, error) {
	rows, err := d.db.Query(
		`SELECT id, session_id, command_id, args, status, result, created_at, completed_at FROM tasks WHERE session_id = ? ORDER BY created_at DESC`,
		sessionID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []TaskRow
	for rows.Next() {
		t := TaskRow{}
		var resultStr sql.NullString
		if err := rows.Scan(&t.ID, &t.SessionID, &t.CommandID, &t.Args, &t.Status, &resultStr, &t.CreatedAt, &t.CompletedAt); err != nil {
			return nil, err
		}
		t.Result = d.decryptField(resultStr.String)
		result = append(result, t)
	}
	return result, nil
}
