package db

import "time"

// FileTransferRow represents one file upload/download record.
type FileTransferRow struct {
	ID         int64     `json:"id"`
	SessionID  string    `json:"session_id"`
	Direction  string    `json:"direction"` // "upload" | "download"
	LocalPath  string    `json:"local_path"`
	RemotePath string    `json:"remote_path"`
	Size       int64     `json:"size"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
}

// CreateFileTransfer records a file transfer operation.
func (d *Database) CreateFileTransfer(sessionID, direction, localPath, remotePath string, size int64, status, taskID string) error {
	now := time.Now()
	_, err := d.db.Exec(
		`INSERT INTO file_transfers (session_id, direction, local_path, remote_path, size, status, task_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		sessionID, direction, localPath, remotePath, size, status, taskID, now,
	)
	return err
}

// CompleteLatestUpload marks the most recent in-progress upload of a session
// as completed. Uploads are chunked tasks without a single task id, so the
// completion marker is matched by session + direction + status.
func (d *Database) CompleteLatestUpload(sessionID string) error {
	_, err := d.db.Exec(
		`UPDATE file_transfers SET status = 'completed' WHERE session_id = ? AND direction = 'upload' AND status = 'started'`,
		sessionID,
	)
	return err
}

// UpdateFileTransferByTask updates a transfer record by its associated task ID.
func (d *Database) UpdateFileTransferByTask(taskID, status string, size int64) error {
	_, err := d.db.Exec(
		`UPDATE file_transfers SET status = ?, size = ? WHERE task_id = ?`,
		status, size, taskID,
	)
	return err
}

// ListFileTransfers returns the most recent file transfer records (newest first).
func (d *Database) ListFileTransfers(limit int) ([]FileTransferRow, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := d.db.Query(
		`SELECT id, session_id, direction, local_path, remote_path, size, status, created_at FROM file_transfers
		 ORDER BY id DESC LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []FileTransferRow
	for rows.Next() {
		var r FileTransferRow
		if err := rows.Scan(&r.ID, &r.SessionID, &r.Direction, &r.LocalPath, &r.RemotePath, &r.Size, &r.Status, &r.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}
