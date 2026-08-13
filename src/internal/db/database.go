package db

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

// encPrefix marks a value as AES-encrypted (kept plaintext otherwise).
const encPrefix = "enc:"

// Database wraps the SQLite connection with prepared statements.
type Database struct {
	db      *sql.DB
	dataDir string
	key     []byte // 32-byte AES key for at-rest field encryption
}

// Open creates or opens the SQLite database at the given path.
func Open(dataDir string) (*Database, error) {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	key, err := loadOrCreateKey(dataDir)
	if err != nil {
		return nil, fmt.Errorf("load db key: %w", err)
	}

	dbPath := filepath.Join(dataDir, "wisp.db")
	sqlDB, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Enable WAL mode and foreign keys
	if _, err := sqlDB.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return nil, err
	}
	if _, err := sqlDB.Exec("PRAGMA foreign_keys=ON"); err != nil {
		return nil, err
	}

	d := &Database{db: sqlDB, dataDir: dataDir, key: key}
	if err := d.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return d, nil
}

// DataDir returns the directory where the database file lives.
func (d *Database) DataDir() string {
	return d.dataDir
}

// loadOrCreateKey loads the persisted 32-byte AES key or generates and stores
// one on first run (0600). Losing this file makes encrypted fields unreadable.
func loadOrCreateKey(dataDir string) ([]byte, error) {
	path := filepath.Join(dataDir, "db_key.bin")
	if data, err := os.ReadFile(path); err == nil && len(data) == 32 {
		return data, nil
	}

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key, 0600); err != nil {
		return nil, err
	}
	return key, nil
}

// encryptField encrypts a plaintext field value for storage (AES-GCM).
func (d *Database) encryptField(plain string) (string, error) {
	if plain == "" {
		return plain, nil
	}
	block, err := aes.NewCipher(d.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(plain), nil)
	return encPrefix + base64.StdEncoding.EncodeToString(append(nonce, ciphertext...)), nil
}

// decryptField decrypts a stored value, returning it unchanged if it was not
// encrypted (e.g. legacy rows) or cannot be decrypted.
func (d *Database) decryptField(enc string) string {
	if !strings.HasPrefix(enc, encPrefix) {
		return enc
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(enc, encPrefix))
	if err != nil {
		return enc
	}
	block, err := aes.NewCipher(d.key)
	if err != nil {
		return enc
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return enc
	}
	if len(data) < gcm.NonceSize() {
		return enc
	}
	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return enc
	}
	return string(plain)
}

// Close closes the database connection.
func (d *Database) Close() error {
	return d.db.Close()
}

// DB returns the underlying sql.DB for advanced queries.
func (d *Database) DB() *sql.DB {
	return d.db
}

func (d *Database) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS listeners (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL UNIQUE,
		protocol TEXT NOT NULL DEFAULT 'tcp',
		host TEXT NOT NULL DEFAULT '',
		bind_host TEXT NOT NULL DEFAULT '0.0.0.0',
		bind_port INTEGER NOT NULL,
		use_tls INTEGER NOT NULL DEFAULT 0,
		status TEXT NOT NULL DEFAULT 'stopped',
		psk TEXT NOT NULL DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		listener_id TEXT NOT NULL,
		external_ip TEXT,
		internal_ip TEXT,
		hostname TEXT,
		username TEXT,
		domain TEXT,
		os TEXT,
		arch TEXT,
		pid INTEGER,
		process_name TEXT,
		is_elevated INTEGER DEFAULT 0,
		sleep_interval INTEGER DEFAULT 5000,
		jitter INTEGER DEFAULT 0,
		first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_seen DATETIME,
		status TEXT DEFAULT 'alive',
		note TEXT DEFAULT '',
		FOREIGN KEY (listener_id) REFERENCES listeners(id)
	);

	CREATE TABLE IF NOT EXISTS tasks (
		id TEXT PRIMARY KEY,
		session_id TEXT NOT NULL,
		command_id INTEGER NOT NULL,
		args TEXT,
		status TEXT DEFAULT 'pending',
		result TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		completed_at DATETIME,
		FOREIGN KEY (session_id) REFERENCES sessions(id)
	);

	CREATE TABLE IF NOT EXISTS console_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		session_id TEXT,
		type TEXT NOT NULL,
		content TEXT NOT NULL,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS file_transfers (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		session_id TEXT NOT NULL,
		direction TEXT NOT NULL,
		local_path TEXT NOT NULL DEFAULT '',
		remote_path TEXT NOT NULL DEFAULT '',
		size INTEGER NOT NULL DEFAULT 0,
		status TEXT NOT NULL DEFAULT 'started',
		task_id TEXT NOT NULL DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS settings (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL DEFAULT ''
	);

	CREATE TABLE IF NOT EXISTS targets (
		id TEXT PRIMARY KEY,
		ip TEXT NOT NULL,
		hostname TEXT NOT NULL DEFAULT '',
		os TEXT NOT NULL DEFAULT '',
		note TEXT NOT NULL DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS credentials (
		id TEXT PRIMARY KEY,
		target TEXT NOT NULL DEFAULT '',
		username TEXT NOT NULL DEFAULT '',
		password TEXT NOT NULL DEFAULT '',
		secret TEXT NOT NULL DEFAULT '',
		kind TEXT NOT NULL DEFAULT '',
		note TEXT NOT NULL DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS loot (
		id TEXT PRIMARY KEY,
		session_id TEXT NOT NULL DEFAULT '',
		name TEXT NOT NULL,
		kind TEXT NOT NULL DEFAULT '',
		data TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS stages (
		token TEXT PRIMARY KEY,
		key BLOB NOT NULL,
		payload BLOB NOT NULL,
		xor INTEGER NOT NULL DEFAULT 0,
		one_time INTEGER NOT NULL DEFAULT 1,
		expires DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS canaries (
		token TEXT PRIMARY KEY,
		build_name TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL DEFAULT 'armed',
		remote_ip TEXT NOT NULL DEFAULT '',
		triggered_at DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);
	CREATE INDEX IF NOT EXISTS idx_sessions_listener ON sessions(listener_id);
	CREATE INDEX IF NOT EXISTS idx_tasks_session ON tasks(session_id);
	CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
	CREATE INDEX IF NOT EXISTS idx_console_logs_session ON console_logs(session_id);
	CREATE INDEX IF NOT EXISTS idx_targets_ip ON targets(ip);
	CREATE INDEX IF NOT EXISTS idx_creds_target ON credentials(target);
	`
	if _, err := d.db.Exec(schema); err != nil {
		return err
	}
	return d.migrateAddColumns()
}

// migrateAddColumns applies additive column migrations for existing databases.
func (d *Database) migrateAddColumns() error {
	hasColumn := func(table, column string) (bool, error) {
		rows, err := d.db.Query(`PRAGMA table_info(` + table + `)`)
		if err != nil {
			return false, err
		}
		defer rows.Close()
		for rows.Next() {
			var cid int
			var name, ctype string
			var notnull, pk int
			var dflt any
			if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
				return false, err
			}
			if name == column {
				return true, nil
			}
		}
		return false, rows.Err()
	}

	if ok, err := hasColumn("listeners", "psk"); err != nil {
		return err
	} else if !ok {
		if _, err := d.db.Exec(`ALTER TABLE listeners ADD COLUMN psk TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	if ok, err := hasColumn("listeners", "host"); err != nil {
		return err
	} else if !ok {
		if _, err := d.db.Exec(`ALTER TABLE listeners ADD COLUMN host TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	if ok, err := hasColumn("listeners", "profile"); err != nil {
		return err
	} else if !ok {
		if _, err := d.db.Exec(`ALTER TABLE listeners ADD COLUMN profile TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	if ok, err := hasColumn("sessions", "seq"); err != nil {
		return err
	} else if !ok {
		if _, err := d.db.Exec(`ALTER TABLE sessions ADD COLUMN seq INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
		// Backfill existing rows in insertion order and seed the counter past
		// the highest number so new sessions continue from there.
		if _, err := d.db.Exec(`UPDATE sessions SET seq = rowid WHERE seq = 0`); err != nil {
			return err
		}
		if _, err := d.db.Exec(
			`INSERT INTO settings(key, value) SELECT 'session_seq', COALESCE(MAX(seq), 0) FROM sessions`,
		); err != nil {
			return err
		}
	}
	return nil
}
