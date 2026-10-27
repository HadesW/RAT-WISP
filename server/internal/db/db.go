// Package db persists teamserver state (plan §1 存储): sessions, tasks,
// audit log, all keyed by project. Session key material NEVER touches disk —
// the DB is history/audit, memory is authoritative for live sessions.
package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"wispp/protocol"
)

type Store struct{ DB *sql.DB }

const schema = `
CREATE TABLE IF NOT EXISTS session_meta(
  session TEXT PRIMARY KEY, tags TEXT, notes TEXT, color TEXT, updated INTEGER
);
CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, color TEXT, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY, project TEXT NOT NULL,
  info TEXT NOT NULL,            -- protocol.SystemInfo JSON
  first_seen INTEGER, last_seen INTEGER, seq INTEGER, status TEXT,
  FOREIGN KEY(project) REFERENCES projects(id)
);
CREATE TABLE IF NOT EXISTS tasks (
  id TEXT PRIMARY KEY, session TEXT NOT NULL, project TEXT NOT NULL,
  cmd INTEGER, args TEXT, status TEXT, output TEXT, exit_code INTEGER,
  created INTEGER, updated INTEGER
);
CREATE TABLE IF NOT EXISTS file_jobs (
  id TEXT PRIMARY KEY, agent TEXT NOT NULL, project TEXT NOT NULL,
  mode TEXT, remote TEXT, local TEXT, size INTEGER, chunk INTEGER,
  received INTEGER DEFAULT 0, sha256 TEXT, status TEXT, -- pending|active|done|failed|cancelled
  created INTEGER, updated INTEGER
);
CREATE TABLE IF NOT EXISTS audit (
  ts INTEGER, level TEXT, kind TEXT, project TEXT, text TEXT
);
CREATE TABLE IF NOT EXISTS listeners (
  id TEXT PRIMARY KEY, name TEXT, kind TEXT, addr TEXT, host TEXT, profile TEXT, project TEXT, enabled INTEGER, created INTEGER
);
CREATE TABLE IF NOT EXISTS profiles (
  name TEXT PRIMARY KEY, body TEXT, updated INTEGER
);
CREATE TABLE IF NOT EXISTS plugins (
  id TEXT PRIMARY KEY, version TEXT, capabilities TEXT, path TEXT, sha256 TEXT, enabled INTEGER, installed INTEGER
);
CREATE TABLE IF NOT EXISTS plugin_calls (
  ts INTEGER, agent TEXT, plugin TEXT, entry TEXT, result TEXT
);
CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY, project TEXT, title TEXT, markdown TEXT, model TEXT, created INTEGER
);
CREATE TABLE IF NOT EXISTS goals (
  id TEXT PRIMARY KEY, project TEXT, title TEXT, status TEXT, created INTEGER, updated INTEGER
);
CREATE TABLE IF NOT EXISTS goal_steps (
  id TEXT PRIMARY KEY, goal TEXT, seq INTEGER, name TEXT, kind TEXT, args TEXT,
  status TEXT, result TEXT, updated INTEGER
);
CREATE TABLE IF NOT EXISTS forwards (
  id TEXT PRIMARY KEY, session TEXT, listen TEXT, target TEXT, status TEXT, created INTEGER
);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY, value TEXT
);
CREATE TABLE IF NOT EXISTS deliveries (
  id TEXT PRIMARY KEY, token TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
  payload TEXT NOT NULL, name TEXT NOT NULL, file TEXT NOT NULL,
  project TEXT NOT NULL, content_type TEXT,
  expires_at INTEGER DEFAULT 0, max_downloads INTEGER DEFAULT 0,
  downloads INTEGER DEFAULT 0, requests INTEGER DEFAULT 0, bytes_out INTEGER DEFAULT 0,
  revoked INTEGER DEFAULT 0, created INTEGER, last_seen INTEGER
);
CREATE TABLE IF NOT EXISTS shares (
  id TEXT PRIMARY KEY, token TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL, file TEXT NOT NULL, project TEXT NOT NULL,
  password_hash TEXT, expires_at INTEGER DEFAULT 0, max_downloads INTEGER DEFAULT 0,
  downloads INTEGER DEFAULT 0, requests INTEGER DEFAULT 0, bytes_out INTEGER DEFAULT 0,
  revoked INTEGER DEFAULT 0, created INTEGER, last_seen INTEGER
);
CREATE INDEX IF NOT EXISTS idx_deliveries_project ON deliveries(project);
CREATE INDEX IF NOT EXISTS idx_shares_project ON shares(project);
CREATE TABLE IF NOT EXISTS counters (
  name TEXT PRIMARY KEY, value INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_project ON sessions(project);
CREATE INDEX IF NOT EXISTS idx_tasks_session ON tasks(session);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts DESC);
CREATE TABLE IF NOT EXISTS ai_conversations (
  id TEXT PRIMARY KEY, project TEXT, title TEXT, created INTEGER, updated INTEGER
);
CREATE TABLE IF NOT EXISTS ai_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT, conv TEXT NOT NULL,
  role TEXT NOT NULL, content TEXT, tool_calls TEXT, tool_call_id TEXT,
  name TEXT, created INTEGER
);
CREATE TABLE IF NOT EXISTS ai_approvals (
  id TEXT PRIMARY KEY, conv TEXT, tool TEXT, args TEXT,
  status TEXT, result TEXT, callid TEXT, created INTEGER, decided INTEGER
);
CREATE INDEX IF NOT EXISTS idx_ai_msgs ON ai_messages(conv, id);
`

func Open(path string) (*Store, error) {
	d, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(4000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	d.SetMaxOpenConns(1) // single writer; WAL readers unaffected
	if _, err := d.Exec(schema); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	// additive column migrations for pre-existing databases (idempotent)
	for _, col := range [][2]string{
		{"sessions", "num INTEGER NOT NULL DEFAULT 0"},
		{"ai_approvals", "callid TEXT"},
		{"ai_conversations", "updated INTEGER"},
		{"listeners", "name TEXT"},
		{"listeners", "host TEXT"},
	} {
		if _, err := d.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s", col[0], col[1])); err != nil &&
			!strings.Contains(err.Error(), "duplicate column") {
			return nil, fmt.Errorf("migrate %s.%s: %w", col[0], col[1], err)
		}
	}
	s := &Store{DB: d}
	return s, s.EnsureProject("default", "Default", "#2F81F7")
}

func (s *Store) EnsureProject(id, name, color string) error {
	_, err := s.DB.Exec(`INSERT INTO projects(id,name,color,created_at) VALUES(?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name, color=excluded.color`,
		id, name, color, time.Now().Unix())
	return err
}

func (s *Store) Projects() ([][3]string, error) {
	rows, err := s.DB.Query(`SELECT id,name,color FROM projects ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][3]string
	for rows.Next() {
		var a, b, c string
		if err := rows.Scan(&a, &b, &c); err != nil {
			return nil, err
		}
		out = append(out, [3]string{a, b, c})
	}
	return out, rows.Err()
}

// UpsertSession stores (creates or refreshes) the session history row.
// num<=0 keeps any previously assigned display number (numbers are permanent
// for an agent id until the session row is deleted).
func (s *Store) UpsertSession(id, project string, info protocol.SystemInfo, first, last time.Time, seq uint64, status string, num int) error {
	b, _ := json.Marshal(info)
	_, err := s.DB.Exec(`INSERT INTO sessions(id,project,info,first_seen,last_seen,seq,status,num)
		VALUES(?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET project=excluded.project, info=excluded.info,
			last_seen=excluded.last_seen, seq=excluded.seq, status=excluded.status,
			num=CASE WHEN excluded.num > 0 THEN excluded.num ELSE sessions.num END`,
		id, project, string(b), first.Unix(), last.Unix(), int64(seq), status, max(num, 0))
	return err
}

// SessionNum returns the persisted display number for an agent (0 = none).
func (s *Store) SessionNum(id string) int {
	var n int
	_ = s.DB.QueryRow(`SELECT num FROM sessions WHERE id=?`, id).Scan(&n)
	return n
}

// NextCounter bumps and returns a durable monotonic counter (numbers are
// never reused, even after the owning session is deleted).
func (s *Store) NextCounter(name string) (int, error) {
	var v int
	err := s.DB.QueryRow(`INSERT INTO counters(name,value) VALUES(?,1)
		ON CONFLICT(name) DO UPDATE SET value=value+1 RETURNING value`, name).Scan(&v)
	return v, err
}

// DeleteSession forgets a session row entirely (ctx-menu delete).
func (s *Store) DeleteSession(id string) error {
	_, err := s.DB.Exec(`DELETE FROM sessions WHERE id=?`, id)
	return err
}

type SessionRow struct {
	ID, Project, Info   string
	FirstSeen, LastSeen int64
	Seq                 int64
	Status              string
	Num                 int `json:"num"`
}

func (s *Store) Sessions(project string) ([]SessionRow, error) {
	q := `SELECT id,project,info,first_seen,last_seen,seq,status,num FROM sessions`
	args := []any{}
	if project != "" {
		q += ` WHERE project=?`
		args = append(args, project)
	}
	q += ` ORDER BY last_seen DESC`
	rows, err := s.DB.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SessionRow
	for rows.Next() {
		var r SessionRow
		if err := rows.Scan(&r.ID, &r.Project, &r.Info, &r.FirstSeen, &r.LastSeen, &r.Seq, &r.Status, &r.Num); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) TaskCreated(id, session, project string, cmd uint32, args []byte) error {
	_, err := s.DB.Exec(`INSERT INTO tasks(id,session,project,cmd,args,status,created,updated)
		VALUES(?,?,?,?,?,?,?,?)`, id, session, project, cmd, string(args),
		protocol.TaskPending, time.Now().Unix(), time.Now().Unix())
	return err
}

func (s *Store) TaskStatus(id, status string, output string, exitCode int) error {
	_, err := s.DB.Exec(`UPDATE tasks SET status=?, output=?, exit_code=?, updated=? WHERE id=?`,
		status, output, exitCode, time.Now().Unix(), id)
	return err
}

func (s *Store) Audit(ts time.Time, level, kind, project, text string) error {
	_, err := s.DB.Exec(`INSERT INTO audit(ts,level,kind,project,text) VALUES(?,?,?,?,?)`,
		ts.Unix(), level, kind, project, text)
	return err
}

// ---- file jobs (plan §2.4) ----

type FileJob struct {
	ID       string `json:"id"`
	Agent    string `json:"agent"`
	Project  string `json:"project"`
	Mode     string `json:"mode"` // up (agent->server) | down (server->agent)
	Remote   string `json:"remote"`
	Local    string `json:"local"`
	Size     int64  `json:"size"`
	Chunk    int    `json:"chunk"`
	Received int    `json:"received"`
	SHA256   string `json:"sha256"`
	Status   string `json:"status"`
	Created  int64  `json:"created"`
}

func (s *Store) FileJobCreated(j *FileJob) error {
	// upsert: Retry() restarts an existing row, keeping `received` as the
	// operator-visible high-water mark until the pumps advance it.
	_, err := s.DB.Exec(`INSERT INTO file_jobs(id,agent,project,mode,remote,local,size,chunk,received,sha256,status,created,updated)
		VALUES(?,?,?,?,?,?,?,?,0,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET status=excluded.status, updated=excluded.updated`,
		j.ID, j.Agent, j.Project, j.Mode, j.Remote, j.Local, j.Size, j.Chunk, j.SHA256, j.Status,
		time.Now().Unix(), time.Now().Unix())
	return err
}

func (s *Store) FileJobProgress(id string, received int, status string) error {
	_, err := s.DB.Exec(`UPDATE file_jobs SET received=?, status=?, updated=? WHERE id=?`,
		received, status, time.Now().Unix(), id)
	return err
}

func (s *Store) FileJobs(project string) ([]FileJob, error) {
	q := `SELECT id,agent,project,mode,remote,local,size,chunk,received,sha256,status FROM file_jobs`
	args := []any{}
	if project != "" {
		q += ` WHERE project=?`
		args = append(args, project)
	}
	q += ` ORDER BY created DESC LIMIT 200`
	rows, err := s.DB.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FileJob
	for rows.Next() {
		var j FileJob
		if err := rows.Scan(&j.ID, &j.Agent, &j.Project, &j.Mode, &j.Remote, &j.Local,
			&j.Size, &j.Chunk, &j.Received, &j.SHA256, &j.Status); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// FileJobSealed records the finalized local path/hash on completion.
func (s *Store) FileJobSealed(id, local, sha string, size int64, status string) error {
	_, err := s.DB.Exec(`UPDATE file_jobs SET local=?, sha256=?, size=?, status=?, updated=? WHERE id=?`,
		local, sha, size, status, time.Now().Unix(), id)
	return err
}

// ---- AI persistence (plan M6) ----

func (s *Store) AITouch(conv, project, title string) error {
	now := time.Now().Unix()
	_, err := s.DB.Exec(`INSERT INTO ai_conversations(id,project,title,created,updated) VALUES(?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET title=CASE WHEN ai_conversations.title='' THEN excluded.title ELSE ai_conversations.title END,
			updated=excluded.updated`,
		conv, project, title, now, now)
	return err
}

func (s *Store) AIAppendMessage(conv, role, content, toolCalls, toolCallID, name string) error {
	now := time.Now().Unix()
	if _, err := s.DB.Exec(`INSERT INTO ai_messages(conv,role,content,tool_calls,tool_call_id,name,created)
		VALUES(?,?,?,?,?,?,?)`, conv, role, content, toolCalls, toolCallID, name, now); err != nil {
		return err
	}
	_, err := s.DB.Exec(`UPDATE ai_conversations SET updated=? WHERE id=?`, now, conv)
	return err
}

type AIMessage struct {
	Role, Content, ToolCalls, ToolCallID, Name string
}

func (s *Store) AIMessages(conv string, limit int) ([]AIMessage, error) {
	rows, err := s.DB.Query(`SELECT role,content,COALESCE(tool_calls,''),COALESCE(tool_call_id,''),COALESCE(name,'')
		FROM ai_messages WHERE conv=? ORDER BY id DESC LIMIT ?`, conv, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rev []AIMessage
	for rows.Next() {
		var m AIMessage
		if err := rows.Scan(&m.Role, &m.Content, &m.ToolCalls, &m.ToolCallID, &m.Name); err != nil {
			return nil, err
		}
		rev = append(rev, m)
	}
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	return rev, rows.Err()
}

func (s *Store) AICreateApproval(id, conv, tool, args, callid string) error {
	_, err := s.DB.Exec(`INSERT INTO ai_approvals(id,conv,tool,args,status,callid,created) VALUES(?,?,?,?,?,?,?)`,
		id, conv, tool, args, "pending", callid, time.Now().Unix())
	return err
}

// AIUpdateToolMessage replaces the placeholder tool message for callid (1:1
// tool_call_id <-> tool message; strict OpenAI-compatible endpoints require it).
func (s *Store) AIUpdateToolMessage(conv, callid, content string) error {
	_, err := s.DB.Exec(`UPDATE ai_messages SET content=? WHERE conv=? AND tool_call_id=? AND role='tool'`,
		content, conv, callid)
	return err
}

type AIApproval struct {
	ID      string `json:"id"`
	Conv    string `json:"conv"`
	Tool    string `json:"tool"`
	Args    string `json:"args"`
	Status  string `json:"status"`
	Result  string `json:"result"`
	CallID  string `json:"callid"`
	Created int64  `json:"created"`
	Decided int64  `json:"decided"`
}

func (s *Store) AIApproval(id string) (*AIApproval, error) {
	var a AIApproval
	err := s.DB.QueryRow(`SELECT id,conv,tool,args,status,COALESCE(result,''),COALESCE(callid,''),created,COALESCE(decided,0)
		FROM ai_approvals WHERE id=?`, id).Scan(&a.ID, &a.Conv, &a.Tool, &a.Args, &a.Status, &a.Result, &a.CallID, &a.Created, &a.Decided)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// AIDecide flips pending->approved/rejected atomically; false = not pending anymore.
func (s *Store) AIDecide(id, status, result string) bool {
	res, err := s.DB.Exec(`UPDATE ai_approvals SET status=?, result=?, decided=? WHERE id=? AND status='pending'`,
		status, result, time.Now().Unix(), id)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n == 1
}

// AIDecideResult stores the executed result onto an approved row.
func (s *Store) AIDecideResult(id, result string) error {
	_, err := s.DB.Exec(`UPDATE ai_approvals SET result=? WHERE id=?`, result, id)
	return err
}

func (s *Store) AIPendingApprovals() ([]AIApproval, error) {
	rows, err := s.DB.Query(`SELECT id,conv,tool,args,status,COALESCE(result,''),COALESCE(callid,''),created,COALESCE(decided,0)
		FROM ai_approvals WHERE status='pending' ORDER BY created DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AIApproval
	for rows.Next() {
		var a AIApproval
		if err := rows.Scan(&a.ID, &a.Conv, &a.Tool, &a.Args, &a.Status, &a.Result, &a.CallID, &a.Created, &a.Decided); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ---- conversation management (console AI panel) ----

type AIConversation struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Updated int64  `json:"updated"`
}

func (s *Store) AIConversations(project string) ([]AIConversation, error) {
	q := `SELECT id,COALESCE(title,''),COALESCE(updated,created) FROM ai_conversations`
	args := []any{}
	if project != "" {
		q += ` WHERE project=?`
		args = append(args, project)
	}
	q += ` ORDER BY COALESCE(updated,created) DESC LIMIT 50`
	rows, err := s.DB.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AIConversation
	for rows.Next() {
		var c AIConversation
		if err := rows.Scan(&c.ID, &c.Title, &c.Updated); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) AIRenameConversation(id, title string) error {
	_, err := s.DB.Exec(`UPDATE ai_conversations SET title=? WHERE id=?`, title, id)
	return err
}

// AIDeleteConversation drops the chat + messages; pending approvals of the
// conversation are rejected first so no orphan write sits in the queue.
func (s *Store) AIDeleteConversation(id string) error {
	if _, err := s.DB.Exec(`UPDATE ai_approvals SET status='rejected', result='{"rejected":"conversation deleted"}', decided=?
		WHERE conv=? AND status='pending'`, time.Now().Unix(), id); err != nil {
		return err
	}
	if _, err := s.DB.Exec(`DELETE FROM ai_messages WHERE conv=?`, id); err != nil {
		return err
	}
	_, err := s.DB.Exec(`DELETE FROM ai_conversations WHERE id=?`, id)
	return err
}

// ---- listeners & malleable profiles ----

type ListenerRow struct {
	ID, Name, Kind, Addr, Host, Profile, Project string
	Enabled                                      bool
}

func (s *Store) ListenerUpsert(l *ListenerRow) error {
	_, err := s.DB.Exec(`INSERT INTO listeners(id,name,kind,addr,host,profile,project,enabled,created) VALUES(?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name, kind=excluded.kind, addr=excluded.addr, host=excluded.host,
			profile=excluded.profile, project=excluded.project, enabled=excluded.enabled`,
		l.ID, l.Name, l.Kind, l.Addr, l.Host, l.Profile, l.Project, l.Enabled, time.Now().Unix())
	return err
}

func (s *Store) ListenerDelete(id string) error {
	_, err := s.DB.Exec(`DELETE FROM listeners WHERE id=?`, id)
	return err
}

func (s *Store) Listeners() ([]ListenerRow, error) {
	rows, err := s.DB.Query(`SELECT id,COALESCE(name,''),kind,addr,COALESCE(host,''),profile,project,enabled FROM listeners ORDER BY created`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ListenerRow
	for rows.Next() {
		var l ListenerRow
		if err := rows.Scan(&l.ID, &l.Name, &l.Kind, &l.Addr, &l.Host, &l.Profile, &l.Project, &l.Enabled); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func (s *Store) ProfileUpsert(name, body string) error {
	_, err := s.DB.Exec(`INSERT INTO profiles(name,body,updated) VALUES(?,?,?)
		ON CONFLICT(name) DO UPDATE SET body=excluded.body, updated=excluded.updated`,
		name, body, time.Now().Unix())
	return err
}

func (s *Store) ProfileDelete(name string) error {
	_, err := s.DB.Exec(`DELETE FROM profiles WHERE name=? AND name NOT IN ('generic','github-api')`, name)
	return err // builtins protected
}

func (s *Store) ProfileGet(name string) (string, bool) {
	var b string
	err := s.DB.QueryRow(`SELECT body FROM profiles WHERE name=?`, name).Scan(&b)
	return b, err == nil
}

type ProfileRow struct {
	Name, Body string
	Updated    int64
}

func (s *Store) ProfileList() ([]ProfileRow, error) {
	rows, err := s.DB.Query(`SELECT name,body,updated FROM profiles ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProfileRow
	for rows.Next() {
		var p ProfileRow
		if err := rows.Scan(&p.Name, &p.Body, &p.Updated); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ---- plugin repository rows (plan §5) ----

type PluginRow struct {
	ID, Version, Capabilities, Path, SHA256 string
	Enabled                                 bool
}

func (s *Store) PluginUpsert(id, version, caps, path, sha string, enabled bool) error {
	_, err := s.DB.Exec(`INSERT INTO plugins(id,version,capabilities,path,sha256,enabled,installed) VALUES(?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET version=excluded.version, capabilities=excluded.capabilities,
			path=excluded.path, sha256=excluded.sha256, enabled=excluded.enabled`,
		id, version, caps, path, sha, enabled, time.Now().Unix())
	return err
}

func (s *Store) PluginList() ([]PluginRow, error) {
	rows, err := s.DB.Query(`SELECT id,version,capabilities,path,sha256,enabled FROM plugins ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PluginRow
	for rows.Next() {
		var p PluginRow
		if err := rows.Scan(&p.ID, &p.Version, &p.Capabilities, &p.Path, &p.SHA256, &p.Enabled); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) PluginGet(id string) (*PluginRow, error) {
	var p PluginRow
	err := s.DB.QueryRow(`SELECT id,version,capabilities,path,sha256,enabled FROM plugins WHERE id=?`, id).
		Scan(&p.ID, &p.Version, &p.Capabilities, &p.Path, &p.SHA256, &p.Enabled)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *Store) PluginSetEnabled(id string, on bool) error {
	_, err := s.DB.Exec(`UPDATE plugins SET enabled=? WHERE id=?`, on, id)
	return err
}

func (s *Store) PluginDelete(id string) error {
	_, err := s.DB.Exec(`DELETE FROM plugins WHERE id=?`, id)
	return err
}

func (s *Store) PluginCall(agent, plugin, entry, result string) error {
	_, err := s.DB.Exec(`INSERT INTO plugin_calls(ts,agent,plugin,entry,result) VALUES(?,?,?,?,?)`,
		time.Now().Unix(), agent, plugin, entry, result)
	return err
}

func (s *Store) PluginCalls(limit int) ([]map[string]any, error) {
	rows, err := s.DB.Query(`SELECT ts,agent,plugin,entry,result FROM plugin_calls ORDER BY ts DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var ts int64
		var a, p, e, res string
		if err := rows.Scan(&ts, &a, &p, &e, &res); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"ts": ts, "agent": a, "plugin": p, "entry": e, "result": res})
	}
	return out, rows.Err()
}

// MarkAllSessionsOffline runs at boot: memory is authoritative for liveness,
// so any persisted online/idle row is stale history and must read offline.
func (s *Store) MarkAllSessionsOffline() error {
	_, err := s.DB.Exec(`UPDATE sessions SET status='offline' WHERE status != 'offline'`)
	return err
}

// ---- action reports (plan §7-M6.5) ----

type ReportRow struct {
	ID       string `json:"id"`
	Project  string `json:"project"`
	Title    string `json:"title"`
	Markdown string `json:"markdown"`
	Model    string `json:"model"`
	Created  int64  `json:"created"`
}

func (s *Store) ReportInsert(r *ReportRow) error {
	_, err := s.DB.Exec(`INSERT INTO reports(id,project,title,markdown,model,created) VALUES(?,?,?,?,?,?)`,
		r.ID, r.Project, r.Title, r.Markdown, r.Model, r.Created)
	return err
}

func (s *Store) ReportList(project string) ([]ReportRow, error) {
	q := `SELECT id,project,title,model,created,length(markdown) FROM reports`
	args := []any{}
	if project != "" {
		q += ` WHERE project=?`
		args = append(args, project)
	}
	q += ` ORDER BY created DESC LIMIT 50`
	rows, err := s.DB.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReportRow
	for rows.Next() {
		var r ReportRow
		var size int
		if err := rows.Scan(&r.ID, &r.Project, &r.Title, &r.Model, &r.Created, &size); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) ReportGet(id string) (*ReportRow, error) {
	var r ReportRow
	err := s.DB.QueryRow(`SELECT id,project,title,markdown,model,created FROM reports WHERE id=?`, id).
		Scan(&r.ID, &r.Project, &r.Title, &r.Markdown, &r.Model, &r.Created)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Store) ReportDelete(id string) error {
	_, err := s.DB.Exec(`DELETE FROM reports WHERE id=?`, id)
	return err
}

// ---- attack orchestration (plan §7-M6.5) ----

type GoalRow struct {
	ID      string `json:"id"`
	Project string `json:"project"`
	Title   string `json:"title"`
	Status  string `json:"status"` // draft|running|paused|awaiting|done|failed
	Created int64  `json:"created"`
}

type StepRow struct {
	ID     string `json:"id"`
	Goal   string `json:"goal"`
	Seq    int    `json:"seq"`
	Name   string `json:"name"`
	Kind   string `json:"kind"` // task|plugin|gate|wait|note
	Args   string `json:"args"`
	Status string `json:"status"` // pending|running|awaiting|done|failed|skipped
	Result string `json:"result"`
}

func (s *Store) GoalInsert(g *GoalRow) error {
	_, err := s.DB.Exec(`INSERT INTO goals(id,project,title,status,created,updated) VALUES(?,?,?,?,?,?)`,
		g.ID, g.Project, g.Title, g.Status, g.Created, g.Created)
	return err
}

func (s *Store) GoalStatus(id, status string) error {
	_, err := s.DB.Exec(`UPDATE goals SET status=?, updated=? WHERE id=?`, status, time.Now().Unix(), id)
	return err
}

func (s *Store) GoalDelete(id string) error {
	if _, err := s.DB.Exec(`DELETE FROM goal_steps WHERE goal=?`, id); err != nil {
		return err
	}
	_, err := s.DB.Exec(`DELETE FROM goals WHERE id=?`, id)
	return err
}

func (s *Store) GoalList(project string) ([]GoalRow, error) {
	q := `SELECT id,project,title,status,created FROM goals`
	args := []any{}
	if project != "" {
		q += ` WHERE project=?`
		args = append(args, project)
	}
	q += ` ORDER BY updated DESC LIMIT 50`
	rows, err := s.DB.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GoalRow
	for rows.Next() {
		var g GoalRow
		if err := rows.Scan(&g.ID, &g.Project, &g.Title, &g.Status, &g.Created); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *Store) GoalGet(id string) (*GoalRow, error) {
	var g GoalRow
	err := s.DB.QueryRow(`SELECT id,project,title,status,created FROM goals WHERE id=?`, id).
		Scan(&g.ID, &g.Project, &g.Title, &g.Status, &g.Created)
	if err != nil {
		return nil, err
	}
	return &g, nil
}

func (s *Store) StepInsert(st *StepRow) error {
	_, err := s.DB.Exec(`INSERT INTO goal_steps(id,goal,seq,name,kind,args,status,updated) VALUES(?,?,?,?,?,?,?,?)`,
		st.ID, st.Goal, st.Seq, st.Name, st.Kind, st.Args, st.Status, time.Now().Unix())
	return err
}

func (s *Store) StepUpdate(id, status, result string) error {
	_, err := s.DB.Exec(`UPDATE goal_steps SET status=?, result=?, updated=? WHERE id=?`, status, result, time.Now().Unix(), id)
	return err
}

// StepPatch edits a step's name and/or args (only meaningful pre-run).
func (s *Store) StepPatch(id, name, args string) error {
	if name != "" {
		if _, err := s.DB.Exec(`UPDATE goal_steps SET name=? WHERE id=?`, name, id); err != nil {
			return err
		}
	}
	if args != "" {
		_, err := s.DB.Exec(`UPDATE goal_steps SET args=? WHERE id=?`, args, id)
		return err
	}
	return nil
}

func (s *Store) StepMove(id string, seq int) error {
	_, err := s.DB.Exec(`UPDATE goal_steps SET seq=? WHERE id=?`, seq, id)
	return err
}

func (s *Store) StepDelete(id string) error {
	_, err := s.DB.Exec(`DELETE FROM goal_steps WHERE id=?`, id)
	return err
}

func (s *Store) Steps(goal string) ([]StepRow, error) {
	rows, err := s.DB.Query(`SELECT id,goal,seq,name,kind,args,status,COALESCE(result,'') FROM goal_steps WHERE goal=? ORDER BY seq`, goal)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StepRow
	for rows.Next() {
		var st StepRow
		if err := rows.Scan(&st.ID, &st.Goal, &st.Seq, &st.Name, &st.Kind, &st.Args, &st.Status, &st.Result); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

func (s *Store) StepGet(id string) (*StepRow, error) {
	var st StepRow
	err := s.DB.QueryRow(`SELECT id,goal,seq,name,kind,args,status,COALESCE(result,'') FROM goal_steps WHERE id=?`, id).
		Scan(&st.ID, &st.Goal, &st.Seq, &st.Name, &st.Kind, &st.Args, &st.Status, &st.Result)
	if err != nil {
		return nil, err
	}
	return &st, nil
}

// ---- port forwards (plan §2.3) ----

type FwdRow struct {
	ID, Session, Listen, Target, Status string
	Created                             int64
}

func (s *Store) FwdInsert(id, session, listen, target string) error {
	_, err := s.DB.Exec(`INSERT INTO forwards(id,session,listen,target,status,created) VALUES(?,?,?,?,?,?)`,
		id, session, listen, target, "active", time.Now().Unix())
	return err
}

func (s *Store) FwdStatus(id, status string) error {
	_, err := s.DB.Exec(`UPDATE forwards SET status=? WHERE id=?`, status, id)
	return err
}

func (s *Store) FwdList() ([]FwdRow, error) {
	rows, err := s.DB.Query(`SELECT id,session,listen,target,status,created FROM forwards ORDER BY created DESC LIMIT 50`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FwdRow
	for rows.Next() {
		var f FwdRow
		if err := rows.Scan(&f.ID, &f.Session, &f.Listen, &f.Target, &f.Status, &f.Created); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// ---- generic settings k/v (file server config etc.) ----

func (s *Store) SettingGet(key string) (string, bool) {
	var v string
	err := s.DB.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	return v, err == nil
}

func (s *Store) SettingSet(key, value string) error {
	_, err := s.DB.Exec(`INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

// ---- session operator metadata (tags / notes / color) ----

type MetaRow struct {
	Session string   `json:"session"`
	Tags    []string `json:"tags"`
	Notes   string   `json:"notes"`
	Color   string   `json:"color"`
	Updated int64    `json:"updated"`
}

func (s *Store) MetaSet(m *MetaRow) error {
	tags, _ := json.Marshal(m.Tags)
	if m.Color == "" {
		// keep existing color when caller only edits tags/notes
		if old, err := s.MetaGet(m.Session); err == nil {
			m.Color = old.Color
		}
	}
	_, err := s.DB.Exec(`INSERT INTO session_meta(session,tags,notes,color,updated) VALUES(?,?,?,?,?)
		ON CONFLICT(session) DO UPDATE SET tags=excluded.tags, notes=excluded.notes, color=excluded.color, updated=excluded.updated`,
		m.Session, string(tags), m.Notes, m.Color, time.Now().Unix())
	return err
}

func (s *Store) MetaGet(id string) (*MetaRow, error) {
	row := s.DB.QueryRow(`SELECT tags,notes,color,updated FROM session_meta WHERE session=?`, id)
	var tagsStr, notes, color string
	var up int64
	if err := row.Scan(&tagsStr, &notes, &color, &up); err != nil {
		return nil, err
	}
	m := &MetaRow{Session: id, Notes: notes, Color: color, Updated: up}
	_ = json.Unmarshal([]byte(tagsStr), &m.Tags)
	return m, nil
}

func (s *Store) MetaAll() (map[string]*MetaRow, error) {
	rows, err := s.DB.Query(`SELECT session,tags,notes,color,updated FROM session_meta`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]*MetaRow{}
	for rows.Next() {
		var id, tagsStr, notes, color string
		var up int64
		if err := rows.Scan(&id, &tagsStr, &notes, &color, &up); err != nil {
			continue
		}
		m := &MetaRow{Session: id, Notes: notes, Color: color, Updated: up}
		_ = json.Unmarshal([]byte(tagsStr), &m.Tags)
		out[id] = m
	}
	return out, nil
}
