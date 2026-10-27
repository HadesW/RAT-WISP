package db

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
)

// TokenHash is the lookup key for delivery/share URLs (raw tokens are stored
// only for operator copy, never used in WHERE clauses).
func TokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Delivery is one tokenized payload download link. Token is kept for operator
// copy; lookups use TokenHash so URLs never appear in SQL query logs.
type Delivery struct {
	ID           string `json:"id"`
	Token        string `json:"token"`
	Payload      string `json:"payload"`
	Name         string `json:"name"`
	File         string `json:"-"`
	Project      string `json:"project"`
	ContentType  string `json:"content_type,omitempty"`
	ExpiresAt    int64  `json:"expires_at,omitempty"`
	MaxDownloads int    `json:"max_downloads,omitempty"`
	Downloads    int64  `json:"downloads"`
	Requests     int64  `json:"requests"`
	BytesOut     int64  `json:"bytes_out"`
	Revoked      bool   `json:"revoked"`
	Created      int64  `json:"created"`
	LastSeen     int64  `json:"last_seen,omitempty"`
}

// Share is one registered file under the share root.
type Share struct {
	ID           string `json:"id"`
	Token        string `json:"token"`
	Name         string `json:"name"`
	File         string `json:"file"` // path relative to root_dir
	Project      string `json:"project"`
	PasswordHash string `json:"-"`
	HasPassword  bool   `json:"has_password"`
	ExpiresAt    int64  `json:"expires_at,omitempty"`
	MaxDownloads int    `json:"max_downloads,omitempty"`
	Downloads    int64  `json:"downloads"`
	Requests     int64  `json:"requests"`
	BytesOut     int64  `json:"bytes_out"`
	Revoked      bool   `json:"revoked"`
	Created      int64  `json:"created"`
	LastSeen     int64  `json:"last_seen,omitempty"`
}

func (s *Store) DeliveryCreate(d Delivery) error {
	_, err := s.DB.Exec(`INSERT INTO deliveries
		(id,token,token_hash,payload,name,file,project,content_type,expires_at,max_downloads,
		 downloads,requests,bytes_out,revoked,created,last_seen)
		VALUES(?,?,?,?,?,?,?,?,?,?,0,0,0,0,?,0)`,
		d.ID, d.Token, TokenHash(d.Token), d.Payload, d.Name, d.File, d.Project,
		nullText(d.ContentType), d.ExpiresAt, d.MaxDownloads, d.Created)
	return err
}

func (s *Store) Deliveries(project string) ([]Delivery, error) {
	q := `SELECT id,token,payload,name,file,project,COALESCE(content_type,''),
		expires_at,max_downloads,downloads,requests,bytes_out,revoked,created,last_seen
		FROM deliveries`
	args := []any{}
	if project != "" {
		q += ` WHERE project=?`
		args = append(args, project)
	}
	q += ` ORDER BY created DESC`
	rows, err := s.DB.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Delivery{}
	for rows.Next() {
		var d Delivery
		var revoked int
		if err := rows.Scan(&d.ID, &d.Token, &d.Payload, &d.Name, &d.File, &d.Project,
			&d.ContentType, &d.ExpiresAt, &d.MaxDownloads, &d.Downloads, &d.Requests,
			&d.BytesOut, &revoked, &d.Created, &d.LastSeen); err != nil {
			return nil, err
		}
		d.Revoked = revoked != 0
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) DeliveryByTokenHash(hash string) (*Delivery, error) {
	var d Delivery
	var revoked int
	err := s.DB.QueryRow(`SELECT id,token,payload,name,file,project,COALESCE(content_type,''),
		expires_at,max_downloads,downloads,requests,bytes_out,revoked,created,last_seen
		FROM deliveries WHERE token_hash=?`, hash).Scan(
		&d.ID, &d.Token, &d.Payload, &d.Name, &d.File, &d.Project, &d.ContentType,
		&d.ExpiresAt, &d.MaxDownloads, &d.Downloads, &d.Requests, &d.BytesOut,
		&revoked, &d.Created, &d.LastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	d.Revoked = revoked != 0
	return &d, nil
}

// DeliveryClaim atomically checks expiry/revocation/download allowance and
// records the request. download=false is used for HEAD.
func (s *Store) DeliveryClaim(id string, now int64, download bool) (bool, error) {
	q := `UPDATE deliveries SET requests=requests+1, last_seen=?
		WHERE id=? AND revoked=0 AND (expires_at=0 OR expires_at>?)`
	if download {
		q = `UPDATE deliveries SET requests=requests+1, downloads=downloads+1, last_seen=?
			WHERE id=? AND revoked=0 AND (expires_at=0 OR expires_at>?)
			AND (max_downloads=0 OR downloads<max_downloads)`
	}
	res, err := s.DB.Exec(q, now, id, now)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

func (s *Store) DeliveryAddBytes(id string, n int64) {
	_, _ = s.DB.Exec(`UPDATE deliveries SET bytes_out=bytes_out+? WHERE id=?`, n, id)
}

func (s *Store) DeliveryPatch(id string, expiresAt *int64, maxDownloads *int, contentType *string, revoked *bool) error {
	set := []string{}
	args := []any{}
	if expiresAt != nil {
		set = append(set, "expires_at=?")
		args = append(args, *expiresAt)
	}
	if maxDownloads != nil {
		set = append(set, "max_downloads=?")
		args = append(args, *maxDownloads)
	}
	if contentType != nil {
		set = append(set, "content_type=?")
		args = append(args, nullText(*contentType))
	}
	if revoked != nil {
		set = append(set, "revoked=?")
		v := 0
		if *revoked {
			v = 1
		}
		args = append(args, v)
	}
	if len(set) == 0 {
		return nil
	}
	args = append(args, id)
	_, err := s.DB.Exec(`UPDATE deliveries SET `+strings.Join(set, ",")+` WHERE id=?`, args...)
	return err
}

func (s *Store) DeliveryDelete(id string) error {
	_, err := s.DB.Exec(`DELETE FROM deliveries WHERE id=?`, id)
	return err
}

func (s *Store) ShareCreate(sh Share) error {
	_, err := s.DB.Exec(`INSERT INTO shares
		(id,token,token_hash,name,file,project,password_hash,expires_at,max_downloads,
		 downloads,requests,bytes_out,revoked,created,last_seen)
		VALUES(?,?,?,?,?,?,?,?,?,0,0,0,0,?,0)`,
		sh.ID, sh.Token, TokenHash(sh.Token), sh.Name, sh.File, sh.Project,
		nullText(sh.PasswordHash), sh.ExpiresAt, sh.MaxDownloads, sh.Created)
	return err
}

func (s *Store) Shares(project string) ([]Share, error) {
	q := `SELECT id,token,name,file,project,COALESCE(password_hash,''),
		expires_at,max_downloads,downloads,requests,bytes_out,revoked,created,last_seen
		FROM shares`
	args := []any{}
	if project != "" {
		q += ` WHERE project=?`
		args = append(args, project)
	}
	q += ` ORDER BY created DESC`
	rows, err := s.DB.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Share{}
	for rows.Next() {
		var sh Share
		var revoked int
		if err := rows.Scan(&sh.ID, &sh.Token, &sh.Name, &sh.File, &sh.Project,
			&sh.PasswordHash, &sh.ExpiresAt, &sh.MaxDownloads, &sh.Downloads,
			&sh.Requests, &sh.BytesOut, &revoked, &sh.Created, &sh.LastSeen); err != nil {
			return nil, err
		}
		sh.Revoked = revoked != 0
		sh.HasPassword = sh.PasswordHash != ""
		out = append(out, sh)
	}
	return out, rows.Err()
}

func (s *Store) ShareByTokenHash(hash string) (*Share, error) {
	var sh Share
	var revoked int
	err := s.DB.QueryRow(`SELECT id,token,name,file,project,COALESCE(password_hash,''),
		expires_at,max_downloads,downloads,requests,bytes_out,revoked,created,last_seen
		FROM shares WHERE token_hash=?`, hash).Scan(
		&sh.ID, &sh.Token, &sh.Name, &sh.File, &sh.Project, &sh.PasswordHash,
		&sh.ExpiresAt, &sh.MaxDownloads, &sh.Downloads, &sh.Requests, &sh.BytesOut,
		&revoked, &sh.Created, &sh.LastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	sh.Revoked = revoked != 0
	sh.HasPassword = sh.PasswordHash != ""
	return &sh, nil
}

func (s *Store) ShareClaim(id string, now int64, download bool) (bool, error) {
	q := `UPDATE shares SET requests=requests+1, last_seen=?
		WHERE id=? AND revoked=0 AND (expires_at=0 OR expires_at>?)`
	if download {
		q = `UPDATE shares SET requests=requests+1, downloads=downloads+1, last_seen=?
			WHERE id=? AND revoked=0 AND (expires_at=0 OR expires_at>?)
			AND (max_downloads=0 OR downloads<max_downloads)`
	}
	res, err := s.DB.Exec(q, now, id, now)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

func (s *Store) ShareAddBytes(id string, n int64) {
	_, _ = s.DB.Exec(`UPDATE shares SET bytes_out=bytes_out+? WHERE id=?`, n, id)
}

func (s *Store) SharePatch(id string, expiresAt *int64, maxDownloads *int, passwordHash *string, revoked *bool) error {
	set := []string{}
	args := []any{}
	if expiresAt != nil {
		set = append(set, "expires_at=?")
		args = append(args, *expiresAt)
	}
	if maxDownloads != nil {
		set = append(set, "max_downloads=?")
		args = append(args, *maxDownloads)
	}
	if passwordHash != nil {
		set = append(set, "password_hash=?")
		args = append(args, nullText(*passwordHash))
	}
	if revoked != nil {
		set = append(set, "revoked=?")
		v := 0
		if *revoked {
			v = 1
		}
		args = append(args, v)
	}
	if len(set) == 0 {
		return nil
	}
	args = append(args, id)
	_, err := s.DB.Exec(`UPDATE shares SET `+strings.Join(set, ",")+` WHERE id=?`, args...)
	return err
}

func (s *Store) ShareDelete(id string) error {
	_, err := s.DB.Exec(`DELETE FROM shares WHERE id=?`, id)
	return err
}

func nullText(s string) any {
	if s == "" {
		return nil
	}
	return s
}
