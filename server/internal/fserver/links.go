package fserver

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"wispp/server/internal/db"
)

// DeliveryView adds the public URL to a stored delivery link.
type DeliveryView struct {
	db.Delivery
	URL string `json:"url"`
}

// ShareView adds the public URL to a stored share.
type ShareView struct {
	db.Share
	URL string `json:"url"`
}

// RootFile is one operator-visible file under root_dir (never exposed by the
// HTTP service unless registered as a share).
type RootFile struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	ModTime string `json:"mod_time"`
}

func (s *Svc) CreateDelivery(payloadID, name, file, project string, ttlSeconds, maxDownloads int, contentType string) (DeliveryView, error) {
	if project == "" {
		project = "default"
	}
	st, err := os.Stat(file)
	if err != nil || !st.Mode().IsRegular() {
		return DeliveryView{}, errors.New("payload file missing or not a regular file")
	}
	name = safeName(name)
	if name == "download.bin" && strings.TrimSpace(filepath.Base(file)) != "" {
		name = safeName(filepath.Base(file))
	}
	ct := sanitizeContentType(contentType)
	token, err := newToken()
	if err != nil {
		return DeliveryView{}, err
	}
	d := db.Delivery{
		ID: newID(), Token: token, Payload: payloadID, Name: name, File: file,
		Project: project, ContentType: ct, ExpiresAt: expiresAt(ttlSeconds),
		MaxDownloads: max(0, maxDownloads), Created: time.Now().Unix(),
	}
	if err := s.Store.DeliveryCreate(d); err != nil {
		return DeliveryView{}, err
	}
	d.Token = token
	return DeliveryView{Delivery: d, URL: s.deliveryURL(token, name)}, nil
}

func (s *Svc) Deliveries(project string) ([]DeliveryView, error) {
	list, err := s.Store.Deliveries(project)
	if err != nil {
		return nil, err
	}
	out := make([]DeliveryView, 0, len(list))
	for _, d := range list {
		out = append(out, DeliveryView{Delivery: d, URL: s.deliveryURL(d.Token, d.Name)})
	}
	return out, nil
}

func (s *Svc) PatchDelivery(id string, expiresAt *int64, maxDownloads *int, contentType *string, revoked *bool) error {
	if contentType != nil {
		ct := sanitizeContentType(*contentType)
		contentType = &ct
	}
	return s.Store.DeliveryPatch(id, expiresAt, maxDownloads, contentType, revoked)
}

func (s *Svc) DeleteDelivery(id string) error { return s.Store.DeliveryDelete(id) }

func (s *Svc) CreateShare(rel, name, project string, ttlSeconds, maxDownloads int, password string) (ShareView, error) {
	if project == "" {
		project = "default"
	}
	_, clean, err := s.resolveShareFile(rel)
	if err != nil {
		return ShareView{}, err
	}
	name = safeName(name)
	if name == "download.bin" {
		name = safeName(filepath.Base(clean))
	}
	hash := ""
	if password != "" {
		b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return ShareView{}, err
		}
		hash = string(b)
	}
	token, err := newToken()
	if err != nil {
		return ShareView{}, err
	}
	sh := db.Share{
		ID: newID(), Token: token, Name: name, File: clean, Project: project,
		PasswordHash: hash, HasPassword: hash != "", ExpiresAt: expiresAt(ttlSeconds),
		MaxDownloads: max(0, maxDownloads), Created: time.Now().Unix(),
	}
	if err := s.Store.ShareCreate(sh); err != nil {
		return ShareView{}, err
	}
	return ShareView{Share: sh, URL: s.shareURL(token)}, nil
}

func (s *Svc) Shares(project string) ([]ShareView, error) {
	list, err := s.Store.Shares(project)
	if err != nil {
		return nil, err
	}
	out := make([]ShareView, 0, len(list))
	for _, sh := range list {
		out = append(out, ShareView{Share: sh, URL: s.shareURL(sh.Token)})
	}
	return out, nil
}

func (s *Svc) PatchShare(id string, expiresAt *int64, maxDownloads *int, password *string, revoked *bool) error {
	var hash *string
	if password != nil {
		h := ""
		if *password != "" {
			b, err := bcrypt.GenerateFromPassword([]byte(*password), bcrypt.DefaultCost)
			if err != nil {
				return err
			}
			h = string(b)
		}
		hash = &h
	}
	return s.Store.SharePatch(id, expiresAt, maxDownloads, hash, revoked)
}

func (s *Svc) DeleteShare(id string) error { return s.Store.ShareDelete(id) }

// RootFiles lists files operators may register as shares. It is API-only and
// never reachable through the public HTTP handler.
func (s *Svc) RootFiles() ([]RootFile, error) {
	root := s.Config().RootDir
	if root == "" {
		return nil, errors.New("share root not configured")
	}
	rootReal, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	out := []RootFile{}
	walkErr := filepath.WalkDir(rootReal, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if len(out) >= 5000 {
			return filepath.SkipAll
		}
		if d.Type()&os.ModeSymlink != 0 || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(rootReal, path)
		if err != nil {
			return nil
		}
		out = append(out, RootFile{
			Name: d.Name(), Path: filepath.ToSlash(rel), Size: info.Size(),
			ModTime: info.ModTime().Format(time.RFC3339),
		})
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// resolveShareFile canonicalizes a relative path and proves it stays under
// root_dir after symlink resolution.
func (s *Svc) resolveShareFile(rel string) (string, string, error) {
	root := s.Config().RootDir
	if root == "" {
		return "", "", errors.New("share root not configured")
	}
	if strings.ContainsRune(rel, 0) {
		return "", "", errors.New("bad path")
	}
	rel = filepath.Clean(filepath.FromSlash(strings.TrimSpace(rel)))
	if rel == "." || rel == "" || filepath.IsAbs(rel) || rel == ".." ||
		strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", "", errors.New("path escapes share root")
	}
	rootReal, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", "", err
	}
	target := filepath.Join(rootReal, rel)
	targetReal, err := filepath.EvalSymlinks(target)
	if err != nil {
		return "", "", err
	}
	if targetReal != rootReal && !strings.HasPrefix(targetReal, rootReal+string(os.PathSeparator)) {
		return "", "", errors.New("path escapes share root")
	}
	st, err := os.Stat(targetReal)
	if err != nil || !st.Mode().IsRegular() {
		return "", "", errors.New("not a regular file")
	}
	return targetReal, filepath.ToSlash(rel), nil
}

func (s *Svc) deliveryURL(token, name string) string {
	return strings.TrimRight(s.baseURL(), "/") + "/p/" + token + "/" + url.PathEscape(name)
}

func (s *Svc) shareURL(token string) string {
	return strings.TrimRight(s.baseURL(), "/") + "/s/" + token
}

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func newID() string {
	b := make([]byte, 5)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func safeName(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == '/' || r == '\\' {
			continue
		}
		b.WriteRune(r)
	}
	s = strings.TrimSpace(b.String())
	if s == "" || s == "." || s == ".." {
		return "download.bin"
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func sanitizeContentType(ct string) string {
	ct = strings.TrimSpace(ct)
	ct = strings.ReplaceAll(ct, "\r", "")
	ct = strings.ReplaceAll(ct, "\n", "")
	if ct == "" || len(ct) > 128 {
		return "application/octet-stream"
	}
	return ct
}

func expiresAt(ttlSeconds int) int64 {
	if ttlSeconds <= 0 {
		return 0
	}
	return time.Now().Add(time.Duration(ttlSeconds) * time.Second).Unix()
}
