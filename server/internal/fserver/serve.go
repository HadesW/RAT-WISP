package fserver

import (
	"crypto/subtle"
	"fmt"
	"html"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"wispp/server/internal/db"
)

func (s *Svc) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/p/", s.serveDelivery)
	mux.HandleFunc("/s/", s.serveShare)
	mux.HandleFunc("/", s.fake404)
	return mux
}

func (s *Svc) modeAllows(mode string) bool {
	m := s.Config().Mode
	return m == ModeBoth || m == mode
}

func (s *Svc) serveDelivery(w http.ResponseWriter, r *http.Request) {
	if !s.modeAllows(ModeDelivery) {
		s.fake404(w, r)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/p/")
	if rest == "" || s.Store == nil {
		s.fake404(w, r)
		return
	}
	token, _, _ := strings.Cut(rest, "/")
	d, err := s.Store.DeliveryByTokenHash(db.TokenHash(token))
	if err != nil || d == nil || !tokenEqual(d.Token, token) {
		s.fake404(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodPost {
		s.fake404(w, r)
		return
	}
	if st, err := os.Stat(d.File); err != nil || !st.Mode().IsRegular() {
		s.fake404(w, r)
		return
	}
	download := r.Method != http.MethodHead
	ok, err := s.Store.DeliveryClaim(d.ID, time.Now().Unix(), download)
	if err != nil || !ok {
		s.fake404(w, r)
		return
	}
	ct := d.ContentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	if r.Method == http.MethodPost {
		s.sendFilePost(w, d.File, d.Name, ct, func(n int64) { s.Store.DeliveryAddBytes(d.ID, n) })
		return
	}
	s.sendFile(w, r, d.File, d.Name, ct, func(n int64) { s.Store.DeliveryAddBytes(d.ID, n) })
}

func (s *Svc) serveShare(w http.ResponseWriter, r *http.Request) {
	if !s.modeAllows(ModeShare) {
		s.fake404(w, r)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/s/")
	if rest == "" || s.Store == nil {
		s.fake404(w, r)
		return
	}
	token, _, hasSub := strings.Cut(rest, "/")
	sh, err := s.Store.ShareByTokenHash(db.TokenHash(token))
	if err != nil || sh == nil || !tokenEqual(sh.Token, token) {
		s.fake404(w, r)
		return
	}
	now := time.Now().Unix()
	if sh.Revoked || (sh.ExpiresAt > 0 && now > sh.ExpiresAt) ||
		(sh.MaxDownloads > 0 && sh.Downloads >= int64(sh.MaxDownloads)) {
		s.fake404(w, r)
		return
	}

	password := r.URL.Query().Get("password")
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			s.fake404(w, r)
			return
		}
		password = r.FormValue("password")
	}
	if sh.PasswordHash != "" {
		if password == "" || bcrypt.CompareHashAndPassword([]byte(sh.PasswordHash), []byte(password)) != nil {
			if hasSub {
				s.fake404(w, r)
				return
			}
			s.passwordPage(w, r, token, password != "")
			return
		}
	}

	if hasSub {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			s.fake404(w, r)
			return
		}
		s.serveShareFile(w, r, sh)
		return
	}
	if r.Method == http.MethodPost {
		// Password form success (or passwordless POST): download directly.
		s.serveShareFile(w, r, sh)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		s.fake404(w, r)
		return
	}
	if s.Config().NoLanding {
		s.fake404(w, r)
		return
	}
	s.landingPage(w, r, sh)
}

func (s *Svc) serveShareFile(w http.ResponseWriter, r *http.Request, sh *db.Share) {
	abs, _, err := s.resolveShareFile(sh.File)
	if err != nil {
		s.fake404(w, r)
		return
	}
	download := r.Method != http.MethodHead
	ok, err := s.Store.ShareClaim(sh.ID, time.Now().Unix(), download)
	if err != nil || !ok {
		s.fake404(w, r)
		return
	}
	ct := mime.TypeByExtension(filepath.Ext(sh.Name))
	if ct == "" {
		ct = "application/octet-stream"
	}
	addBytes := func(n int64) { s.Store.ShareAddBytes(sh.ID, n) }
	if r.Method == http.MethodPost {
		s.sendFilePost(w, abs, sh.Name, ct, addBytes)
		return
	}
	s.sendFile(w, r, abs, sh.Name, ct, addBytes)
}

func (s *Svc) sendFile(w http.ResponseWriter, r *http.Request, file, name, ct string, addBytes func(int64)) {
	f, err := os.Open(file)
	if err != nil {
		s.fake404(w, r)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		s.fake404(w, r)
		return
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	cw := &countWriter{ResponseWriter: w}
	http.ServeContent(cw, r, "", st.ModTime(), f)
	if addBytes != nil && cw.n > 0 {
		addBytes(cw.n)
	}
}

func (s *Svc) sendFilePost(w http.ResponseWriter, file, name, ct string, addBytes func(int64)) {
	f, err := os.Open(file)
	if err != nil {
		s.fake404(w, nil)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		s.fake404(w, nil)
		return
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	w.Header().Set("Content-Length", strconv.FormatInt(st.Size(), 10))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	n, _ := io.Copy(w, f)
	if addBytes != nil && n > 0 {
		addBytes(n)
	}
}

func (s *Svc) landingPage(w http.ResponseWriter, r *http.Request, sh *db.Share) {
	name := html.EscapeString(sh.Name)
	remaining := "unlimited"
	if sh.MaxDownloads > 0 {
		remaining = strconv.FormatInt(int64(sh.MaxDownloads)-sh.Downloads, 10)
	}
	expiry := "no expiry"
	if sh.ExpiresAt > 0 {
		expiry = time.Unix(sh.ExpiresAt, 0).Format(time.RFC3339)
	}
	var size int64
	if abs, _, err := s.resolveShareFile(sh.File); err == nil {
		if st, err := os.Stat(abs); err == nil {
			size = st.Size()
		}
	}
	dl := fmt.Sprintf("/s/%s/%s", url.PathEscape(sh.Token), url.PathEscape(sh.Name))
	form := ""
	if sh.PasswordHash != "" {
		form = `<form method="post" action="` + html.EscapeString("/s/"+sh.Token) + `">
      <input name="password" type="password" placeholder="Password" autofocus>
      <button type="submit">Download</button></form>`
	}
	page := `<!doctype html><html><head><meta charset="utf-8">
<title>` + name + `</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:system-ui,sans-serif;background:#0f1115;color:#e6e6e6;display:flex;min-height:100vh;margin:0;align-items:center;justify-content:center}
.card{background:#171a21;border:1px solid #2a2f3a;border-radius:10px;padding:28px 32px;min-width:320px}
h1{font-size:18px;margin:0 0 10px;word-break:break-all}small{color:#8b93a1}
a{display:block;margin-top:16px;background:#2f81f7;color:#fff;text-align:center;padding:10px;border-radius:6px;text-decoration:none}
input,button{width:100%;box-sizing:border-box;margin-top:12px;padding:9px;border-radius:6px;border:1px solid #2a2f3a;background:#0f1115;color:#e6e6e6}
button{background:#2f81f7;border:0;cursor:pointer}</style></head>
<body><div class="card"><h1>` + name + `</h1>
<small>` + humanSize(size) + ` · expires ` + html.EscapeString(expiry) + ` · downloads left ` + remaining + `</small>` +
		func() string {
			if sh.PasswordHash != "" {
				return form
			}
			return `<a href="` + html.EscapeString(dl) + `">Download</a>`
		}() + `</div></body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = io.WriteString(w, page)
}

func (s *Svc) passwordPage(w http.ResponseWriter, r *http.Request, token string, wrong bool) {
	msg := ""
	if wrong {
		msg = `<p style="color:#e5534b">Wrong password</p>`
	}
	page := `<!doctype html><html><head><meta charset="utf-8"><title>Protected file</title>
<style>body{font-family:system-ui,sans-serif;background:#0f1115;color:#e6e6e6;display:flex;min-height:100vh;margin:0;align-items:center;justify-content:center}
.card{background:#171a21;border:1px solid #2a2f3a;border-radius:10px;padding:28px 32px;min-width:300px}
input,button{width:100%;box-sizing:border-box;margin-top:12px;padding:9px;border-radius:6px;border:1px solid #2a2f3a;background:#0f1115;color:#e6e6e6}
button{background:#2f81f7;border:0;cursor:pointer}</style></head><body><div class="card">
<h1>Protected file</h1>` + msg + `<form method="post" action="` + html.EscapeString("/s/"+token) + `">
<input name="password" type="password" placeholder="Password" autofocus><button type="submit">Download</button></form>
</div></body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	if r.Method != http.MethodHead {
		_, _ = io.WriteString(w, page)
	}
}

func (s *Svc) fake404(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusNotFound)
	if r != nil && r.Method == http.MethodHead {
		return
	}
	_, _ = io.WriteString(w, `<!doctype html><html><head><title>404 Not Found</title></head>
<body><center><h1>404 Not Found</h1></center><hr><center>nginx</center></body></html>`)
}

func tokenEqual(stored, presented string) bool {
	return subtle.ConstantTimeCompare([]byte(stored), []byte(presented)) == 1
}

type countWriter struct {
	http.ResponseWriter
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.ResponseWriter.Write(p)
	c.n += int64(n)
	return n, err
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for n/div >= unit && exp < 3 {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}
