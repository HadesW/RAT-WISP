package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestServeSPA(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>console</html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "assets"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "assets", "app-abc.js"), []byte("console.log(1)"), 0o600); err != nil {
		t.Fatal(err)
	}
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	h := serveSPA(api, dir)

	cases := []struct {
		name  string
		path  string
		code  int
		cache string
		body  string
	}{
		{"root", "/", http.StatusOK, "no-cache", "<html>console</html>"},
		{"client route", "/sessions/42", http.StatusOK, "no-cache", "<html>console</html>"},
		{"asset", "/assets/app-abc.js", http.StatusOK, "public, max-age=31536000, immutable", "console.log(1)"},
		{"missing asset", "/assets/app-old.js", http.StatusNotFound, "", "404 page not found"},
		{"missing file", "/favicon.ico", http.StatusNotFound, "", ""},
		{"api", "/api/status", http.StatusNoContent, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if rec.Code != tc.code {
				t.Fatalf("code = %d, want %d", rec.Code, tc.code)
			}
			if got := rec.Header().Get("Cache-Control"); got != tc.cache {
				t.Errorf("Cache-Control = %q, want %q", got, tc.cache)
			}
			if tc.body != "" && !strings.Contains(rec.Body.String(), tc.body) {
				t.Errorf("body = %q, want substring %q", rec.Body.String(), tc.body)
			}
		})
	}
}
