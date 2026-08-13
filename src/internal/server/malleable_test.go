package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/user/wisp/internal/db"
)

// TestMalleableProfileEndpoints verifies the HTTP listener registers custom
// URIs and applies profile response headers when a Malleable profile is set.
func TestMalleableProfileEndpoints(t *testing.T) {
	database, err := db.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	// Build the mux the way the HTTP listener does with a profile.
	prof := db.ListenerProfile{
		CheckinURI:  "/wp-admin/admin-ajax.php",
		StagePrefix: "/wp-content/uploads/",
		ResponseHeaders: map[string]string{
			"Server":       "nginx/1.18.0",
			"X-Powered-By": "PHP/7.4.33",
		},
		UserAgents: []string{"UA-wp", "UA-mobile"},
	}
	profJSON, _ := json.Marshal(prof)

	ln, err := database.CreateListener("wp", "http", "127.0.0.1", 8805, false, "", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SetListenerProfile(ln.ID, string(profJSON)); err != nil {
		t.Fatal(err)
	}
	got, err := database.GetListener(ln.ID)
	if err != nil {
		t.Fatal(err)
	}
	mp := got.MalleableProfile()
	if mp.CheckinURI != "/wp-admin/admin-ajax.php" {
		t.Fatalf("checkin uri = %q", mp.CheckinURI)
	}

	// Register URIs: /wp-admin/admin-ajax.php → checkin handler, custom stage prefix.
	mux := http.NewServeMux()
	wrap := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			for k, v := range mp.ResponseHeaders {
				w.Header().Set(k, v)
			}
			h(w, r)
		}
	}
	mux.HandleFunc("/wp-admin/admin-ajax.php", wrap(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"tasks":""}`))
	}))
	mux.HandleFunc("/wp-content/uploads/", wrap(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("raw-stage"))
	}))

	// Checkin on the custom URI gets profile headers.
	req := httptest.NewRequest("POST", "/wp-admin/admin-ajax.php", strings.NewReader(`{"id":"a","seq":1}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Header().Get("Server") != "nginx/1.18.0" {
		t.Fatalf("Server header = %q", rec.Header().Get("Server"))
	}
	if rec.Header().Get("X-Powered-By") != "PHP/7.4.33" {
		t.Fatalf("X-Powered-By = %q", rec.Header().Get("X-Powered-By"))
	}

	// Stage download on the custom prefix.
	req2 := httptest.NewRequest("GET", "/wp-content/uploads/abcd1234?raw=1", nil)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)
	if rec2.Body.String() != "raw-stage" {
		t.Fatalf("stage body = %q", rec2.Body.String())
	}
}
