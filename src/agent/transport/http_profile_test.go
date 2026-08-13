package transport

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/user/wisp/agent/config"
	"github.com/user/wisp/shared/protocol"
)

// TestHTTPTransportTrafficProfile verifies the Malleable-profile lite behavior:
// the agent rotates User-Agent and alternates URI paths across requests.
func TestHTTPTransportTrafficProfile(t *testing.T) {
	var mu sync.Mutex
	var seenUAs []string
	var seenPaths []string
	keys, err := protocol.GenerateSessionKeys()
	if err != nil {
		t.Fatal(err)
	}
	emptyBatch, err := keys.Encrypt(nil)
	if err != nil {
		t.Fatal(err)
	}
	emptyB64 := base64.StdEncoding.EncodeToString(emptyBatch)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seenUAs = append(seenUAs, r.UserAgent())
		seenPaths = append(seenPaths, r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"tasks":"` + emptyB64 + `"}`))
	}))
	defer srv.Close()

	tp := NewHTTPTransport("127.0.0.1", 1, false, "agent1", "", "")
	tp.Keys = keys
	tp.SetTrafficProfile(&config.TrafficProfile{
		UserAgents: []string{"UA-A", "UA-B"},
		URIs:       []string{"/one", "/two", "/three"},
	})
	tp.base = srv.URL

	// Do several checkins; each must rotate UA and alternate path.
	for i := 0; i < 6; i++ {
		if _, err := tp.Checkin([]byte("result" + string(rune('0'+i)))); err != nil {
			t.Fatalf("checkin %d: %v", i, err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seenUAs) != 6 {
		t.Fatalf("checkins recorded = %d", len(seenUAs))
	}
	// UA must alternate A/B/A/B...
	for i, ua := range seenUAs {
		want := "UA-A"
		if i%2 == 1 {
			want = "UA-B"
		}
		if ua != want {
			t.Fatalf("checkin %d UA = %q, want %q", i, ua, want)
		}
	}
	// Paths must be a rotation of /one,/two,/three (each appears, not all fixed).
	pathSet := map[string]bool{}
	for _, p := range seenPaths {
		pathSet[p] = true
	}
	if len(pathSet) < 2 {
		t.Fatalf("paths not rotating: %v", seenPaths)
	}
	for p := range pathSet {
		if p != "/one" && p != "/two" && p != "/three" {
			t.Fatalf("unexpected path %q", p)
		}
	}
	t.Logf("UAs=%v paths=%v", seenUAs, seenPaths)
}
