package stage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestSvc(ttl time.Duration) *Service { return New(ttl) }

func getJSON(t *testing.T, ts *httptest.Server, url string) (*http.Response, []byte) {
	t.Helper()
	r, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return r, b
}

func openAES(token string, body []byte) []byte {
	var sr struct{ IV, CT string }
	if err := json.Unmarshal(body, &sr); err != nil {
		panic(err)
	}
	iv, _ := base64.StdEncoding.DecodeString(sr.IV)
	ct, _ := base64.StdEncoding.DecodeString(sr.CT)
	k := sha256.Sum256([]byte("sp-stage|" + token))
	b, _ := aes.NewCipher(k[:])
	g, _ := cipher.NewGCM(b)
	out, err := g.Open(nil, iv, ct, nil)
	if err != nil {
		panic(err)
	}
	return out
}

func TestIssueDeliverOneTime(t *testing.T) {
	svc := newTestSvc(time.Minute)
	ts := httptest.NewServer(svc)
	defer ts.Close()
	payload := []byte("stage2-bytes-1234")
	tok, err := svc.Issue(payload, "")
	if err != nil {
		t.Fatal(err)
	}
	r, b := getJSON(t, ts, ts.URL+"/stage/"+tok)
	if r.StatusCode != 200 {
		t.Fatalf("status %d", r.StatusCode)
	}
	if string(openAES(tok, b)) != string(payload) {
		t.Fatal("payload mismatch")
	}
	// one-time: second fetch must 404 like a random token
	r2, _ := getJSON(t, ts, ts.URL+"/stage/"+tok)
	if r2.StatusCode != http.StatusNotFound {
		t.Fatal("token replay allowed")
	}
	r3, _ := getJSON(t, ts, ts.URL+"/stage/deadbeef")
	if r3.StatusCode != http.StatusNotFound {
		t.Fatal("unknown token not 404")
	}
}

func TestTTLExpiry(t *testing.T) {
	svc := New(time.Second)
	tok, _ := svc.Issue([]byte("x"), "")
	time.Sleep(1100 * time.Millisecond)
	req := httptest.NewRequest("GET", "/stage/"+tok, nil)
	w := httptest.NewRecorder()
	svc.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatal("expired token served")
	}
}

func TestRawXORDeterministic(t *testing.T) {
	svc := New(time.Minute)
	tok, _ := svc.Issue([]byte("hello-c-stager"), "")
	req := httptest.NewRequest("GET", "/stage/"+tok+"?raw=1", nil)
	w := httptest.NewRecorder()
	svc.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	ciphered := w.Body.Bytes()
	plain := xor(ciphered, key(tok)) // same keystream: decrypt = decrypt
	if string(plain) != "hello-c-stager" {
		t.Fatalf("raw xor round trip: %q", plain)
	}
	if string(ciphered) == "hello-c-stager" {
		t.Fatal("raw stage not obfuscated")
	}
}

func TestBase64Render(t *testing.T) {
	svc := New(time.Minute)
	tok, _ := svc.Issue([]byte("base64-stage2"), "")
	req := httptest.NewRequest("GET", "/stage/"+tok+"?b64=1", nil)
	w := httptest.NewRecorder()
	svc.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	if got := w.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
		t.Fatalf("content type: %q", got)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(w.Body.String()))
	if err != nil || string(raw) != "base64-stage2" {
		t.Fatalf("b64 round trip: %q %v", raw, err)
	}
	if code := serveToken(svc, tok); code != http.StatusNotFound {
		t.Fatalf("b64 fetch did not consume the token: %d", code)
	}
}

func TestIPBinding(t *testing.T) {
	svc := New(time.Minute)
	tok, _ := svc.Issue([]byte("x"), "10.0.0.9")
	req := httptest.NewRequest("GET", "/stage/"+tok, nil)
	req.RemoteAddr = "127.0.0.1:1234"
	w := httptest.NewRecorder()
	svc.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatal("wrong IP accepted")
	}
}

var _ = strings.TrimSpace

func serveToken(svc *Service, token string) int {
	req := httptest.NewRequest("GET", "/stage/"+token, nil)
	w := httptest.NewRecorder()
	svc.ServeHTTP(w, req)
	return w.Code
}

func TestUsesRearmAndPersist(t *testing.T) {
	dir := t.TempDir()
	svc := New(time.Minute)
	if err := svc.Persist(dir); err != nil {
		t.Fatal(err)
	}
	tok, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.IssueEx(tok, []byte("bundle-bytes"), "", 0, 2); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if code := serveToken(svc, tok); code != http.StatusOK {
			t.Fatalf("fetch %d: %d", i+1, code)
		}
	}
	if code := serveToken(svc, tok); code != http.StatusNotFound {
		t.Fatalf("allowance exhausted but served: %d", code)
	}
	if st, ok := svc.Status(tok); !ok || st.Remaining != 0 || st.Total != 2 {
		t.Fatalf("status after consume: %+v ok=%v", st, ok)
	}

	if st, err := svc.Rearm(tok, 0, 3); err != nil || st.Remaining != 3 {
		t.Fatalf("rearm: %+v %v", st, err)
	}
	if code := serveToken(svc, tok); code != http.StatusOK {
		t.Fatalf("rearmed fetch: %d", code)
	}

	// Restart: allowance + bundle must survive.
	svc2 := New(time.Minute)
	if err := svc2.Persist(dir); err != nil {
		t.Fatal(err)
	}
	if st, ok := svc2.Status(tok); !ok || st.Remaining != 2 || st.Total != 3 {
		t.Fatalf("restored status: %+v ok=%v", st, ok)
	}
	if code := serveToken(svc2, tok); code != http.StatusOK {
		t.Fatalf("restored fetch: %d", code)
	}

	svc3 := New(time.Minute)
	if err := svc3.Persist(dir); err != nil {
		t.Fatal(err)
	}
	if st, _ := svc3.Status(tok); st.Remaining != 1 {
		t.Fatalf("remaining after restart: %+v", st)
	}
	svc3.Revoke(tok)
	if _, ok := svc3.Status(tok); ok {
		t.Fatal("revoked token still present")
	}
	svc4 := New(time.Minute)
	if err := svc4.Persist(dir); err != nil {
		t.Fatal(err)
	}
	if _, ok := svc4.Status(tok); ok {
		t.Fatal("revoked token restored from disk")
	}
}

func TestExpiredCanRearm(t *testing.T) {
	svc := New(20 * time.Millisecond)
	tok, _ := NewToken()
	if err := svc.IssueEx(tok, []byte("x"), "", 0, 1); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	if code := serveToken(svc, tok); code != http.StatusNotFound {
		t.Fatal("expired token served")
	}
	if _, err := svc.Rearm(tok, time.Minute, 1); err != nil {
		t.Fatal(err)
	}
	if code := serveToken(svc, tok); code != http.StatusOK {
		t.Fatal("rearmed token not served")
	}
}

func TestRejectsNonHexToken(t *testing.T) {
	svc := New(time.Minute)
	if err := svc.IssueEx("../escape", []byte("x"), "", 0, 1); err == nil {
		t.Fatal("path-like token accepted")
	}
}

func TestCustomStagePath(t *testing.T) {
	svc := New(time.Minute)
	if err := svc.SetPath("/assets/sync"); err != nil {
		t.Fatal(err)
	}
	tok, _ := NewToken()
	if err := svc.IssueEx(tok, []byte("x"), "", 0, 2); err != nil {
		t.Fatal(err)
	}
	old := httptest.NewRequest("GET", "/stage/"+tok, nil)
	ow := httptest.NewRecorder()
	svc.ServeHTTP(ow, old)
	if ow.Code != http.StatusNotFound {
		t.Fatal("default path still served after SetPath")
	}
	req := httptest.NewRequest("GET", "/assets/sync/"+tok, nil)
	w := httptest.NewRecorder()
	svc.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("custom path: %d", w.Code)
	}
	if err := svc.SetPath("/"); err == nil {
		t.Fatal("root path accepted")
	}
}

func TestActiveCount(t *testing.T) {
	s := New(time.Hour)
	tok, err := s.Issue([]byte("stage2"), "")
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Active(); got != 1 {
		t.Fatalf("active after issue: %d", got)
	}
	s.Revoke(tok)
	if got := s.Active(); got != 0 {
		t.Fatalf("active after revoke: %d", got)
	}
}
