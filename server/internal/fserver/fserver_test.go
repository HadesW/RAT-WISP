package fserver

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"wispp/server/internal/db"
)

func testSvc(t *testing.T) (*Svc, string, string) {
	t.Helper()
	data, root := t.TempDir(), t.TempDir()
	store, err := db.Open(filepath.Join(data, "f.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.DB.Close() })
	svc := New(store, nil, data)
	svc.cfg = normalizeConfig(Config{Enabled: true, Mode: ModeBoth, RootDir: root, Addr: "127.0.0.1:0"})
	return svc, root, data
}

func payloadFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent.bin")
	if err := os.WriteFile(path, []byte("payload-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func do(svc *Svc, method, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	svc.handler().ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func TestDeliveryGetHeadPost(t *testing.T) {
	svc, _, _ := testSvc(t)
	file := payloadFile(t)
	view, err := svc.CreateDelivery("p1", "", file, "default", 60, 0, "application/x-msdownload")
	if err != nil {
		t.Fatal(err)
	}
	path := "/p/" + view.Token + "/" + view.Name
	get := do(svc, http.MethodGet, path)
	if get.Code != http.StatusOK || get.Body.String() != "payload-bytes" {
		t.Fatalf("GET: %d %q", get.Code, get.Body.String())
	}
	if ct := get.Header().Get("Content-Type"); ct != "application/x-msdownload" {
		t.Fatalf("content type: %q", ct)
	}
	head := do(svc, http.MethodHead, path)
	if head.Code != http.StatusOK || head.Body.Len() != 0 {
		t.Fatalf("HEAD: %d len=%d", head.Code, head.Body.Len())
	}
	post := do(svc, http.MethodPost, path)
	if post.Code != http.StatusOK || post.Body.String() != "payload-bytes" {
		t.Fatalf("POST: %d %q", post.Code, post.Body.String())
	}
	list, _ := svc.Deliveries("")
	if len(list) != 1 || list[0].Downloads != 2 || list[0].Requests != 3 {
		t.Fatalf("stats: %+v", list)
	}
}

func TestDeliveryExpiryLimitRevoke(t *testing.T) {
	svc, _, _ := testSvc(t)
	file := payloadFile(t)
	view, _ := svc.CreateDelivery("p1", "", file, "default", 0, 1, "")
	path := "/p/" + view.Token
	if r := do(svc, http.MethodGet, path); r.Code != http.StatusOK {
		t.Fatalf("first: %d", r.Code)
	}
	if r := do(svc, http.MethodGet, path); r.Code != http.StatusNotFound {
		t.Fatalf("over limit: %d", r.Code)
	}

	view2, _ := svc.CreateDelivery("p2", "", file, "default", 0, 0, "")
	past := time.Now().Add(-time.Minute).Unix()
	if err := svc.PatchDelivery(view2.ID, &past, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if r := do(svc, http.MethodGet, "/p/"+view2.Token); r.Code != http.StatusNotFound {
		t.Fatalf("expired: %d", r.Code)
	}

	view3, _ := svc.CreateDelivery("p3", "", file, "default", 0, 0, "")
	yes := true
	_ = svc.PatchDelivery(view3.ID, nil, nil, nil, &yes)
	if r := do(svc, http.MethodGet, "/p/"+view3.Token); r.Code != http.StatusNotFound {
		t.Fatalf("revoked: %d", r.Code)
	}
	if r := do(svc, http.MethodGet, "/p/not-a-token"); r.Code != http.StatusNotFound {
		t.Fatalf("unknown: %d", r.Code)
	}
}

func TestShareLandingAndDownload(t *testing.T) {
	svc, root, _ := testSvc(t)
	if err := os.MkdirAll(filepath.Join(root, "docs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "docs", "report.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	view, err := svc.CreateShare("docs/report.txt", "", "default", 60, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	landing := do(svc, http.MethodGet, "/s/"+view.Token)
	if landing.Code != http.StatusOK || !strings.Contains(landing.Body.String(), "report.txt") {
		t.Fatalf("landing: %d %q", landing.Code, landing.Body.String())
	}
	dl := do(svc, http.MethodGet, "/s/"+view.Token+"/report.txt")
	if dl.Code != http.StatusOK || dl.Body.String() != "hello" {
		t.Fatalf("download: %d %q", dl.Code, dl.Body.String())
	}
	list, _ := svc.Shares("")
	if len(list) != 1 || list[0].Downloads != 1 {
		t.Fatalf("stats: %+v", list)
	}
	if r := do(svc, http.MethodGet, "/s/"+view.Token+"/../report.txt"); r.Code == http.StatusOK {
		t.Fatal("traversal path served")
	}
	if r := do(svc, http.MethodGet, "/"); r.Code != http.StatusNotFound {
		t.Fatalf("directory browse: %d", r.Code)
	}
}

func TestSharePasswordAndLimits(t *testing.T) {
	svc, root, _ := testSvc(t)
	if err := os.WriteFile(filepath.Join(root, "secret.txt"), []byte("s3cret"), 0o600); err != nil {
		t.Fatal(err)
	}
	view, err := svc.CreateShare("secret.txt", "", "default", 0, 0, "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	landing := do(svc, http.MethodGet, "/s/"+view.Token)
	if landing.Code != http.StatusUnauthorized || !strings.Contains(landing.Body.String(), "password") {
		t.Fatalf("password landing: %d", landing.Code)
	}
	direct := do(svc, http.MethodGet, "/s/"+view.Token+"/secret.txt")
	if direct.Code != http.StatusNotFound {
		t.Fatalf("direct without password: %d", direct.Code)
	}
	bad := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/s/"+view.Token, strings.NewReader("password=nope"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	svc.handler().ServeHTTP(bad, req)
	if bad.Code != http.StatusUnauthorized {
		t.Fatalf("bad password: %d", bad.Code)
	}
	ok := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/s/"+view.Token, strings.NewReader("password=hunter2"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	svc.handler().ServeHTTP(ok, req)
	if ok.Code != http.StatusOK || ok.Body.String() != "s3cret" {
		t.Fatalf("password download: %d %q", ok.Code, ok.Body.String())
	}
	if got := do(svc, http.MethodGet, "/s/"+view.Token+"/secret.txt?password=hunter2"); got.Code != http.StatusOK {
		t.Fatalf("query password: %d", got.Code)
	}

	outside := filepath.Join(t.TempDir(), "outside.txt")
	_ = os.WriteFile(outside, []byte("nope"), 0o600)
	if _, err := svc.CreateShare("../outside.txt", "", "default", 0, 0, ""); err == nil {
		t.Fatal("traversal registration accepted")
	}
}

func TestModeGatingAndTLS(t *testing.T) {
	svc, root, data := testSvc(t)
	view, _ := svc.CreateDelivery("p1", "", payloadFile(t), "default", 0, 0, "")
	if r := do(svc, http.MethodGet, "/p/"+view.Token); r.Code != http.StatusOK {
		t.Fatalf("delivery in both: %d", r.Code)
	}
	svc.cfg.Mode = ModeShare
	if r := do(svc, http.MethodGet, "/p/"+view.Token); r.Code != http.StatusNotFound {
		t.Fatalf("delivery outside mode: %d", r.Code)
	}
	svc.cfg.Mode = ModeBoth

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	data2 := data
	if err := svc.Apply(Config{Enabled: true, RootDir: root, Addr: "127.0.0.1:" + strconv.Itoa(port), UseTLS: true, Host: "127.0.0.1", Mode: ModeBoth}); err != nil {
		t.Fatal(err)
	}
	defer svc.stop()
	crt := filepath.Join(data2, "fserver.crt")
	raw, err := os.ReadFile(crt)
	if err != nil {
		t.Fatalf("cert not generated: %v", err)
	}
	block, _ := pem.Decode(raw)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || cert.Subject.CommonName != "wisp file server" {
		t.Fatalf("unexpected cert: %v", err)
	}
	client := &http.Client{Timeout: 3 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	var last error
	for i := 0; i < 20; i++ {
		resp, err := client.Get("https://127.0.0.1:" + strconv.Itoa(port) + "/p/" + view.Token)
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK || string(b) != "payload-bytes" {
				t.Fatalf("https GET: %d %q", resp.StatusCode, b)
			}
			return
		}
		last = err
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("https server did not answer: %v", last)
}
