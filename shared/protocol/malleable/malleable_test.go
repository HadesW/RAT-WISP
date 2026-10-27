package malleable

import (
	"strings"
	"testing"
)

// Test sample also used by the manual acceptance flow (import via API).
const sample = `
# WISP++ supported subset: one http block per import
set sleeptime "5000";
set jitter "25";

http-get {
    set uri "/api/v3/beacon/{uuid}";
    set uri "/api/v3/beacon/{n}";
    set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120";
    set useragent "curl/8.4.0";
    set host "beacon.corp.example";

    client {
        header "Accept" "application/json";
    }

    metadata {
        base64url;
        prepend "data=";
        header "Cookie";
    }

    output {
        base64url;
        prepend "OK";
        terminate "\n";
        print;
    }

    server {
        header "Content-Type" "text/html; charset=utf-8";
        output {
            base64url;
            print;
        }
    }
}
`

func TestCompileHttpGet(t *testing.T) {
	p, err := Compile("wap", sample)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "wap" || p.Method != "GET" {
		t.Fatalf("meta: %+v", p)
	}
	if len(p.URIs) != 2 || p.URIs[0] != "/api/v3/beacon/{uuid}" || p.URIs[1] != "/api/v3/beacon/{n}" {
		t.Fatalf("uris: %v", p.URIs)
	}
	if p.Host != "beacon.corp.example" || len(p.UAPool) != 2 {
		t.Fatalf("host/ua: %q %v", p.Host, p.UAPool)
	}
	if len(p.Headers) != 1 || p.Headers[0].Key != "Accept" || p.Headers[0].Value != "application/json" {
		t.Fatalf("headers: %+v", p.Headers)
	}
	if p.Data != "header:Cookie" {
		t.Fatalf("data: %q", p.Data)
	}
	if len(p.DataTransform) != 2 || p.DataTransform[0] != "base64url" || p.DataTransform[1] != "prepend:data=" {
		t.Fatalf("transforms: %v", p.DataTransform)
	}
	if !p.Response.UrlBase64 || !strings.HasPrefix(p.Response.Body, "OK{data}") {
		t.Fatalf("response: %+v", p.Response)
	}
	if p.Response.ContentType != "text/html; charset=utf-8" {
		t.Fatalf("content type: %q", p.Response.ContentType)
	}
	if p.SleepMS != 5000 || p.JitterPct != 25 {
		t.Fatalf("sleeptime/jitter: %d/%d", p.SleepMS, p.JitterPct)
	}

	// round-trip the request payload through the pipeline
	env := []byte(`{"v":2,"type":1}`)
	enc, err := p.EncodeData(env)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(enc), "data=") {
		t.Fatalf("encoded: %q", enc)
	}
	dec, err := p.DecodeData(enc)
	if err != nil {
		t.Fatal(err)
	}
	if string(dec) != string(env) {
		t.Fatalf("roundtrip: %q", dec)
	}
}

func TestCompileHttpPostBody(t *testing.T) {
	p, err := Compile("post", `
http-post {
    set uri "/submit.php";
    set verb POST;
    metadata { base64; print; }
    output { print; }
}
`)
	if err != nil {
		t.Fatal(err)
	}
	if p.Method != "POST" || p.Data != "body" || len(p.DataTransform) != 1 {
		t.Fatalf("post compile: %+v", p)
	}
	if p.Response.Body != "{data}" {
		t.Fatalf("raw response expected: %q", p.Response.Body)
	}
}

func TestCompileErrors(t *testing.T) {
	if _, err := Compile("x", `http-get { metadata { mask; print; } }`); err == nil || !strings.Contains(err.Error(), "mask") {
		t.Fatalf("mask: %v", err)
	}
	if _, err := Compile("x", `http-get { set uri "/a"; metadata { print; } }
	http-post { set uri "/b"; metadata { print; } }`); err == nil || !strings.Contains(err.Error(), "multiple http blocks") {
		t.Fatalf("multi block: %v", err)
	}
	if _, err := Compile("x", `set foo "bar";`); err == nil {
		t.Fatal("no http block accepted")
	}
}

func TestCompiledProfileAcceptsRoundTrip(t *testing.T) {
	p, err := Compile("wap", sample)
	if err != nil {
		t.Fatal(err)
	}
	ua := p.PickUA()
	env := []byte(`{"v":2,"type":1,"agent":"x"}`)
	req, err := p.ApplyAgentRequest("http://beacon.corp.example", ua, env)
	if err != nil {
		t.Fatal(err)
	}
	if req.Host != "beacon.corp.example" || req.Method != "GET" {
		t.Fatalf("request: host=%q method=%q", req.Host, req.Method)
	}
	if !p.Accepts(req) {
		t.Fatal("agent-shaped request rejected by profile")
	}
	got, err := p.Extract(req, 1<<20)
	if err != nil || string(got) != string(env) {
		t.Fatalf("extract: %q %v", got, err)
	}
	// Wrong host / UA / header are rejected.
	bad := req.Clone(req.Context())
	bad.Host = "evil.example"
	if p.Accepts(bad) {
		t.Fatal("bad host accepted")
	}
	bad = req.Clone(req.Context())
	bad.Header.Set("User-Agent", "wget/1.0")
	if p.Accepts(bad) {
		t.Fatal("bad ua accepted")
	}
	bad = req.Clone(req.Context())
	bad.Header.Del("Accept")
	if p.Accepts(bad) {
		t.Fatal("missing header accepted")
	}
}
