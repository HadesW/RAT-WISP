package protocol

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProfileValidateDefaults(t *testing.T) {
	p := &Profile{Name: "x", URIs: []string{"/a/{uuid}"}}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if p.Method != "POST" || p.Data != DataBody {
		t.Fatalf("defaults not applied: %+v", p)
	}
	bad := &Profile{URIs: []string{"/a/{bogus}"}}
	if err := bad.Validate(); err == nil {
		t.Fatal("bogus placeholder accepted")
	}
}

func TestURIPlacementRoundTrip(t *testing.T) {
	p := &Profile{Name: "gh", URIs: []string{"/app/{n}/tokens"}, Data: "header:X-GitHub-Request-Id", Method: "POST"}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	payload := []byte("sealed-envelope-bytes")
	req, err := p.ApplyAgentRequest("http://x", "curl/1", payload)
	if err != nil {
		t.Fatal(err)
	}
	if !p.MatchPath(req.URL.Path) {
		t.Fatalf("own request path %q rejected by MatchPath", req.URL.Path)
	}
	srvReq := httptest.NewRequest(req.Method, req.URL.String(), req.Body)
	srvReq.Header = req.Header
	got, err := p.Extract(srvReq, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("header slot round-trip lost data")
	}
}

func TestParamAndBodySlots(t *testing.T) {
	for _, slot := range []string{"param:tid", "body"} {
		p := &Profile{URIs: []string{"/u"}, Data: slot}
		if err := p.Validate(); err != nil {
			t.Fatal(err)
		}
		req, _ := p.ApplyAgentRequest("http://x", "", []byte("zz"))
		srvReq := httptest.NewRequest(req.Method, req.URL.String(), req.Body)
		srvReq.Header = req.Header
		got, err := p.Extract(srvReq, 1<<20)
		if err != nil || string(got) != "zz" {
			t.Fatalf("slot %s: %v %q", slot, err, got)
		}
	}
}

func TestMatchPathRejectsMismatch(t *testing.T) {
	p := &Profile{URIs: []string{"/api/{uuid}/beat", "/d/{n}"}}
	_ = p.Validate()
	ok := []string{"/api/0123abcd5678/beat", "/d/42"}
	no := []string{"/api/nothex!!/beat", "/api//beat", "/d/4x", "/d", "/d/42/9", "/evil"}
	for _, s := range ok {
		if !p.MatchPath(s) {
			t.Fatalf("should match: %s", s)
		}
	}
	for _, s := range no {
		if p.MatchPath(s) {
			t.Fatalf("should NOT match: %s", s)
		}
	}
}

func TestResponseAndNotFoundTemplates(t *testing.T) {
	p := &Profile{
		URIs:     []string{"/u"},
		Response: ResponseProfile{Status: 201, ContentType: "application/json", Body: `{"id":"{uuid}","token":"{data}","t":{ts}}`},
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	env := &Envelope{V: ProtocolVersion, Type: MsgCheckin, Agent: "cafe"}
	env.Data = json.RawMessage(`"YWJj"`)
	p.WriteResponse(rec, env.Marshal())
	if rec.Code != 201 {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"id":"`) {
		t.Fatalf("template not expanded: %s", body)
	}
	if strings.Contains(body, "{uuid}") || strings.Contains(body, "{ts}") {
		t.Fatalf("unexpanded placeholders: %s", body)
	}
	back, err := p.ParseResponse([]byte(body))
	if err != nil || back.Type != MsgCheckin || back.Agent != "cafe" {
		t.Fatalf("ParseResponse lost the envelope: %v %+v", err, back)
	}
	rec2 := httptest.NewRecorder()
	(&Profile{}).Validate()
	def := &Profile{}
	def.Validate()
	def.WriteNotFound(rec2)
	if rec2.Code != 404 || !strings.Contains(rec2.Body.String(), "404") {
		t.Fatalf("default camo broken: %d %s", rec2.Code, rec2.Body.String())
	}
}

func TestBuiltinProfilesValid(t *testing.T) {
	for _, p := range BuiltinProfiles() {
		if err := p.Validate(); err != nil {
			t.Fatalf("%s: %v", p.Name, err)
		}
		u := p.PickURI()
		if !p.MatchPath(u) {
			t.Fatalf("%s: picked uri %q does not self-match", p.Name, u)
		}
	}
}

func TestPadEnvelope(t *testing.T) {
	p := &Profile{PadBlock: 256}
	env := []byte(`{"v":2,"type":1}`)
	out := p.PadEnvelope(env)
	if len(out)%256 != 0 || !bytes.HasPrefix(out, env) {
		t.Fatalf("pad: len=%d", len(out))
	}
	if _, err := ReadEnvelope(out); err != nil {
		t.Fatalf("padded envelope rejected: %v", err)
	}
	if !bytes.Equal((&Profile{}).PadEnvelope(env), env) {
		t.Fatal("pad_block=0 must be identity")
	}
	if err := (&Profile{PadBlock: 8}).Validate(); err == nil {
		t.Fatal("tiny pad_block accepted")
	}
}
