package db

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestStripJSONCRemovesComments(t *testing.T) {
	src := `{
  // line comment
  "register_uri": "/wp-login.php", /* block comment */
  /* multi
     line */
  "checkin_uri": "/api/v1/checkin",
  "ua": "Mozilla//not-a-comment" // trailing
}`
	out := stripJSONC([]byte(src))
	var m map[string]string
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("stripped JSON invalid: %v\n%s", err, string(out))
	}
	if m["register_uri"] != "/wp-login.php" {
		t.Fatalf("register_uri wrong: %q", m["register_uri"])
	}
	if m["checkin_uri"] != "/api/v1/checkin" {
		t.Fatalf("checkin_uri wrong: %q", m["checkin_uri"])
	}
	// The string containing "//" must survive.
	if m["ua"] != "Mozilla//not-a-comment" {
		t.Fatalf("string content mangled: %q", m["ua"])
	}
}

func TestStripJSONCPreservesEscapedQuotes(t *testing.T) {
	src := `{
  "note": "contains \"quoted // not comment\"",
  "x": 1 // tail
}`
	out := stripJSONC([]byte(src))
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("stripped JSON invalid: %v", err)
	}
	if m["note"] != `contains "quoted // not comment"` {
		t.Fatalf("escaped quote handling wrong: %q", m["note"])
	}
}

func TestMalleableProfileAcceptsJSONC(t *testing.T) {
	row := &ListenerRow{Profile: `{
  // WordPress imitated service
  "register_uri": "/wp-login.php", /* stage via wp uploads */
  "checkin_uri":  "/wp-admin/admin-ajax.php",
  "stage_prefix": "/wp-content/uploads/",
  "user_agents": ["Mozilla//UA"]
}`}
	p := row.MalleableProfile()
	if p.RegisterURI != "/wp-login.php" {
		t.Fatalf("register_uri wrong: %q", p.RegisterURI)
	}
	if p.StagePrefix != "/wp-content/uploads/" {
		t.Fatalf("stage_prefix wrong: %q", p.StagePrefix)
	}
	if len(p.UserAgents) != 1 || p.UserAgents[0] != "Mozilla//UA" {
		t.Fatalf("user_agents wrong: %v", p.UserAgents)
	}
}

func TestMalleableProfilePlainJSONStillWorks(t *testing.T) {
	row := &ListenerRow{Profile: `{"checkin_uri":"/ping"}`}
	p := row.MalleableProfile()
	if p.CheckinURI != "/ping" {
		t.Fatalf("plain JSON broke: %q", p.CheckinURI)
	}
}

func TestMalleableProfileEmpty(t *testing.T) {
	row := &ListenerRow{Profile: ""}
	p := row.MalleableProfile()
	if p.CheckinURI != "" || p.StagePrefix != "" {
		t.Fatalf("empty profile should be zero-valued: %+v", p)
	}
}

func TestStripJSONCNoopOnPlain(t *testing.T) {
	src := strings.Repeat(`{"a":"b"}`, 1)
	out := string(stripJSONC([]byte(src)))
	if out != src {
		t.Fatalf("plain JSON changed: %s", out)
	}
}
