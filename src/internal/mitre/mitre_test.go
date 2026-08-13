package mitre

import (
	"strings"
	"testing"
)

func TestCatalog(t *testing.T) {
	r := BuildReport()
	if r.Techniques == 0 || r.Tactics == 0 {
		t.Fatalf("empty report: %d techniques %d tactics", r.Techniques, r.Tactics)
	}
	if len(r.SortedTactics()) != r.Tactics {
		t.Fatal("SortedTactics length mismatch")
	}
	// Every entry must have a non-empty technique, name, tactic.
	for _, e := range Catalog {
		if e.Technique == "" || e.Name == "" || e.Tactic == "" || e.Command == "" {
			t.Fatalf("incomplete entry: %+v", e)
		}
	}
}

func TestJSON(t *testing.T) {
	j, err := BuildReport().JSON()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(j, "T1059") {
		t.Fatal("JSON missing techniques")
	}
}

func TestNavigator(t *testing.T) {
	n, err := BuildReport().NavigatorLayer()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(n, "enterprise-attack") || !strings.Contains(n, "techniques") {
		t.Fatal("navigator layer malformed")
	}
}

func TestByCommand(t *testing.T) {
	if e, ok := ByCommand("shell"); !ok || e.Technique != "T1059" {
		t.Fatalf("shell mapping wrong: %+v", e)
	}
	if _, ok := ByCommand("nonexistent"); ok {
		t.Fatal("nonexistent command should not map")
	}
}
