package services

import (
	"strings"
	"testing"
)

func TestRunScriptBasics(t *testing.T) {
	se := NewScriptEngine(nil)

	out, err := se.RunScript(`
		local sum = 0
		for i = 1, 10 do sum = sum + i end
		print("sum=" .. sum)
		local s = wisp.json({hello="world", n=42})
		print("json=" .. s)
		local env = os.getenv("PATH")
		if env == "" then env = "(empty)" end
		print("path=" .. env)
	`)
	if err != nil {
		t.Fatalf("RunScript: %v", err)
	}
	t.Logf("output:\n%s", out)
	if !strings.Contains(out, "sum=55") {
		t.Errorf("missing sum=55 in output: %q", out)
	}
	if !strings.Contains(out, "json=") || !strings.Contains(out, "hello") {
		t.Errorf("json call failed: %q", out)
	}
	if !strings.Contains(out, "path=") {
		t.Errorf("os.getenv failed: %q", out)
	}
}

func TestRunScriptError(t *testing.T) {
	se := NewScriptEngine(nil)
	_, err := se.RunScript(`error("boom")`)
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected script error, got %v", err)
	}
}

func TestSanitizeName(t *testing.T) {
	if got := sanitizeName("a/b\\c:d*e?f"); got != "a_b_c_d_e_f" {
		t.Fatalf("sanitize = %q", got)
	}
}
