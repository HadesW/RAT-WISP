package platform

import (
	"net"
	"os"
	"strings"
	"testing"
)

func TestGetInternalIP(t *testing.T) {
	ip := GetInternalIP()

	if ip == "" {
		t.Fatal("internal IP should not be empty")
	}
	// Must be parseable and not loopback/unspecified
	parsed := net.ParseIP(ip)
	if parsed == nil {
		t.Fatalf("internal IP %q is not a valid IP", ip)
	}
	if parsed.IsLoopback() || parsed.IsUnspecified() {
		t.Errorf("internal IP %q should not be loopback/unspecified", ip)
	}
}

func TestGetProcessPath(t *testing.T) {
	p := GetProcessPath()
	if p == "" {
		t.Fatal("process path should not be empty")
	}
	// The path should either be absolute or match os.Args[0]
	exe, err := os.Executable()
	if err == nil {
		norm := strings.ReplaceAll(p, "\\", "/")
		exeNorm := strings.ReplaceAll(exe, "\\", "/")
		if !strings.Contains(strings.ToLower(norm), strings.ToLower(exeNorm)) {
			t.Errorf("process path %q does not match executable %q", p, exe)
		}
	}
}

func TestGetDomainFromEnv(t *testing.T) {
	// Manipulate environment to verify precedence: USERDNSDOMAIN > USERDOMAIN > LOGONSERVER
	t.Setenv("USERDNSDOMAIN", "corp.example.com")
	t.Setenv("USERDOMAIN", "CORP")
	t.Setenv("LOGONSERVER", `\\DC01`)

	if got := getDomainFromEnv(); got != "corp.example.com" {
		t.Errorf("USERDNSDOMAIN precedence failed, got %q", got)
	}

	t.Setenv("USERDNSDOMAIN", "")
	if got := getDomainFromEnv(); got != "CORP" {
		t.Errorf("USERDOMAIN fallback failed, got %q", got)
	}

	t.Setenv("USERDOMAIN", "")
	if got := getDomainFromEnv(); got != "DC01" {
		t.Errorf("LOGONSERVER fallback failed, got %q", got)
	}

	t.Setenv("LOGONSERVER", "")
	if got := getDomainFromEnv(); got != "" {
		t.Errorf("expected empty domain, got %q", got)
	}
}
