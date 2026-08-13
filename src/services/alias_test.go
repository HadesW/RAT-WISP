package services

import (
	"strings"
	"testing"

	"github.com/user/wisp/internal/db"
)

// TestAliasResolve verifies alias registration via Lua and command rewriting
// with $1/$N/$* placeholders.
func TestAliasResolve(t *testing.T) {
	database, err := db.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	svc := NewServerService()
	svc.db = database
	ss := NewScriptService(svc)
	_ = ss // engine resolver installed on svc

	src := `
wisp.alias("mimikatz", "shell", '"C:\\tools\\mimikatz.exe" "sekurlsa::logonpasswords" $*', "run mimikatz")
wisp.alias("psx", "shell", "powershell -ep bypass -enc $1", "")
`
	out, err := ss.RunScript(src)
	if err != nil {
		t.Fatalf("run script: %v (out=%q)", err, out)
	}

	// resolver on the server service must rewrite
	cmd, args, ok := svc.resolveCommand("mimikatz", "full")
	if !ok || cmd != "shell" {
		t.Fatalf("resolve mimikatz = (%s,%s,%v)", cmd, args, ok)
	}
	if !strings.Contains(args, "mimikatz.exe") || !strings.Contains(args, "full") {
		t.Fatalf("mimikatz args = %q", args)
	}

	cmd, args, ok = svc.resolveCommand("psx", "AQID")
	if !ok || cmd != "shell" {
		t.Fatalf("resolve psx = (%s,%s,%v)", cmd, args, ok)
	}
	if !strings.Contains(args, "AQID") {
		t.Fatalf("psx args = %q", args)
	}

	// non-alias passes through unchanged
	cmd, args, ok = svc.resolveCommand("sysinfo", "")
	if ok || cmd != "sysinfo" {
		t.Fatalf("resolve sysinfo = (%s,%s,%v)", cmd, args, ok)
	}

	// aliases listed
	list := ss.ListAliases()
	if len(list) != 2 {
		t.Fatalf("ListAliases = %d, want 2", len(list))
	}

	// clear works
	src2 := `wisp.alias_clear("mimikatz")`
	if _, err := ss.RunScript(src2); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := svc.resolveCommand("mimikatz", ""); ok {
		t.Fatal("alias not cleared")
	}
}

// TestAliasSendCommand verifies SendCommand routes through the resolver: an
// alias for a real command produces a valid task.
func TestAliasSendCommand(t *testing.T) {
	database, err := db.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	svc := NewServerService()
	svc.db = database
	_ = NewScriptService(svc)

	ln, err := svc.db.CreateListener("l1", "tcp", "127.0.0.1", 4444, false, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.db.CreateSession(&db.SessionRow{ID: "s1", ListenerID: ln.ID, Status: "alive"}); err != nil {
		t.Fatal(err)
	}

	src := `wisp.alias("sysi", "sysinfo")`
	if _, err := NewScriptService(svc).RunScript(src); err != nil {
		t.Fatal(err)
	}
	ss := NewSessionService(svc)
	if err := ss.SendCommand("s1", "sysi", ""); err != nil {
		t.Fatalf("SendCommand(alias): %v", err)
	}
}
