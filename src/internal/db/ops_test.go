package db

import (
	"testing"
)

func TestOpsCRUD(t *testing.T) {
	dir := t.TempDir()
	d, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	// Targets
	tg, err := d.AddTarget("10.0.0.5", "dc01", "", "domain controller")
	if err != nil {
		t.Fatal(err)
	}
	targets, err := d.ListTargets()
	if err != nil || len(targets) != 1 || targets[0].IP != "10.0.0.5" {
		t.Fatalf("targets: %v %v", targets, err)
	}
	_ = tg

	// Credentials (encrypted at rest)
	cred, err := d.AddCredential("10.0.0.5", "admin", "P@ssw0rd!", "", "password", "")
	if err != nil {
		t.Fatal(err)
	}
	creds, err := d.ListCredentials()
	if err != nil || len(creds) != 1 {
		t.Fatalf("creds: %v", err)
	}
	if creds[0].Password != "P@ssw0rd!" {
		t.Fatalf("password not decrypted: %q", creds[0].Password)
	}
	// raw stored value must be encrypted
	var raw string
	if err := d.db.QueryRow(`SELECT password FROM credentials WHERE id=?`, cred.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if raw == "P@ssw0rd!" || raw[:4] != "enc:" {
		t.Fatalf("credential not encrypted at rest: %q", raw)
	}

	// Loot
	_, err = d.AddLoot("sess1", "hashdump", "text", "user:500:aaa:bbb:::")
	if err != nil {
		t.Fatal(err)
	}
	loot, err := d.ListLoot(10)
	if err != nil || len(loot) != 1 {
		t.Fatalf("loot: %v", err)
	}

	// Deletes
	if err := d.DeleteTarget(tg.ID); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteCredential(cred.ID); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteLoot(loot[0].ID); err != nil {
		t.Fatal(err)
	}
}
