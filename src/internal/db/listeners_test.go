package db

import (
	"testing"
)

func TestListenerCRUDWithPSK(t *testing.T) {
	d, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer d.Close()

	ln, err := d.CreateListener("http-01", "http", "0.0.0.0", 8080, false, "my-psk-value", "192.168.1.50")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if ln.Status != "stopped" {
		t.Errorf("status = %q, want stopped", ln.Status)
	}
	if ln.PSK != "my-psk-value" {
		t.Errorf("psk = %q, want stored value", ln.PSK)
	}
	if ln.Host != "192.168.1.50" {
		t.Errorf("callback host = %q, want 192.168.1.50", ln.Host)
	}
	if ln.BindHost != "0.0.0.0" {
		t.Errorf("bind host = %q, want 0.0.0.0", ln.BindHost)
	}

	// GetListener round-trips the PSK
	got, err := d.GetListener(ln.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.PSK != "my-psk-value" {
		t.Errorf("get psk = %q", got.PSK)
	}
	if got.UseTLS {
		t.Error("use_tls should be false")
	}

	// Status update
	if err := d.UpdateListenerStatus(ln.ID, "running"); err != nil {
		t.Fatalf("update status: %v", err)
	}
	got, _ = d.GetListener(ln.ID)
	if got.Status != "running" {
		t.Errorf("status = %q, want running", got.Status)
	}

	// Delete
	if err := d.DeleteListener(ln.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := d.GetListener(ln.ID); err == nil {
		t.Error("listener should be gone after delete")
	}
}

func TestListenerNameUnique(t *testing.T) {
	d, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer d.Close()

	if _, err := d.CreateListener("dup", "tcp", "0.0.0.0", 4444, false, ""); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, err := d.CreateListener("dup", "tcp", "0.0.0.0", 4445, false, ""); err == nil {
		t.Error("duplicate listener name should fail")
	}
}
