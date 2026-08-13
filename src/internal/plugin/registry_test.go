package plugin

import "testing"

func TestRegistryDeclareLoadList(t *testing.T) {
	r := NewRegistry()
	r.Declare(&Plugin{ID: "core", Kind: KindAgent, Lang: LangRust, Commands: []uint32{1, 2}})
	r.Declare(&Plugin{ID: "screenshot", Kind: KindAgent, Lang: LangRust, Platform: "windows", Commands: []uint32{25}})

	if !r.Load("core") {
		t.Fatal("load core failed")
	}
	if r.Load("nope") {
		t.Fatal("load unknown should fail")
	}

	got := r.Loaded()
	if len(got) != 1 || got[0] != "core" {
		t.Fatalf("loaded = %v, want [core]", got)
	}

	owner, ok := r.CommandOwner(25)
	if !ok || owner != "screenshot" {
		t.Fatalf("cmd 25 owner = %q ok=%v, want screenshot true", owner, ok)
	}
}

func TestRegistryReplaceAndUnload(t *testing.T) {
	r := NewRegistry()
	r.Declare(&Plugin{ID: "x", Kind: KindServer, Lang: LangLua, Events: []string{"listener:checkin"}})
	r.Declare(&Plugin{ID: "x", Kind: KindServer, Lang: LangLua, Events: []string{"listener:checkin", "task:dispatch"}}) // replace
	if p, _ := r.Get("x"); len(p.Events) != 2 {
		t.Fatalf("expected replaced events, got %v", p.Events)
	}
	r.Load("x")
	r.Unload("x")
	if len(r.Loaded()) != 0 {
		t.Fatal("expected empty loaded after unload")
	}
}

func TestDefaultSeed(t *testing.T) {
	// Reset then seed
	Seed()
	d := Default()
	list := d.List()
	if len(list) == 0 {
		t.Fatal("expected seeded plugins")
	}
	// screenshot should own cmd 25
	owner, ok := d.CommandOwner(25)
	if !ok || owner != "screenshot" {
		t.Fatalf("cmd 25 owner = %q, want screenshot", owner)
	}
}
