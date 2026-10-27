package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"wispp/protocol"
)

// demoWasm: (module (func (export "exec") (param i32 i32)(result i32) local.get 0 local.get 1 i32.add))
// hand-assembled minimal binary (wazero requires wasm, not WAT).
const demoWasmHex = "0061736d0100000001070160027f7f017f03020100070801046578656300000a09010700200020016a0b"

func signDemo(t *testing.T) (manifest, module, sig, pubhex string) {
	t.Helper()
	mj, _ := json.Marshal(protocol.ManifestLite{ID: "demo-add", Version: "1.0.0", Capabilities: []string{"demo.add"}})
	mod, err := hex.DecodeString(demoWasmHex)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	s := ed25519.Sign(priv, append(append([]byte(nil), mj...), mod...))
	return string(mj), string(mod), base64.StdEncoding.EncodeToString(s), hex.EncodeToString(pub)
}

func TestPluginLoadExec(t *testing.T) {
	manifest, module, sig, pubhex := signDemo(t)
	agentPluginPubkey = pubhex
	res, err := pluginLoad(&protocol.PluginLoadArgs{
		ID: "demo-add", Version: "1.0.0", Manifest: manifest,
		ModuleB64: base64.StdEncoding.EncodeToString([]byte(module)), Sig: sig})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(res)
	out, err := pluginExec(&protocol.PluginExecArgs{ID: "demo-add", Entry: "exec", A: 2, B: 3})
	if err != nil {
		t.Fatal(err)
	}
	var r struct {
		Result int32 `json:"result"`
	}
	_ = json.Unmarshal([]byte(out), &r)
	if r.Result != 5 {
		t.Fatalf("exec: %s", out)
	}
	if caps := pluginCaps(); len(caps) != 1 || caps[0] != "demo-add:demo.add" {
		t.Fatalf("caps: %v", caps)
	}
}

func TestPluginTamperedRejected(t *testing.T) {
	manifest, module, sig, pubhex := signDemo(t)
	agentPluginPubkey = pubhex
	bad := manifest + " " // one byte of drift between signed and delivered
	_, err := pluginLoad(&protocol.PluginLoadArgs{
		ID: "x", Version: "1", Manifest: bad,
		ModuleB64: base64.StdEncoding.EncodeToString([]byte(module)), Sig: sig})
	if err == nil {
		t.Fatal("tampered manifest accepted")
	}
	t.Log(err)
	// no pubkey configured → refuse everything
	agentPluginPubkey = ""
	if _, err := pluginLoad(&protocol.PluginLoadArgs{ID: "x", Manifest: manifest, Sig: sig}); err == nil {
		t.Fatal("load without pubkey allowed")
	}
}

// TestPluginV1: ABI v1 JSON passthrough plugin (scripts/plugins/demo-host.wat)
// exercising the host_exec capability gate end-to-end inside the sandbox.
func TestPluginV1(t *testing.T) {
	mod, err := os.ReadFile("testdata/demo-host.wasm")
	if err != nil {
		t.Skip("demo-host.wasm not built:", err)
	}
	mj, _ := json.Marshal(protocol.ManifestLite{ID: "demo-host", Version: "1.0.0", ABI: 1,
		Capabilities: []string{"host.sysinfo"}})
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	s := ed25519.Sign(priv, append(append([]byte(nil), mj...), mod...))
	agentPluginPubkey = hex.EncodeToString(pub)
	if _, err := pluginLoad(&protocol.PluginLoadArgs{
		ID: "demo-host", Version: "1.0.0", Manifest: string(mj),
		ModuleB64: base64.StdEncoding.EncodeToString(mod), Sig: base64.StdEncoding.EncodeToString(s)}); err != nil {
		t.Fatal("load v1:", err)
	}
	// granted capability: sysinfo → JSON with hostname
	out, err := pluginExec(&protocol.PluginExecArgs{ID: "demo-host", Entry: "exec_json",
		Args: json.RawMessage(`{"cmd":"sysinfo"}`)})
	if err != nil {
		t.Fatal("exec v1:", err)
	}
	if !strings.Contains(out, "hostname") || !strings.Contains(out, `"ok":true`) {
		t.Fatalf("v1 sysinfo: %s", out)
	}
	// ungranted capability: must be refused by the gate, not executed
	out2, err := pluginExec(&protocol.PluginExecArgs{ID: "demo-host", Entry: "exec_json",
		Args: json.RawMessage(`{"cmd":"shell","command":"touch /tmp/wisp_should_not_exist"}`)})
	if err != nil {
		t.Fatal("exec v1 denial:", err)
	}
	if !strings.Contains(out2, "not granted") {
		t.Fatalf("denial expected, got: %s", out2)
	}
	if _, err := os.Stat("/tmp/wisp_should_not_exist"); err == nil {
		t.Fatal("capability gate leaked: shell ran without host.shell")
	}
}
