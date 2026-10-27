package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	kcp "github.com/xtaci/kcp-go/v5"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"wispp/protocol"
)

// Type2 RCP client (plan §2.3): one long-lived multiplexed connection per
// agent, dialing the address announced in RegisterAck. Independent of the
// Type1 sleep loop: terminal and desktop stay realtime while Type1 naps.

// filePacket is one routed delivery on a file channel.
type filePacket struct {
	ctrl bool
	data []byte
}

type rcpHandle struct {
	stop chan struct{}

	mu      sync.Mutex
	stdin   io.Writer       // shell stdin, nil until the child is up
	pending [][]byte        // input that raced ahead of setIn
	packets chan filePacket // file channels only
}

func (h *rcpHandle) emit(p filePacket) bool {
	if h.packets == nil {
		return false
	}
	select {
	case h.packets <- p:
		return true
	case <-h.stop:
		return false
	}
}

func (h *rcpHandle) setIn(w io.Writer) {
	h.mu.Lock()
	h.stdin = w
	for _, p := range h.pending {
		_, _ = h.stdin.Write(p)
	}
	h.pending = nil
	h.mu.Unlock()
}

func (h *rcpHandle) writeIn(p []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.stdin != nil {
		_, _ = h.stdin.Write(p)
		return
	}
	if len(h.pending) < 32 {
		h.pending = append(h.pending, append([]byte(nil), p...))
	}
}

func rcpLoop(ctx context.Context, addr, agentID, token string) {
	for {
		err := rcpSession(ctx, addr, agentID, token)
		select {
		case <-ctx.Done():
			log.Printf("rcp: Type2 closed by operator request")
			return
		default:
		}
		if err != nil {
			log.Printf("rcp: session ended: %v (redial in 5s)", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

func rcpDial(addr string) (net.Conn, error) {
	if strings.HasPrefix(addr, "kcp://") {
		s, err := kcp.DialWithOptions(strings.TrimPrefix(addr, "kcp://"), nil, 0, 0)
		if err != nil {
			return nil, err
		}
		s.SetNoDelay(1, 10, 2, 1)
		s.SetStreamMode(true)
		return s, nil
	}
	return net.DialTimeout("tcp", strings.TrimPrefix(addr, "tcp://"), 10*time.Second)
}

func rcpSession(ctx context.Context, addr, agentID, token string) error {
	conn, err := rcpDial(addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	send := make(chan *protocol.RCPFrame, 64)
	var seq uint32
	var seqMu sync.Mutex
	nextSeq := func() uint32 { seqMu.Lock(); defer seqMu.Unlock(); seq++; return seq }

	go func() {
		for f := range send {
			_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if err := protocol.WriteRCPFrame(conn, f); err != nil {
				for range send { // drain so senders don't block once we're out
				}
				return
			}
		}
	}()

	key, err := hex.DecodeString(token)
	if err != nil || len(key) != 16 {
		return errRejected("bad rcp token")
	}
	// v2: server sends a nonce first; the token stays on the encrypted Type1
	// channel and only a fresh HMAC proof travels here.
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	chFrame, err := protocol.ReadRCPFrame(conn)
	if err != nil || chFrame.Kind != protocol.RCPKindChallenge {
		return errRejected("expected rcp challenge")
	}
	var ch protocol.RCPChallenge
	if json.Unmarshal(chFrame.Payload, &ch) != nil || len(ch.Nonce) != 32 {
		return errRejected("bad rcp challenge")
	}
	an, err := rcpNonce()
	if err != nil {
		return err
	}
	hello, _ := json.Marshal(protocol.RCPHello{Agent: agentID, Nonce: an,
		Proof: rcpProof(key, "agent", agentID, ch.Nonce, an)})
	if err := protocol.WriteRCPFrame(conn, &protocol.RCPFrame{
		Kind: protocol.RCPKindHello, Payload: hello}); err != nil {
		return err
	}
	ackFrame, err := protocol.ReadRCPFrame(conn)
	if err != nil || ackFrame.Kind != protocol.RCPKindAck {
		return err
	}
	var ack protocol.RCPAck
	_ = json.Unmarshal(ackFrame.Payload, &ack)
	if !ack.OK {
		return errRejected(ack.Reason)
	}
	want := rcpProof(key, "server", agentID, ch.Nonce, an)
	if !hmac.Equal([]byte(ack.Proof), []byte(want)) {
		return errRejected("rcp server proof mismatch")
	}
	log.Printf("rcp: connected %s (shell/view channels live)", addr)

	var (
		mu   sync.Mutex
		chrs = map[uint32]*rcpHandle{}
	)
	stopChan := func(id uint32) {
		mu.Lock()
		if h, ok := chrs[id]; ok {
			close(h.stop)
			delete(chrs, id)
		}
		mu.Unlock()
	}

	for {
		_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		f, err := protocol.ReadRCPFrame(conn)
		if err != nil {
			mu.Lock()
			for id := range chrs {
				close(chrs[id].stop)
				delete(chrs, id)
			}
			mu.Unlock()
			return err
		}
		switch f.Kind {
		case protocol.RCPKindOpen:
			var op protocol.RCPOpen
			if err := json.Unmarshal(f.Payload, &op); err != nil {
				continue
			}
			h := &rcpHandle{stop: make(chan struct{})}
			mu.Lock()
			chrs[op.Chan] = h
			mu.Unlock()
			switch op.Kind {
			case protocol.RCPChanShell:
				go rcpShell(op.Chan, h, send, nextSeq)
			case protocol.RCPChanView:
				h.packets = make(chan filePacket, 32)
				go rcpView(op.Chan, h, send, nextSeq)
			case protocol.RCPChanFwd:
				h.packets = make(chan filePacket, 64)
				var fa protocol.FwdArgs
				if json.Unmarshal(op.Args, &fa) == nil && fa.Target != "" {
					go rcpFwd(op.Chan, fa.Target, h, send, nextSeq)
				} else {
					stopChan(op.Chan)
				}
			case protocol.RCPChanFile:
				h.packets = make(chan filePacket, 64)
				var begin protocol.FileCtrl
				if json.Unmarshal(op.Args, &begin) == nil {
					go rcpFile(op.Chan, &begin, h, send, nextSeq)
				}
			default:
				_ = protocol.WriteRCPFrame(conn, &protocol.RCPFrame{Chan: op.Chan, Kind: protocol.RCPKindClose,
					Payload: mustMarshal(protocol.RCPClose{Chan: op.Chan, Reason: "unsupported kind"})})
				stopChan(op.Chan)
			}
		case protocol.RCPKindFrame:
			mu.Lock()
			h := chrs[f.Chan]
			mu.Unlock()
			if h == nil {
				continue
			}
			if h.packets != nil { // file channel: ctrl/data routing by flags
				h.emit(filePacket{ctrl: f.Flags&protocol.RCPFlagJSON != 0, data: f.Payload})
				continue
			}
			if f.Flags&protocol.RCPFlagJSON != 0 {
				continue // shell control (resize/hello): pipe mode has no PTY to size
			}
			h.writeIn(f.Payload)
		case protocol.RCPKindClose:
			var pc protocol.RCPClose
			_ = json.Unmarshal(f.Payload, &pc)
			stopChan(pc.Chan)
		case protocol.RCPKindPing:
			send <- &protocol.RCPFrame{Chan: f.Chan, Kind: protocol.RCPKindPong, Seq: nextSeq()}
		}
	}
}

// rcpFile executes one Type3 transfer on the agent side (plan §2.4).
// up: read begin.Path and stream chunks from the server resume checkpoint.
// down: write begin.Path (+".part"), advertising local resume, verify end.
// rcpFwd bridges one RCP channel to a TCP target (port forwarding, plan §2.3).
func rcpFwd(chID uint32, target string, h *rcpHandle, send chan<- *protocol.RCPFrame, nextSeq func() uint32) {
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		send <- &protocol.RCPFrame{Chan: chID, Kind: protocol.RCPKindClose,
			Payload: mustMarshal(protocol.RCPClose{Chan: chID, Reason: "dial " + target + ": " + err.Error()})}
		return
	}
	defer conn.Close()

	go func() { // target → server
		buf := make([]byte, 32*1024)
		for {
			n, rerr := conn.Read(buf)
			if n > 0 {
				frame := &protocol.RCPFrame{Chan: chID, Kind: protocol.RCPKindFrame, Seq: nextSeq(), Payload: append([]byte(nil), buf[:n]...)}
				select {
				case send <- frame:
				case <-h.stop:
					return
				}
			}
			if rerr != nil {
				select {
				case send <- &protocol.RCPFrame{Chan: chID, Kind: protocol.RCPKindClose,
					Payload: mustMarshal(protocol.RCPClose{Chan: chID, Reason: "target eof"})}:
				default:
				}
				return
			}
		}
	}()

	for {
		select {
		case <-h.stop:
			return
		case p, ok := <-h.packets:
			if !ok {
				return
			}
			if p.ctrl {
				continue
			}
			if _, err := conn.Write(p.data); err != nil {
				return
			}
		}
	}
}

func rcpFile(chID uint32, begin *protocol.FileCtrl, h *rcpHandle, send chan<- *protocol.RCPFrame, nextSeq func() uint32) {
	switch begin.Mode {
	case "up":
		rcpFileUp(chID, begin, h, send, nextSeq)
	case "down":
		rcpFileDown(chID, begin, h, send, nextSeq)
	default:
		h.sendCtrl(chID, send, nextSeq, protocol.FileCtrl{Op: protocol.FileOpError, Job: begin.Job, Reason: "bad mode"})
	}
}

func rcpFileUp(chID uint32, begin *protocol.FileCtrl, h *rcpHandle, send chan<- *protocol.RCPFrame, nextSeq func() uint32) {
	f, err := os.Open(begin.Path)
	if err != nil {
		send <- &protocol.RCPFrame{Kind: protocol.RCPKindFrame, Flags: protocol.RCPFlagJSON,
			Seq: nextSeq(), Payload: mustMarshal(protocol.FileCtrl{Op: protocol.FileOpError, Job: begin.Job, Reason: err.Error()})}
		return
	}
	defer f.Close()
	h.sendCtrl(chID, send, nextSeq, protocol.FileCtrl{Op: protocol.FileOpReady, Job: begin.Job, Mode: "up"})

	var resume protocol.FileCtrl
	for {
		p, ok := <-h.packets
		if !ok {
			return
		}
		if p.ctrl {
			_ = json.Unmarshal(p.data, &resume)
			break
		}
	}
	if resume.Resume > 0 {
		if _, err := f.Seek(int64(resume.Resume)*int64(begin.Chunk), io.SeekStart); err != nil {
			return
		}
	}
	buf := make([]byte, begin.Chunk)
	for {
		select {
		case <-h.stop:
			return
		default:
		}
		n, rerr := f.Read(buf)
		if n > 0 {
			send <- &protocol.RCPFrame{Chan: chID, Kind: protocol.RCPKindFrame, Seq: nextSeq(), Payload: append([]byte(nil), buf[:n]...)}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			h.sendCtrl(chID, send, nextSeq, protocol.FileCtrl{Op: protocol.FileOpError, Job: begin.Job, Reason: rerr.Error()})
			return
		}
	}
	hf := sha256.New()
	if raw, err := os.ReadFile(begin.Path); err == nil {
		hf.Write(raw)
		h.sendCtrl(chID, send, nextSeq, protocol.FileCtrl{Op: protocol.FileOpEnd, Job: begin.Job,
			SHA256: hex.EncodeToString(hf.Sum(nil))})
	}
}

func rcpFileDown(chID uint32, begin *protocol.FileCtrl, h *rcpHandle, send chan<- *protocol.RCPFrame, nextSeq func() uint32) {
	part := begin.Path + ".part"
	if dir := filepath.Dir(begin.Path); dir != "." && dir != string(filepath.Separator) {
		_ = os.MkdirAll(dir, 0o700)
	}
	var have int64
	if st, err := os.Stat(part); err == nil {
		have = st.Size()
	}
	f, err := os.OpenFile(part, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		h.sendCtrl(chID, send, nextSeq, protocol.FileCtrl{Op: protocol.FileOpError, Job: begin.Job, Reason: err.Error()})
		return
	}
	defer f.Close()
	resume := int(have / int64(begin.Chunk))
	if _, err := f.Seek(int64(resume)*int64(begin.Chunk), io.SeekStart); err != nil {
		return
	}
	h.sendCtrl(chID, send, nextSeq, protocol.FileCtrl{Op: protocol.FileOpReady, Job: begin.Job, Mode: "down", Resume: resume})

	done := func(ok bool, reason, sha string) {
		h.sendCtrl(chID, send, nextSeq, protocol.FileCtrl{Op: protocol.FileOpDone, Job: begin.Job, OK: ok, Reason: reason, SHA256: sha})
	}
	for {
		select {
		case <-h.stop:
			return
		case p, ok := <-h.packets:
			if !ok {
				return
			}
			if !p.ctrl {
				if _, err := f.Write(p.data); err != nil {
					done(false, err.Error(), "")
					return
				}
				continue
			}
			var c protocol.FileCtrl
			if json.Unmarshal(p.data, &c) != nil {
				continue
			}
			switch c.Op {
			case protocol.FileOpEnd:
				if err := f.Sync(); err != nil {
					done(false, err.Error(), "")
					return
				}
				f.Close()
				raw, err := os.ReadFile(part)
				if err != nil {
					done(false, err.Error(), "")
					return
				}
				sum := sha256.Sum256(raw)
				got := hex.EncodeToString(sum[:])
				if c.SHA256 != "" && got != c.SHA256 {
					done(false, "sha256 mismatch", got)
					return
				}
				if err := os.Rename(part, begin.Path); err != nil {
					done(false, err.Error(), got)
					return
				}
				done(true, "", got)
				return
			case protocol.FileOpError:
				done(false, c.Reason, "")
				return
			}
		}
	}
}

// sendCtrl helper on the handle (nil-safe).
func (h *rcpHandle) sendCtrl(chID uint32, send chan<- *protocol.RCPFrame, nextSeq func() uint32, c protocol.FileCtrl) {
	h.mu.Lock()
	enabled := h.packets != nil
	h.mu.Unlock()
	if !enabled {
		return
	}
	send <- &protocol.RCPFrame{Chan: chID, Kind: protocol.RCPKindFrame, Flags: protocol.RCPFlagJSON,
		Seq: nextSeq(), Payload: mustMarshal(c)}
}

type rcpRejected string

func (r rcpRejected) Error() string { return "rcp rejected: " + string(r) }

func errRejected(reason string) error { return rcpRejected(reason) }

func mustMarshal(v any) []byte { b, _ := json.Marshal(v); return b }

func sendCtrlJSON(ch uint32, send chan<- *protocol.RCPFrame, nextSeq func() uint32, v any) {
	send <- &protocol.RCPFrame{Chan: ch, Kind: protocol.RCPKindFrame, Flags: protocol.RCPFlagJSON,
		Seq: nextSeq(), Payload: mustMarshal(v)}
}

// rcpShell runs one interactive shell and pumps both directions.
func rcpShell(ch uint32, h *rcpHandle, send chan<- *protocol.RCPFrame, nextSeq func() uint32) {
	var cmd *exec.Cmd
	shell := "sh"
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/Q", "/K", "chcp 65001>nul")
		shell = "cmd"
	} else {
		shell = "/bin/sh"
		if fi, err := os.Stat("/bin/bash"); err == nil && !fi.IsDir() {
			shell = "/bin/bash"
		}
		cmd = exec.Command(shell, "-i")
		// UTF-8 for Chinese/English output; keep an existing UTF-8 locale.
		loc := os.Getenv("LC_ALL")
		if loc == "" {
			loc = os.Getenv("LANG")
		}
		if !strings.Contains(strings.ToLower(loc), "utf") {
			loc = "C.UTF-8"
		}
		cmd.Env = append(os.Environ(), "LANG="+loc, "LC_ALL="+loc)
		shell = filepath.Base(shell)
	}
	fail := func(reason string) {
		log.Printf("rcp: shell: %s", reason)
		send <- &protocol.RCPFrame{Chan: ch, Kind: protocol.RCPKindClose,
			Payload: mustMarshal(protocol.RCPClose{Chan: ch, Reason: reason})}
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		fail("stdin: " + err.Error())
		return
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		fail("pipe: " + err.Error())
		return
	}
	cmd.Stdout = outW
	cmd.Stderr = outW // merged, like a terminal
	if err := cmd.Start(); err != nil {
		fail("shell start: " + err.Error())
		outW.Close()
		return
	}
	outW.Close() // parent's copy; child holds its own fd
	h.setIn(stdin)
	sendCtrlJSON(ch, send, nextSeq, protocol.RCPShellHello{
		Op: protocol.RCPOpHello, TTY: false, Shell: shell, OS: runtime.GOOS, Encoding: "utf-8",
	})

	go func() { // output pump: eager small reads = low latency
		defer outR.Close()
		buf := make([]byte, 4096)
		for {
			n, rerr := outR.Read(buf)
			if n > 0 {
				send <- &protocol.RCPFrame{Chan: ch, Kind: protocol.RCPKindFrame, Seq: nextSeq(),
					Payload: append([]byte(nil), buf[:n]...)}
			}
			if rerr != nil {
				break
			}
		}
	}()

	exit := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exit) }()

	select {
	case <-h.stop:
		_ = cmd.Process.Kill()
	case <-exit:
	}
	send <- &protocol.RCPFrame{Chan: ch, Kind: protocol.RCPKindClose,
		Payload: mustMarshal(protocol.RCPClose{Chan: ch, Reason: "shell ended"})}
}

// rcpView streams screen captures (1 fps PNG) until closed (M3 demo grade;
// dirty-region/JPEG lands with the Rust agent, plan §2.3).
func rcpView(ch uint32, h *rcpHandle, send chan<- *protocol.RCPFrame, nextSeq func() uint32) {
	interval := time.Second
	fails := 0
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" && runtime.GOOS != "linux" {
		interval = 5 * time.Second
	}
	for {
		select {
		case <-h.stop:
			return
		case p := <-h.packets:
			if p.ctrl || len(p.data) == 0 {
				continue
			}
			var ev inputEvent
			if json.Unmarshal(p.data, &ev) == nil {
				inputInject(ev)
			}
			continue
		default:
		}
		tmp := filepath.Join(os.TempDir(), "wisp_rcp_view.png")
		if err := captureToFile(tmp); err == nil {
			compressShot(tmp)
			if data, rerr := os.ReadFile(tmp); rerr == nil && len(data) > 0 {
				send <- &protocol.RCPFrame{Chan: ch, Kind: protocol.RCPKindFrame, Seq: nextSeq(), Payload: data}
				_ = os.Remove(tmp)
				fails = 0
			} else {
				fails++
			}
		} else {
			fails++
		}
		if fails == 3 { // e.g. macOS screen-recording permission missing: tell the console, stop hammering
			send <- &protocol.RCPFrame{Chan: ch, Kind: protocol.RCPKindClose,
				Payload: mustMarshal(protocol.RCPClose{Chan: ch, Reason: "capture failed (screen recording permission?)"})}
			return
		}
		select {
		case <-h.stop:
			return
		case <-time.After(interval):
		}
	}
}

func rcpNonce() (string, error) {
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
