package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"wispp/protocol"
)

// TestRCPFileDown: fake hub pushes a file into the agent's filesystem.
func TestRCPFileDown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	psk, agent := "fpsk", "fd01"
	go rcpLoop(context.Background(), ln.Addr().String(), agent, protocol.RCPToken(psk, agent))

	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	testRCPHandshake(t, conn, psk, agent)

	dst := filepath.Join(t.TempDir(), "pushed.dat")
	chunk := protocol.FileCtrl{Chunk: 1024}
	payload := make([]byte, 2500)
	for i := range payload {
		payload[i] = byte(i)
	}
	sum := sha256.Sum256(payload)
	begin, _ := json.Marshal(protocol.FileCtrl{
		Op: protocol.FileOpBegin, Mode: "down", Job: "j1", Path: dst,
		Size: int64(len(payload)), Chunk: 1024,
	})
	_ = protocol.WriteRCPFrame(conn, &protocol.RCPFrame{Chan: 9, Kind: protocol.RCPKindOpen,
		Payload: mustMarshal(protocol.RCPOpen{Chan: 9, Kind: protocol.RCPChanFile, Args: begin})})

	// agent should greet with ready{resume:0}
	f, err := protocol.ReadRCPFrame(conn)
	if err != nil || f.Flags&protocol.RCPFlagJSON == 0 {
		t.Fatalf("want ready ctrl: %v %+v", err, f)
	}
	var ready protocol.FileCtrl
	_ = json.Unmarshal(f.Payload, &ready)
	if ready.Op != protocol.FileOpReady || ready.Resume != 0 || ready.Chunk != 0 {
		t.Fatalf("ready: %+v", ready)
	}
	_ = chunk

	resume, _ := json.Marshal(protocol.FileCtrl{Op: protocol.FileOpResume, Job: "j1", Resume: 0})
	_ = protocol.WriteRCPFrame(conn, &protocol.RCPFrame{Chan: 9, Kind: protocol.RCPKindFrame, Flags: protocol.RCPFlagJSON, Payload: resume})
	for off := 0; off < len(payload); off += 1024 {
		end := off + 1024
		if end > len(payload) {
			end = len(payload)
		}
		_ = protocol.WriteRCPFrame(conn, &protocol.RCPFrame{Chan: 9, Kind: protocol.RCPKindFrame, Payload: payload[off:end]})
	}
	eb, _ := json.Marshal(protocol.FileCtrl{Op: protocol.FileOpEnd, Job: "j1", SHA256: hex.EncodeToString(sum[:])})
	_ = protocol.WriteRCPFrame(conn, &protocol.RCPFrame{Chan: 9, Kind: protocol.RCPKindFrame, Flags: protocol.RCPFlagJSON, Payload: eb})

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		got, err := os.ReadFile(dst)
		if err == nil && len(got) == len(payload) {
			g := sha256.Sum256(got)
			if g == sum {
				return // success
			}
			t.Fatal("bytes differ")
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("file never materialized")
}
