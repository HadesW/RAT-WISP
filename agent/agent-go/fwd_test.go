package main

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"wispp/protocol"
)

// TestRCPFwdBridge: fake hub opens an fwd channel; agent must dial the local
// echo target and pump bytes both directions.
func TestRCPFwdBridge(t *testing.T) {
	// echo target
	eln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer eln.Close()
	go func() {
		c, err := eln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("echo:" + line))
		}
	}()

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	psk, agent := "fpsk", "fwd01"
	go rcpLoop(context.Background(), ln.Addr().String(), agent, protocol.RCPToken(psk, agent))

	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	testRCPHandshake(t, conn, psk, agent)

	args, _ := json.Marshal(protocol.FwdArgs{Target: eln.Addr().String()})
	openb, _ := json.Marshal(protocol.RCPOpen{Chan: 5, Kind: protocol.RCPChanFwd, Args: args})
	_ = protocol.WriteRCPFrame(conn, &protocol.RCPFrame{Chan: 5, Kind: protocol.RCPKindOpen, Payload: openb})

	// read frames until one arrives on chan 5 (agent dialed ok); send input
	deadline := time.Now().Add(8 * time.Second)
	gotEcho := ""
	for time.Now().Before(deadline) {
		_ = protocol.WriteRCPFrame(conn, &protocol.RCPFrame{Chan: 5, Kind: protocol.RCPKindFrame, Payload: []byte("hi-fwd\n")})
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		f, err := protocol.ReadRCPFrame(conn)
		if err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		if f.Kind == protocol.RCPKindFrame && f.Chan == 5 && len(f.Payload) > 0 {
			gotEcho = string(f.Payload)
			break
		}
	}
	if gotEcho != "echo:hi-fwd\n" {
		t.Fatalf("fwd bridge: %q", gotEcho)
	}
}
