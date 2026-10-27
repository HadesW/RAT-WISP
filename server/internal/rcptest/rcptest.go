// Package rcptest provides the v2 RCP challenge-response handshake for tests
// that need a scripted agent talking to a real hub.
package rcptest

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"wispp/protocol"
)

// Dial connects to hubAddr and authenticates as agent using psk.
func Dial(hubAddr, psk, agent string) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", hubAddr, 3*time.Second)
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	f, err := protocol.ReadRCPFrame(c)
	if err != nil {
		c.Close()
		return nil, err
	}
	if f.Kind != protocol.RCPKindChallenge {
		c.Close()
		return nil, fmt.Errorf("rcptest: first frame kind %#x", f.Kind)
	}
	var ch protocol.RCPChallenge
	if json.Unmarshal(f.Payload, &ch) != nil || len(ch.Nonce) != 32 {
		c.Close()
		return nil, errors.New("rcptest: bad challenge")
	}
	key, ok := protocol.RCPKeyFromToken(protocol.RCPToken(psk, agent))
	if !ok {
		c.Close()
		return nil, errors.New("rcptest: key")
	}
	an, err := protocol.NewRCPNonce()
	if err != nil {
		c.Close()
		return nil, err
	}
	hello, _ := json.Marshal(protocol.RCPHello{Agent: agent, Nonce: an,
		Proof: protocol.RCPAgentProof(key, agent, ch.Nonce, an)})
	if err := protocol.WriteRCPFrame(c, &protocol.RCPFrame{
		Kind: protocol.RCPKindHello, Payload: hello}); err != nil {
		c.Close()
		return nil, err
	}
	ackFrame, err := protocol.ReadRCPFrame(c)
	if err != nil {
		c.Close()
		return nil, err
	}
	var ack protocol.RCPAck
	if json.Unmarshal(ackFrame.Payload, &ack) != nil || !ack.OK {
		c.Close()
		return nil, fmt.Errorf("rcptest: rejected: %s", ack.Reason)
	}
	if ack.Proof != protocol.RCPServerProof(key, agent, ch.Nonce, an) {
		c.Close()
		return nil, errors.New("rcptest: server proof mismatch")
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}
