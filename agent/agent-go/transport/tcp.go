package transport

import (
	"crypto/rsa"
	"fmt"
	"net"
	"strings"
	"time"

	"wispp/protocol"
)

// TCP ships Type1 envelopes as magic-framed packets, one dial per message
// (plan §2.1; KCP/RCP reuse the framing in M3).
type TCP struct {
	servers []string // tcp://host:port
}

func NewTCP(servers []string) *TCP { return &TCP{servers: servers} }

func (t *TCP) addr(i int) string { return strings.TrimPrefix(t.servers[i], "tcp://") }

// exchange sends one envelope and reads the reply envelope.
func (t *TCP) exchange(env *protocol.Envelope) (*protocol.Envelope, error) {
	var lastErr error
	for i := range t.servers {
		conn, err := net.DialTimeout("tcp", t.addr(i), 10*time.Second)
		if err != nil {
			lastErr = err
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
		err = protocol.WritePacket(conn, &protocol.Packet{Type: protocol.TypeEnvelope, Payload: env.Marshal()})
		if err == nil {
			var pkt *protocol.Packet
			pkt, err = protocol.ReadPacket(conn)
			if err == nil && pkt.Type == protocol.TypeEnvelope {
				var out *protocol.Envelope
				out, err = protocol.ReadEnvelope(pkt.Payload)
				conn.Close()
				if err == nil {
					return out, nil
				}
			}
		}
		conn.Close()
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("transport: no servers configured")
	}
	return nil, lastErr
}

func (t *TCP) Send(env *protocol.Envelope) (*protocol.Envelope, error) { return t.exchange(env) }

// Pubkey uses the dedicated key bootstrap frames (plan §3).
func (t *TCP) Pubkey() (*rsa.PublicKey, error) {
	var lastErr error
	for i := range t.servers {
		conn, err := net.DialTimeout("tcp", t.addr(i), 10*time.Second)
		if err != nil {
			lastErr = err
			continue
		}
		err = protocol.WritePacket(conn, &protocol.Packet{Type: protocol.TypeRequestKey})
		if err == nil {
			var pkt *protocol.Packet
			pkt, err = protocol.ReadPacket(conn)
			if err == nil && pkt.Type == protocol.TypeServerKey {
				pub, perr := protocol.DecodePublicKeyPEM(pkt.Payload)
				conn.Close()
				if perr == nil {
					return pub, nil
				}
				err = perr
			}
		}
		conn.Close()
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("transport: no servers configured")
	}
	return nil, lastErr
}
