package transport

import (
	"crypto/rsa"
	"fmt"
	"net"
	"strings"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"
	"wispp/protocol"
)

// KCP ships Type1 envelopes over KCP (reliable UDP, plan §2.1): same framing
// as TCP, survives packet loss / mild congestion better.
type KCP struct {
	servers []string // kcp://host:port
}

func NewKCP(servers []string) *KCP { return &KCP{servers: servers} }

func (k *KCP) dial(i int) (net.Conn, error) {
	addr := strings.TrimPrefix(k.servers[i], "kcp://")
	s, err := kcp.DialWithOptions(addr, nil, 0, 0)
	if err != nil {
		return nil, err
	}
	s.SetNoDelay(1, 10, 2, 1)
	s.SetStreamMode(true)
	return s, nil
}

func (k *KCP) exchange(env *protocol.Envelope) (*protocol.Envelope, error) {
	var lastErr error
	for i := range k.servers {
		conn, err := k.dial(i)
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
				out, perr := protocol.ReadEnvelope(pkt.Payload)
				conn.Close()
				if perr == nil {
					return out, nil
				}
				err = perr
			}
		}
		conn.Close()
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("transport: no kcp servers configured")
	}
	return nil, lastErr
}

func (k *KCP) Send(env *protocol.Envelope) (*protocol.Envelope, error) { return k.exchange(env) }

// Pubkey uses the dedicated bootstrap frames (same as TCP).
func (k *KCP) Pubkey() (*rsa.PublicKey, error) {
	var lastErr error
	for i := range k.servers {
		conn, err := k.dial(i)
		if err != nil {
			lastErr = err
			continue
		}
		err = protocol.WritePacket(conn, &protocol.Packet{Type: protocol.TypeRequestKey})
		if err == nil {
			pkt, err := protocol.ReadPacket(conn)
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
		lastErr = fmt.Errorf("transport: no kcp servers configured")
	}
	return nil, lastErr
}
