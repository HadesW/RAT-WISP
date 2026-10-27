// Package transport implements Type1 senders behind one interface:
// HTTP (malleable-profile shaped) and raw TCP (magic-framed packets).
package transport

import (
	"crypto/rsa"
	"fmt"
	"strings"

	"wispp/protocol"
)

// Sender ships envelopes and fetches the server public key.
type Sender interface {
	Send(env *protocol.Envelope) (*protocol.Envelope, error)
	Pubkey() (*rsa.PublicKey, error)
}

// New dispatches by endpoint scheme. All servers share one transport kind in
// practice (same profile), but mixed lists fall back per scheme group.
func New(servers []string, prof *protocol.Profile, insecure bool) (Sender, error) {
	var httpURLs, tcpURLs, kcpURLs, quicURLs []string
	for _, s := range servers {
		switch {
		case strings.HasPrefix(s, "tcp://"):
			tcpURLs = append(tcpURLs, s)
		case strings.HasPrefix(s, "kcp://"):
			kcpURLs = append(kcpURLs, s)
		case strings.HasPrefix(s, "quic://"):
			quicURLs = append(quicURLs, s)
		case strings.HasPrefix(s, "http://"), strings.HasPrefix(s, "https://"):
			httpURLs = append(httpURLs, s)
		default:
			return nil, fmt.Errorf("transport: unsupported scheme in %q (use http:// https:// tcp:// kcp:// quic://)", s)
		}
	}
	switch {
	case len(httpURLs) > 0:
		return NewHTTP(httpURLs, prof, insecure), nil
	case len(tcpURLs) > 0:
		return NewTCP(tcpURLs), nil
	case len(kcpURLs) > 0:
		return NewKCP(kcpURLs), nil
	case len(quicURLs) > 0:
		return NewQUIC(quicURLs), nil
	}
	return nil, fmt.Errorf("transport: no usable servers")
}
