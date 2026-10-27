package listener

import (
	"io"
	"net"
	"sync"
	"time"

	"wispp/protocol"
)

// TCPListener is a Type1 raw-TCP agent listener (plan §2.1):
// frames = protocol.Packet{Magic|Size|Type|Payload}, Payload = envelope JSON
// (TypeEnvelope) or PEM (TypeRequestKey/TypeServerKey bootstrap).
type TCPListener struct {
	Core

	Addr string

	mu   sync.Mutex
	ln   net.Listener
	done chan struct{}
	wg   sync.WaitGroup
}

// MaxTCPFrame caps a single framed envelope.
const MaxTCPFrame = 4 << 20

func (l *TCPListener) ListenAndServe() error {
	ln, err := net.Listen("tcp", l.Addr)
	if err != nil {
		return err
	}
	return l.Serve(ln)
}

// Serve runs the accept loop on an existing listener (tests, TLS wrap later).
func (l *TCPListener) Serve(ln net.Listener) error {
	l.mu.Lock()
	l.ln, l.done = ln, make(chan struct{})
	l.mu.Unlock()

	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-l.done:
				return nil
			default:
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				return err
			}
		}
		l.wg.Add(1)
		go l.serveConn(c)
	}
}

func (l *TCPListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ln != nil {
		close(l.done)
		err := l.ln.Close()
		l.wg.Wait()
		return err
	}
	return nil
}

// serveConn handles keep-alive connections: many request/reply frames per dial.
func (l *TCPListener) serveConn(c net.Conn) {
	defer l.wg.Done()
	defer c.Close()
	ra := c.RemoteAddr().String()
	ip := ipOnly(ra)
	for {
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Minute))
		pkt, err := protocol.ReadPacket(io.LimitReader(c, MaxTCPFrame))
		if err != nil {
			return // EOF or junk: drop silently (a scan sees a dead port)
		}
		switch pkt.Type {
		case protocol.TypeRequestKey:
			_ = protocol.WritePacket(c, &protocol.Packet{
				Type: protocol.TypeServerKey, Payload: protocol.EncodePublicKeyPEM(&l.Priv.PublicKey)})
		case protocol.TypeEnvelope:
			env, err := protocol.ReadEnvelope(pkt.Payload)
			if err != nil {
				return
			}
			resp, err := l.Process(env, ip)
			if err != nil {
				return
			}
			_ = protocol.WritePacket(c, &protocol.Packet{Type: protocol.TypeEnvelope, Payload: resp.Marshal()})
		default:
			return
		}
	}
}

func ipOnly(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}
